// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/proxy/utils/Initializable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC20/IERC20Upgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC20/ERC20Storage.sol";
import "@gnus.ai/contracts-upgradeable-diamond/utils/cryptography/ECDSAUpgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/utils/cryptography/MerkleProofUpgradeable.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSControlStorage.sol";
import "./GNUSWithdrawLimiterStorage.sol";
import "./GNUSTreasuryStorage.sol";
import "./GNUSBridgeValidatorStorage.sol";
import "./GNUSLifecycleStorage.sol";
import "./GNUSLifecycleTypes.sol";
import "./interfaces/IAllowlistRegistry.sol";

/// @title GNUSBridge
/// @notice Manages bridging, minting, burning, and token transfers for the GNUS ecosystem.
/// @dev Supports both ERC20 and ERC1155 token standards, with additional functionality for bridging tokens across chains.
/// @custom:security-contact support@gnus.ai
contract GNUSBridge is Initializable, GNUSERC1155MaxSupply, GeniusAccessControl, IERC20Upgradeable {
    using GNUSNFTFactoryStorage for GNUSNFTFactoryStorage.Layout;
    using ERC20Storage for ERC20Storage.Layout;
    using GNUSControlStorage for GNUSControlStorage.Layout;
    using GNUSTreasuryStorage for GNUSTreasuryStorage.Layout;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    string public constant name = "Genius Token & NFT Collections";
    string public constant symbol = "GNUS";
    uint8 public constant decimals = 18;
    /// @dev Fee denominator (thousandths). Bridge fee math: `amount * (1000 - fee) / 1000`.
    /// Cap is GNUSControl.MAX_FEE (200 = 20%).
    uint256 private constant FEE_DENOMINATOR = 1000;
    /// @dev Role identifier for creators — identical value to GNUSNFTFactory.CREATOR_ROLE
    ///      (keccak256("CREATOR_ROLE")). Re-declared locally (GNUSLifecycle.sol:36 precedent)
    ///      to avoid a circular import.
    bytes32 private constant _CREATOR_ROLE = keccak256("CREATOR_ROLE");
    /// @dev Phase 14 D-23 revert reason for bridging an expired entitlement.
    string private constant LICENSE_EXPIRED_ERROR = "License expired";

    /**
     * @notice Emitted when a token holder initiates a bridge to another chain.
     * @param sender Address initiating the bridge operation.
     * @param id Token ID being bridged.
     * @param amount Amount of tokens being bridged.
     * @param srcChainID Source chain ID.
     * @param destChainID Destination chain ID.
     * @param sgnsDestination 32-byte X component of the destination recipient's elliptic curve public key
     * on the SuperGenius chain (not an Ethereum address).
     * @param destinationYOdd Parity of the Y component of the public key (false = even, true = odd),
     * used together with `sgnsDestination` to reconstruct the full public key.
     * @dev Emitted when token holder wants to bridge to another chain
     */
    event BridgeOutInitiated(
        address indexed sender,
        uint256 id,
        uint256 amount,
        uint256 srcChainID,
        uint256 destChainID,
        bytes32 sgnsDestination,
        bool destinationYOdd
    );

    /**
     * @notice Emitted when a bridge-in certificate is verified and tokens are released to the recipient.
     * @param transferId Source-chain burn transaction hash (free-form bytes32, replay-protection key).
     * @param recipient Address receiving the minted tokens.
     * @param amount PRE-FEE amount of tokens bridged in (matches BridgeOutInitiated semantics).
     * The recipient actually receives `amount` less the bridge fee.
     * @param srcChainID Chain ID the bridge-out was initiated on.
     * @param destChainID Chain ID the bridge-in was executed on (== block.chainid).
     * @dev Emitted after `_mintWithBridgeFee` succeeds; CEI ordering — `processedMessages[transferId]`
     * is set BEFORE the mint so reentrancy cannot replay.
     */
    event BridgeReleased(
        bytes32 indexed transferId,
        address indexed recipient,
        uint256 amount,
        uint256 srcChainID,
        uint256 destChainID
    );

    /**
     * @notice Emitted when the Super Admin rotates the validator set.
     * @param oldRoot Previous validator merkle root (bytes32(0) if never configured).
     * @param newRoot New validator merkle root.
     * @param oldThreshold Previous m-of-n signature threshold (0 if never configured).
     * @param newThreshold New m-of-n signature threshold.
     * @dev Old values are read into locals, then written, then the event is emitted
     * (conventional emit-after-write ordering) so off-chain monitors can reconstruct
     * the full (root, threshold) transition.
     */
    event ValidatorSetUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 oldThreshold,
        uint256 newThreshold
    );

    /**
     * @inheritdoc IERC165Upgradeable
     */
    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) ||
            AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
            (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /**
     * @notice Internal function to mint tokens with a bridge fee applied.
     * @param user Address receiving the minted tokens.
     * @param tokenID Token ID being minted.
     * @param amount Amount of tokens to mint.
     */
    function _mintWithBridgeFee(address user, uint256 tokenID, uint256 amount) internal {
        uint256 bridgeFee = GNUSControlStorage.layout().bridgeFee;
        if (bridgeFee != 0) {
            // WR-04: defense-in-depth. updateBridgeFee in GNUSControl enforces
            // newFee <= MAX_FEE (200), but if MAX_FEE is ever raised above
            // FEE_DENOMINATOR, or storage is mis-initialized during an upgrade, the
            // subtraction below would panic-revert with no message. Guard locally.
            require(bridgeFee <= FEE_DENOMINATOR, "Bridge fee exceeds denominator");
            amount = (amount * (FEE_DENOMINATOR - bridgeFee)) / FEE_DENOMINATOR;
            // WR-02: post-fee guard. A pre-fee amount that floors to zero after the fee
            // would otherwise mint nothing while the source-chain burn is final. Revert
            // so the certificate can be re-submitted after a fee change.
            require(amount > 0, "Bridge fee consumes entire amount");
        }
        // Phase 9 D8/D9: counter + global cap AFTER fee adjustment (post-fee amount is
        // what enters existence). Cap fires only for GNUS_TOKEN_ID mints (root mint /
        // bridge-in); convert's GNUS-terminal mint leg is NOT routed through here and
        // is therefore NOT cap-checked (conversion conserves).
        if (tokenID == GNUS_TOKEN_ID) {
            GNUSTreasuryStorage.Layout storage t = GNUSTreasuryStorage.layout();
            require(t.globalSupply + amount <= GNUS_MAX_SUPPLY, "Global max supply exceeded");
            t.globalSupply += amount;
            t.chainSupply[block.chainid] += amount;
        }
        _mint(user, tokenID, amount, "");
        emit Transfer(address(0), user, amount);
    }

    /**
     * @notice Mint GNUS ERC20 tokens.
     * @param user Address receiving the minted tokens.
     * @param amount Amount of tokens to mint.
     * @dev Callable only by addresses with the `MINTER_ROLE`.
     */
    function mint(address user, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mintWithBridgeFee(user, GNUS_TOKEN_ID, amount);
    }

    /**
     * @notice Mint GNUS ERC20 tokens via the 3-arg overload (MINTER_ROLE bridge-in path).
     * @param user Address receiving the minted tokens.
     * @param tokenID Token ID to mint — MUST be GNUS_TOKEN_ID (0). Phase 9 D10: bridging a
     * child token in is effected as a mint of id 0 followed by a `convert` via GNUSTreasury.
     * @param amount Amount of tokens to mint.
     * @dev Callable only by addresses with the `MINTER_ROLE`.
     */
    function mint(address user, uint256 tokenID, uint256 amount) public onlyRole(MINTER_ROLE) {
        require(tokenID == GNUS_TOKEN_ID, "MINTER_ROLE mints GNUS only");
        _mintWithBridgeFee(user, tokenID, amount);
    }

    /**
     * @notice Burn GNUS ERC20 tokens.
     * @param user Address whose tokens will be burned.
     * @param amount Amount of tokens to burn.
     * @dev Callable only by addresses with the `MINTER_ROLE`.
     */
    function burn(address user, uint256 amount) public onlyRole(MINTER_ROLE) {
        _burn(user, GNUS_TOKEN_ID, amount);
        GNUSTreasuryStorage.Layout storage t = GNUSTreasuryStorage.layout();
        require(t.globalSupply >= amount, "Burn exceeds global supply");
        require(t.chainSupply[block.chainid] >= amount, "Burn exceeds chain supply");
        t.globalSupply -= amount;
        t.chainSupply[block.chainid] -= amount;
        emit Transfer(user, address(0), amount);
    }

    /**
     * @notice Creates `amount` tokens of token type `id`, and assigns them to `to`.
     * @dev This function overrides the `_mint` function from ERC1155Upgradeable.
     * It ensures that the recipient address is not the zero address, performs necessary checks and updates balances.
     * Emits a {TransferSingle} event.
     * @param to The address to which the minted tokens will be assigned.
     * @param id The ID of the token type to mint.
     * @param amount The amount of tokens to mint.
     * @param data Additional data with no specified format.
     *
     * Requirements:
     * - `to` cannot be the zero address.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the acceptance magic value.
     */
    function _mint(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal override(ERC1155Upgradeable) {
        require(to != address(0), "ERC1155: mint to the zero address");

        address operator = _msgSender();
        uint256[] memory ids = asSingletonArray(id);
        uint256[] memory amounts = asSingletonArray(amount);

        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

        ERC1155Storage.layout()._balances[id][to] += amount;
        emit TransferSingle(operator, address(0), to, id, amount);

        _afterTokenTransfer(operator, address(0), to, ids, amounts, data);
    }

    /**
     * @notice Burn tokens and emit an event for bridging to another chain.
     * @param amount Amount of tokens to bridge.
     * @param id Token ID being bridged.
     * @param destChainID Destination chain ID.
     * @param sgnsDestination 32-byte X component of the destination recipient's elliptic curve public key
     * on the SuperGenius chain (not an Ethereum address).
     * @param destinationYOdd Parity of the Y component of the public key (false = even, true = odd),
     * used together with `sgnsDestination` to reconstruct the full public key.
     */
    function bridgeOut(
        uint256 amount,
        uint256 id,
        uint256 destChainID,
        bytes32 sgnsDestination,
        bool destinationYOdd
    ) external {
        address sender = _msgSender();
        require(GNUSNFTFactoryStorage.layout().NFTs[id].nftCreated, "Token not created.");
        require(balanceOf(sender, id) >= amount, "Insufficient tokens.");
        require(sgnsDestination != bytes32(0), "Invalid destination key");

        require(destChainID != GNUSControlStorage.layout().chainID, "Cannot bridge to same chain");

        // Phase 13 D7 (13-06): bridging IS a transfer. The policy check MUST run here,
        // BEFORE the limiter charge and the _burn — the subsequent _burn fires
        // _beforeTokenTransfer, whose burn carve-out (to == 0) would otherwise permit
        // the bridge burn (the hook cannot distinguish "burn for bridge" from "burn for
        // spend/settle" — 13-RESEARCH Pattern 5 / Pitfall P3).
        _enforceBridgePolicy(sender, id);

        // CR-03: child-token (id != GNUS_TOKEN_ID) bridging skips the limiter hook
        // (the hook only aggregates GNUS_TOKEN_ID), so apply it explicitly here.
        // Phase 9 D1/D2: `amount` is already minion-denominated - charge directly,
        // no rate division. GNUS bridging is already charged by the _burn
        // hook, so it is excluded to avoid double-charging the user.
        // B1 provenance: bridgeOut does NOT touch globalSupply - the destination
        // chain's bridge-in mint is the + side.
        if (id != GNUS_TOKEN_ID) {
            if (LibDiamond.diamondStorage().contractOwner != sender) {
                GNUSWithdrawLimiterStorage.checkAndRecordWithdraw(sender, amount);
            } else {
                emit GNUSWithdrawLimiterStorage.SuperAdminBypass(sender, amount, "GNUSBridge.bridgeOut");
            }
        }

        _burn(sender, id, amount);
        emit BridgeOutInitiated(
            sender,
            id,
            amount,
            GNUSControlStorage.layout().chainID,
            destChainID,
            sgnsDestination,
            destinationYOdd
        );
    }

    /**
     * @notice Phase 13 D7 bridge transfer-policy gate (SC4).
     * @dev Bridging IS a transfer — policy-bound tokens are non-bridgeable in v1. Called from
     *      bridgeOut BEFORE the limiter charge and the _burn so a policy-bound revert consumes
     *      no withdrawal-limiter allowance and changes no state. Behavior per policy
     *      (GNUSLifecycleTypes.TransferPolicy):
     *        GNUS_TOKEN_ID      → return (GNUS always bridges; also the predicate's carve-out).
     *        UNRESTRICTED       → return (zero-default legacy behavior).
     *        ALLOWLISTED        → registry configured + isAllowed(SENDER).
     *        LOCKED_AFTER_START → return only pre-start (validFrom == 0 or now < validFrom);
     *                             revert at/after start (mirrors the transfer predicate).
     *        SOULBOUND → Phase 14 D-24: allowed ONLY for CREATOR_ROLE/ADMIN callers while
     *                     the entitlement is unexpired (D-23); other callers revert.
     *        ISSUER_ONLY / CONTROLLED_RESALE → revert (blocked in v1, D7).
     *
     *      Q4 v1 SIMPLIFICATION: the ALLOWLISTED bridge check targets the SENDER (the bridge
     *      initiator on this source chain), NOT the cross-chain destination — a cross-chain
     *      destination registry is not expressible without a cross-chain registry. v2 scope.
     *
     *      Implemented inline (not by calling GNUSLifecyclePolicy.enforceTransferPolicy) because
     *      the bridge semantics differ from the holder-to-holder predicate: the burn carve-out
     *      (to == 0) would permit the bridge burn, and ALLOWLISTED checks the sender here, not
     *      the destination.
     * @param sender The bridge initiator (source-chain holder).
     * @param id The token id being bridged.
     */
    function _enforceBridgePolicy(address sender, uint256 id) internal view {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        if (id == GNUS_TOKEN_ID) {
            return; // GNUS itself is always UNRESTRICTED
        }
        if (nft.transferPolicy == uint8(TransferPolicy.UNRESTRICTED)) {
            return; // zero-default preserves legacy behavior
        }
        if (nft.transferPolicy == uint8(TransferPolicy.ALLOWLISTED)) {
            // Q4 v1: registry checks the SENDER (source-chain bridge initiator).
            address registry = GNUSLifecycleStorage.layout().allowlistRegistry[id];
            require(registry != address(0), "ALLOWLISTED: no registry configured");
            require(
                IAllowlistRegistry(registry).isAllowed(sender),
                "ALLOWLISTED: bridge initiator not allowed"
            );
            return;
        }
        if (nft.transferPolicy == uint8(TransferPolicy.LOCKED_AFTER_START)) {
            // Pre-start bridges are allowed (matching the transfer predicate's pre-start
            // pass); the lock engages at validFrom.
            if (nft.validFrom == 0 || block.timestamp < nft.validFrom) {
                return;
            }
            revert("Policy-bound token cannot bridge in v1");
        }
        // Phase 14 D-24: SOULBOUND credits may bridge out ONLY under operator mediation —
        // the caller must hold CREATOR_ROLE or DEFAULT_ADMIN_ROLE (mint→bridge transport to
        // SG timed UTXOs, D-19/D-21/D-22). Non-privileged soulbound holders remain locked out.
        if (nft.transferPolicy == uint8(TransferPolicy.SOULBOUND)) {
            if (hasRole(DEFAULT_ADMIN_ROLE, sender) || hasRole(_CREATOR_ROLE, sender)) {
                // Phase 14 D-23: expired value must not reach SuperGenius. Gate BEFORE the
                // limiter charge + burn (call-site ordering unchanged — zero limiter
                // consumption on revert). Mirrors the "Sale ended" analogue
                // (GNUSLifecycleMint.sol) for both expiration modes; None passes.
                if (nft.expirationMode == uint8(ExpirationMode.PerTokenId)) {
                    require(
                        nft.validUntil == 0 || block.timestamp < nft.validUntil,
                        LICENSE_EXPIRED_ERROR
                    );
                } else if (nft.expirationMode == uint8(ExpirationMode.PerHolder)) {
                    uint64 holderExpiry = GNUSLifecycleStorage.layout().holderExpiresAt[id][sender];
                    require(
                        holderExpiry == 0 || block.timestamp < holderExpiry,
                        LICENSE_EXPIRED_ERROR
                    );
                }
                return;
            }
            revert("Policy-bound token cannot bridge in v1");
        }
        // ISSUER_ONLY, CONTROLLED_RESALE: non-bridgeable in v1 (D7).
        revert("Policy-bound token cannot bridge in v1");
    }

    /**
     * @notice Computes the EIP-191-wrapped digest that SG validators sign for a bridge-in.
     * @param transferId Source-chain burn transaction hash (replay-protection key).
     * @param srcChainID Chain ID the bridge-out was initiated on.
     * @param recipient Address receiving the minted tokens.
     * @param amount PRE-FEE amount of tokens to bridge in.
     * @return The EIP-191 message hash validators signed.
     * @dev Field order and types are load-bearing per CONTEXT D-08/D-10. `block.chainid` binds
     * the destination chain (cross-chain replay protection); `address(this)` binds the diamond
     * (cross-diamond replay protection). Wrapped with `toEthSignedMessageHash` per
     * 10-RESEARCH.md §Alternatives (EIP-191 chosen for wallet compatibility).
     */
    function _bridgeInDigest(
        bytes32 transferId,
        uint256 srcChainID,
        address recipient,
        uint256 amount
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                transferId,
                srcChainID,
                block.chainid,
                address(this),
                recipient,
                GNUS_TOKEN_ID,
                amount
            )
        );
        return ECDSAUpgradeable.toEthSignedMessageHash(structHash);
    }

    /**
     * @notice Verifies a threshold ECDSA certificate against the committed validator merkle root.
     * @param digest EIP-191-wrapped digest (output of `_bridgeInDigest`).
     * @param signatures Array of validator signatures over `digest`.
     * @param merkleProofs Parallel array of merkle proofs, one per signature, proving the
     * recovered signer is a member of `validatorMerkleRoot`.
     * @return validCount Number of valid signatures verified.
     * @dev Implements 10-RESEARCH.md §Pattern 2. Enforces:
     *  - `signatures.length == merkleProofs.length`
     *  - `validatorThreshold > 0` (Pitfall 7: unconfigured validator set must reject, not accept)
     *  - `signatures.length >= validatorThreshold` (D-12)
     *  - Recovered signers are strictly ascending (D-13 duplicate protection)
     *  - Each signer is a registered validator via merkle membership (D-15)
     *  - Leaf is `keccak256(abi.encodePacked(signer))` — 20-byte packed encoding per Pitfall 3
     *    (NOT `abi.encode` which pads to 32).
     */
    function _verifyThresholdCertificate(
        bytes32 digest,
        bytes[] calldata signatures,
        bytes32[][] calldata merkleProofs
    ) internal view returns (uint256 validCount) {
        require(signatures.length == merkleProofs.length, "Sig/proof length mismatch");
        GNUSBridgeValidatorStorage.Layout storage v = GNUSBridgeValidatorStorage.layout();
        require(v.validatorThreshold > 0, "Validator set not configured");
        require(signatures.length >= v.validatorThreshold, "Below threshold");

        address lastSigner = address(0);
        for (uint256 i = 0; i < signatures.length; ++i) {
            (address signer, ECDSAUpgradeable.RecoverError err) = ECDSAUpgradeable.tryRecover(
                digest,
                signatures[i]
            );
            require(err == ECDSAUpgradeable.RecoverError.NoError, "Bad signature");
            require(signer > lastSigner, "Signers not strictly ascending");
            lastSigner = signer;
            bytes32 leaf = keccak256(abi.encodePacked(signer));
            require(
                MerkleProofUpgradeable.verify(merkleProofs[i], v.validatorMerkleRoot, leaf),
                "Not a registered validator"
            );
            unchecked {
                ++validCount;
            }
        }
    }

    /**
     * @notice Executes a destination-chain bridge release against a threshold validator certificate.
     * @param transferId Source-chain burn transaction hash (free-form bytes32; replay-protection key).
     * @param srcChainID Chain ID the bridge-out was initiated on.
     * @param recipient Address receiving the minted tokens.
     * @param amount PRE-FEE amount of tokens to bridge in. Bridge fee is applied inside
     * `_mintWithBridgeFee`; recipient receives `amount - fee`.
     * @param signatures Validator signatures over the EIP-191 digest (strictly ascending by
     * recovered address).
     * @param merkleProofs Parallel merkle proofs, one per signature.
     * @dev Permissionless — authorization is the certificate itself, not the caller (D-09).
     * Body ordering is load-bearing for security:
     *  1. Pause check FIRST (D-20/D-21, Pitfall 4)
     *  2. Replay / chain / recipient / amount sanity checks (D-07, D-08)
     *  3. Threshold certificate verification (D-12, D-13, D-15)
     *  4. Mark `processedMessages[transferId] = true` BEFORE the mint (CEI, Pitfall 2, T-10-12)
     *  5. Mint via `_mintWithBridgeFee` so bridge fee, global cap, and chainSupply apply (D-22)
     * `GNUS_TOKEN_ID` is hardcoded (D-14) — child-token bridge-in is mint-of-id-0 followed by
     * `convert` via GNUSTreasury.
     */
    function bridgeIn(
        bytes32 transferId,
        uint256 srcChainID,
        address recipient,
        uint256 amount,
        bytes[] calldata signatures,
        bytes32[][] calldata merkleProofs
    ) external {
        require(!GNUSControlStorage.layout().paused, "GNUSControl: contract paused");
        GNUSBridgeValidatorStorage.Layout storage v = GNUSBridgeValidatorStorage.layout();
        require(!v.processedMessages[transferId], "Message already processed");
        require(block.chainid == GNUSControlStorage.layout().chainID, "Wrong destination chain");
        require(srcChainID != block.chainid, "Cannot bridge from same chain");
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");

        bytes32 digest = _bridgeInDigest(transferId, srcChainID, recipient, amount);
        _verifyThresholdCertificate(digest, signatures, merkleProofs);

        v.processedMessages[transferId] = true;
        _mintWithBridgeFee(recipient, GNUS_TOKEN_ID, amount);
        emit BridgeReleased(transferId, recipient, amount, srcChainID, block.chainid);
    }

    /**
     * @notice Rotates the validator set committed on-chain.
     * @param newRoot New merkle root of authorized validator addresses.
     * @param newThreshold New m-of-n signature threshold (must be > 0).
     * @dev Callable only by the Super Admin multisig (D-18). Old root/threshold are read
     * into locals, the new values are written, then `ValidatorSetUpdated` is emitted
     * (emit-after-write). Old root becomes invalid immediately — in-flight certificates
     * signed against the old root will fail verification (T-10-13 accepted risk; D-05
     * allows re-signing).
     */
    function setValidatorSet(bytes32 newRoot, uint256 newThreshold) external onlySuperAdminRole {
        require(newRoot != bytes32(0), "Invalid root");
        require(newThreshold > 0, "Invalid threshold");
        GNUSBridgeValidatorStorage.Layout storage v = GNUSBridgeValidatorStorage.layout();
        bytes32 oldRoot = v.validatorMerkleRoot;
        uint256 oldThreshold = v.validatorThreshold;
        v.validatorMerkleRoot = newRoot;
        v.validatorThreshold = newThreshold;
        emit ValidatorSetUpdated(oldRoot, newRoot, oldThreshold, newThreshold);
    }

    /**
     * @notice Retrieves the total supply of tokens in existence for the specified token ID.
     * @dev This function overrides the `totalSupply` function from the parent contract.
     * It calls an internal function to get the total supply of tokens for the GNUS token ID.
     * @return The total number of tokens currently in existence for the GNUS token ID.
     */
    function totalSupply() external view override returns (uint256) {
        return totalSupply(GNUS_TOKEN_ID);
    }

    /**
     * @notice Retrieves the balance of GNUS tokens for a specified account.
     * @dev This function overrides the balanceOf function from the inherited contract.
     * @param account The address of the account whose token balance is being queried.
     * @return The amount of GNUS tokens owned by the specified account.
     */
    function balanceOf(address account) external view override returns (uint256) {
        return balanceOf(account, GNUS_TOKEN_ID);
    }

    /**
     * @notice
     * @dev Moves `amount` tokens from the caller's account to `to`.
     * Returns a boolean value indicating whether the operation succeeded.
     * Emits a {Transfer} event.
     * @inheritdoc IERC20Upgradeable
     */
    function transfer(address to, uint256 amount) external virtual override returns (bool) {
        _safeTransferFrom(_msgSender(), to, GNUS_TOKEN_ID, amount, "");
        emit Transfer(_msgSender(), to, amount);
        return true;
    }

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(
        address owner,
        address spender
    ) public view virtual override returns (uint256) {
        return ERC20Storage.layout()._allowances[owner][spender];
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, amount);
        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, ERC20Storage.layout()._allowances[owner][spender] + addedValue);
        return true;
    }

    /**
     * @notice Approves the specified `amount` of tokens for the `spender` to spend on behalf of the caller.
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * @param spender The address which will spend the funds.
     * @param subtractedValue The amount of tokens to decrease the allowance by.
     * @return A boolean value indicating whether the operation succeeded.
     *
     * @dev IMPORTANT: Changing an allowance with this method brings the risk of someone using both the old and the new allowance due to transaction ordering.
     * One possible solution to mitigate this race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
     * see https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     */
    function decreaseAllowance(
        address spender,
        uint256 subtractedValue
    ) public virtual returns (bool) {
        address owner = _msgSender();
        uint256 currentAllowance = ERC20Storage.layout()._allowances[owner][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked {
            _approve(owner, spender, currentAllowance - subtractedValue);
        }

        return true;
    }

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function _safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal override(ERC1155Upgradeable) {
        require(to != address(0), "ERC1155: transfer to the zero address");

        address operator = _msgSender();
        uint256[] memory ids = asSingletonArray(id);
        uint256[] memory amounts = asSingletonArray(amount);

        _beforeTokenTransfer(operator, from, to, ids, amounts, data);

        uint256 fromBalance = ERC1155Storage.layout()._balances[id][from];
        require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");
        unchecked {
            ERC1155Storage.layout()._balances[id][from] = fromBalance - amount;
        }
        ERC1155Storage.layout()._balances[id][to] += amount;

        emit TransferSingle(operator, from, to, id, amount);

        _afterTokenTransfer(operator, from, to, ids, amounts, data);
    }

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external virtual override returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _safeTransferFrom(from, to, GNUS_TOKEN_ID, amount, "");
        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Internal function to set the allowance of a spender over the owner's tokens.
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     *
     * @param owner The address of the token owner.
     * @param spender The address of the spender.
     * @param amount The amount of tokens to be approved for spending.
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        ERC20Storage.layout()._allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Updates `owner` s allowance for `spender` based on spent `amount`.
     *
     * Does not update the allowance amount in case of infinite allowance.
     * Revert if not enough allowance is available.
     *
     * Might emit an {Approval} event.
     */
    function _spendAllowance(address owner, address spender, uint256 amount) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            unchecked {
                _approve(owner, spender, currentAllowance - amount);
            }
        }
    }
}
