// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/ERC1155Storage.sol";
import "@gnus.ai/contracts-upgradeable-diamond/utils/cryptography/ECDSAUpgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/utils/cryptography/MerkleProofUpgradeable.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSControlStorage.sol";
import "./GNUSTreasuryStorage.sol";
import "./GNUSBridgeValidatorStorage.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title BridgeMessage — V2 canonical source-event identity (BRIDGE-12, PD-BR-3).
/// @notice Replaces the Phase 10 free-form `transferId` replay key: the V2 key is the composite
///         of the BRIDGE_MESSAGE_ID_V2 domain separator and the four source-event identity
///         fields, so two valid bridge events in the same source transaction stay distinct
///         because their event indexes differ (SPEC :247-290). File-scope struct so the
///         bridgeIn ABI renders the canonical tuple type.
struct BridgeMessage {
    /// @dev Chain ID the bridge-out was initiated on (must differ from block.chainid).
    uint256 srcChainID;
    /// @dev Canonical identifier of the bridge contract/subsystem on the source network —
    ///      for an EVM source, the source bridge address left-padded to bytes32.
    bytes32 sourceBridgeID;
    /// @dev Source transaction hash or equivalent source-ledger transaction ID.
    bytes32 sourceTxHash;
    /// @dev EVM log index, SuperGenius output index, or another canonical event index
    ///      within sourceTxHash.
    uint256 sourceEventIndex;
    /// @dev Address receiving the minted (post-fee) tokens on this chain.
    address recipient;
    /// @dev PRE-FEE GNUS amount; `_mintWithBridgeFee` applies the destination bridge fee.
    uint256 amount;
}

/// @title IGNUSBridgeAttestorEvents
/// @notice Cross-system event surface for the GNUSBridgeAttestor facet (Phase 15).
/// @dev Solidity 0.8.19 does not support file-level events (added in 0.8.22), so the V2
///      events are declared in this interface; the facet inherits it to emit. ABI signature
///      is identical to a file-level declaration (IGNUSLicensingEvents pattern).
interface IGNUSBridgeAttestorEvents {
    /// @notice Emitted when the V2 attestor set is bootstrapped (BRIDGE-11, D-04).
    /// @param genesisAttestor One-leaf Genesis attestor address (the only epoch-0 signer).
    /// @param root One-leaf Genesis root keccak256(abi.encodePacked(genesisAttestor)).
    /// @param initiator superAdmin that performed the one-time bootstrap.
    event BridgeAttestorSetInitialized(address indexed genesisAttestor, bytes32 root, address initiator);

    /// @notice Emitted when a verified certificate advances the attestor root (Plan 15-02 bridgeIn).
    /// @param oldEpoch Epoch the certificate was verified against.
    /// @param newEpoch oldEpoch + 1 — exactly one increment per root transition.
    /// @param oldRoot Root the certificate was verified against.
    /// @param newRoot Root installed by the certificate.
    event BridgeAttestorSetAdvanced(
        uint64 indexed oldEpoch,
        uint64 indexed newEpoch,
        bytes32 indexed oldRoot,
        bytes32 newRoot
    );

    /// @notice Emitted when the superAdmin recovers the attestor set under emergency pause (D-05).
    /// @param oldEpoch Epoch before the recovery.
    /// @param newEpoch oldEpoch + 1 — post-state can never be epoch 0 (Genesis unrecoverable).
    /// @param oldRoot Root before the recovery.
    /// @param newRoot Recovery root installed while paused.
    event BridgeAttestorEmergencyReset(
        uint64 indexed oldEpoch,
        uint64 indexed newEpoch,
        bytes32 indexed oldRoot,
        bytes32 newRoot
    );

    /// @notice Emitted when the superAdmin overrides the active attestor threshold (D-03).
    /// @param oldThreshold Previous active threshold (0 before V2 bootstrap).
    /// @param newThreshold New active threshold (bounded ACTIVE_ATTESTOR_THRESHOLD..MAX_ATTESTOR_SIGNATURES).
    event BridgeAttestorActiveThresholdSet(uint256 oldThreshold, uint256 newThreshold);

    /// @notice Emitted when a V2 bridge-in certificate is verified and tokens are released
    ///         to the recipient (Plan 15-02 bridgeIn).
    /// @param transferId V2 messageId (`_bridgeMessageId` output) — the composite replay key.
    ///        The parameter NAME is kept from the Phase 10 declaration so the event signature
    ///        (topic0) stays byte-identical for off-chain monitors; the transferId→messageId
    ///        rename is docs-only (15-RESEARCH "State of the Art").
    /// @param recipient Address receiving the minted tokens.
    /// @param amount PRE-FEE amount of tokens bridged in (recipient receives `amount` less
    ///        the bridge fee applied in `_mintWithBridgeFee`).
    /// @param srcChainID Chain ID the bridge-out was initiated on.
    /// @param destChainID Chain ID the bridge-in was executed on (== block.chainid).
    /// @dev Emitted after the fee-mint succeeds; CEI ordering — `processedMessages[messageId]`
    ///      is set BEFORE the mint so reentrancy cannot replay.
    event BridgeReleased(
        bytes32 indexed transferId,
        address indexed recipient,
        uint256 amount,
        uint256 srcChainID,
        uint256 destChainID
    );
}

/// @title GNUSBridgeAttestor
/// @notice V2 bridge-in attestor facet: certificate `bridgeIn` + Genesis bootstrap, threshold
///         override, and emergency recovery (Phase 15).
/// @dev Plan 15-01 facet split (D-01), completed by Plan 15-02: this facet owns the entire
///      Phase 15 V2 bridge-in surface — the certificate `bridgeIn` with the rolling-root
///      transition (BRIDGE-15), the `BRIDGE_CERTIFICATE_V2` split-encode digest (BRIDGE-13),
///      the per-signer Merkle certificate verifier (BRIDGE-14), the canonical `BridgeMessage`
///      replay key (BRIDGE-12), the one-time Genesis bootstrap `initializeBridgeAttestorV2`,
///      the epoch-derived threshold helper with its bounded superAdmin override
///      `setBridgeAttestorActiveThreshold`, the paused-gated `emergencyRecoverAttestorSet`,
///      and the V2 view getters. GNUSBridge owns bridgeOut, policy gating, and the mint/burn
///      paths — its legacy bridge-in block was deleted in Plan 15-02 (D-06). The two facets
///      NEVER call each other — state is shared only through diamond storage
///      (GNUSBridgeValidatorStorage / GNUSControlStorage / GNUSTreasuryStorage).
///
///      Storage (BRIDGE-10, D-11): appended slots +3..+6 of GNUSBridgeValidatorStorage —
///      bridgeAttestorRoot (+3), bridgeAttestorEpoch (+4), bridgeAttestorV2Initialized (+5),
///      activeAttestorThreshold (+6). Legacy slots +0..+2 stay frozen (dead once V2 is active).
///
///      Bootstrap wiring (D-04): `initializeBridgeAttestorV2(address)` takes an argument, so it
///      is deliberately NOT wired as a config deployInit/upgradeInit (those encode zero-arg
///      calls); it runs as a manual superAdmin call post-cut, keeping the Genesis address out
///      of this repo.
/// @custom:security-contact support@gnus.ai
contract GNUSBridgeAttestor is GNUSERC1155MaxSupply, GeniusAccessControl, IGNUSBridgeAttestorEvents {
    /// @dev Epoch-0 (Genesis) signature threshold per SPEC — immutable 1-of-1 bootstrap only.
    uint256 private constant GENESIS_ATTESTOR_THRESHOLD = 1;
    /// @dev Steady-state signature threshold per SPEC (PD-BR-2 revised); written to the override
    ///      slot at bootstrap and the floor of the superAdmin setter — structurally prevents
    ///      recreating 1-of-N while active.
    uint256 private constant ACTIVE_ATTESTOR_THRESHOLD = 2;
    /// @dev Hard cap on signatures per certificate per SPEC; also the ceiling of the override
    ///      setter (the certificate cap rejects anything higher anyway).
    uint256 private constant MAX_ATTESTOR_SIGNATURES = 16;
    /// @dev V2 canonical source-event message domain (PD-BR-3 / BRIDGE-12). Declared now so
    ///      Plan 15-02 does not re-open the constants block; consumed by 15-02 code only.
    bytes32 private constant BRIDGE_MESSAGE_ID_V2 = keccak256("GNUS_BRIDGE_MESSAGE_ID_V2");
    /// @dev V2 certificate domain separator (PD-BR-4 / BRIDGE-13). Declared now so Plan 15-02
    ///      does not re-open the constants block; consumed by 15-02 code only.
    bytes32 private constant BRIDGE_CERTIFICATE_V2 = keccak256("GNUS_BRIDGE_CERTIFICATE_V2");

    /// @dev Validation revert reasons — named constants (no magic strings).
    string private constant _ERR_ZERO_GENESIS = "Genesis attestor is zero address";
    string private constant _ERR_ALREADY_INITIALIZED = "Attestor set already initialized";
    string private constant _ERR_THRESHOLD_BELOW_FLOOR = "Threshold below active floor";
    string private constant _ERR_THRESHOLD_ABOVE_CAP = "Threshold above attestor cap";
    string private constant _ERR_RECOVERY_NOT_PAUSED = "GNUSControl: contract must be paused";
    string private constant _ERR_RECOVERY_ROOT_ZERO = "Invalid recovery root";
    string private constant _ERR_RECOVERY_NOT_INITIALIZED = "Attestor set not initialized";
    /// @dev bridgeIn / certificate-verifier validation revert reasons (Plan 15-02).
    string private constant _ERR_BRIDGE_PAUSED = "GNUSControl: contract paused";
    string private constant _ERR_V2_NOT_INITIALIZED = "Bridge attestor V2 not initialized";
    string private constant _ERR_WRONG_DESTINATION_CHAIN = "Wrong destination chain";
    string private constant _ERR_SAME_CHAIN = "Cannot bridge from same chain";
    string private constant _ERR_ZERO_SOURCE_BRIDGE = "Invalid source bridge";
    string private constant _ERR_ZERO_SOURCE_TX = "Invalid source transaction";
    string private constant _ERR_ZERO_RECIPIENT = "Invalid recipient";
    string private constant _ERR_ZERO_AMOUNT = "Invalid amount";
    string private constant _ERR_ZERO_NEXT_ROOT = "Invalid next attestor root";
    string private constant _ERR_MESSAGE_PROCESSED = "Message already processed";
    string private constant _ERR_ROOT_NOT_CONFIGURED = "Bridge attestor root not configured";
    string private constant _ERR_GENESIS_MUST_ADVANCE = "Genesis certificate must install API attestors";
    string private constant _ERR_SIG_PROOF_MISMATCH = "Sig/proof length mismatch";
    string private constant _ERR_BELOW_THRESHOLD = "Below threshold";
    string private constant _ERR_TOO_MANY_SIGNATURES = "Too many attestor signatures";
    string private constant _ERR_BAD_SIGNATURE = "Bad signature";
    string private constant _ERR_NOT_ASCENDING = "Signers not strictly ascending";
    string private constant _ERR_NOT_ATTESTOR = "Not a registered attestor";
    /// @dev Fee denominator (thousandths) for the `_mintWithBridgeFee` inline replica —
    ///      identical value to GNUSBridge.FEE_DENOMINATOR (twin copies must stay in sync).
    uint256 private constant FEE_DENOMINATOR = 1000;

    /// @notice ERC-20 Transfer event for the bridge-in mint leg (topic-equal to
    ///         IERC20Upgradeable.Transfer — Solidity 0.8.19 cannot emit through a qualified
    ///         interface name, so the identical signature is declared locally;
    ///         GNUSLicensingPurchase.sol precedent).
    event Transfer(address indexed from, address indexed to, uint256 value);

    /// @notice Checks if the contract supports a specific interface.
    /// @dev Diamond-aware override (GNUSRedeemAdapter.sol:35-47 shape) — ORs ERC1155 and
    ///      AccessControlEnumerable interface support with any interfaces registered in the
    ///      diamond's supportedInterfaces mapping.
    /// @param interfaceId The ID of the interface to check.
    /// @return True if the interface is supported.
    function supportsInterface(bytes4 interfaceId)
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

    /// @notice One-time Genesis bootstrap of the V2 attestor set (BRIDGE-11, D-03/D-04).
    /// @dev Post-cut manual superAdmin call — NOT a deployInit/upgradeInit (it takes an
    ///      argument; the tooling encodes zero-arg initializers, and the Genesis address must
    ///      not appear in this repo). One-shot: `bridgeAttestorV2Initialized` is written true
    ///      here and never resets — not even by `emergencyRecoverAttestorSet` — so bootstrap
    ///      can run exactly once per diamond. Writes the one-leaf Genesis root
    ///      `keccak256(abi.encodePacked(genesisAttestor))` (20-byte packed leaf, Pitfall 3) at
    ///      epoch 0 and installs the default active threshold per D-03 "defaults set at init".
    ///      The first successful certificate MUST advance to a different root (Plan 15-02).
    /// @param genesisAttestor Genesis attestor address (the only epoch-0 signer; must be nonzero).
    function initializeBridgeAttestorV2(address genesisAttestor) external onlySuperAdminRole {
        require(genesisAttestor != address(0), _ERR_ZERO_GENESIS);
        GNUSBridgeValidatorStorage.Layout storage v = GNUSBridgeValidatorStorage.layout();
        require(!v.bridgeAttestorV2Initialized, _ERR_ALREADY_INITIALIZED);
        v.bridgeAttestorRoot = keccak256(abi.encodePacked(genesisAttestor));
        v.bridgeAttestorEpoch = 0;
        v.bridgeAttestorV2Initialized = true;
        v.activeAttestorThreshold = ACTIVE_ATTESTOR_THRESHOLD;
        emit BridgeAttestorSetInitialized(genesisAttestor, v.bridgeAttestorRoot, _msgSender());
    }

    /// @notice Overrides the active (epoch > 0) attestor signature threshold (D-03).
    /// @dev Epoch-0 threshold is immutable (GENESIS_ATTESTOR_THRESHOLD); this setter only
    ///      touches the active override slot. The floor structurally prevents recreating a
    ///      1-of-N active set; the cap matches the certificate signature limit (anything
    ///      higher could never verify anyway). Read-old, write, emit-after-write.
    /// @param newThreshold New active threshold (ACTIVE_ATTESTOR_THRESHOLD..MAX_ATTESTOR_SIGNATURES).
    function setBridgeAttestorActiveThreshold(uint256 newThreshold) external onlySuperAdminRole {
        require(newThreshold >= ACTIVE_ATTESTOR_THRESHOLD, _ERR_THRESHOLD_BELOW_FLOOR);
        require(newThreshold <= MAX_ATTESTOR_SIGNATURES, _ERR_THRESHOLD_ABOVE_CAP);
        GNUSBridgeValidatorStorage.Layout storage v = GNUSBridgeValidatorStorage.layout();
        uint256 oldThreshold = v.activeAttestorThreshold;
        v.activeAttestorThreshold = newThreshold;
        emit BridgeAttestorActiveThresholdSet(oldThreshold, newThreshold);
    }

    /// @notice Emergency recovery of the attestor set — the D-05 conversion of the legacy
    ///         `setValidatorSet` routine rotation.
    /// @dev Requires the diamond to be PAUSED (inverted pause gate — normal-operation root
    ///      changes flow only through verified certificates), a nonzero new root, and an
    ///      initialized V2 set (recovery presupposes a live set). Always writes
    ///      `epoch = oldEpoch + 1`, so the post-state epoch is never 0 — together with the
    ///      one-shot init this makes Genesis structurally unrecoverable. Never touches
    ///      `bridgeAttestorV2Initialized`. Not a Genesis path, not routine rotation.
    /// @param newRoot Nonzero merkle root of the recovery attestor set.
    function emergencyRecoverAttestorSet(bytes32 newRoot) external onlySuperAdminRole {
        require(GNUSControlStorage.layout().paused, _ERR_RECOVERY_NOT_PAUSED);
        require(newRoot != bytes32(0), _ERR_RECOVERY_ROOT_ZERO);
        GNUSBridgeValidatorStorage.Layout storage v = GNUSBridgeValidatorStorage.layout();
        require(v.bridgeAttestorV2Initialized, _ERR_RECOVERY_NOT_INITIALIZED);
        bytes32 oldRoot = v.bridgeAttestorRoot;
        uint256 oldEpoch = v.bridgeAttestorEpoch;
        v.bridgeAttestorRoot = newRoot;
        v.bridgeAttestorEpoch = oldEpoch + 1;
        emit BridgeAttestorEmergencyReset(uint64(oldEpoch), uint64(oldEpoch + 1), oldRoot, newRoot);
    }

    /// @notice Epoch-derived required signature count (D-03, WR-04-style zero guard).
    /// @dev Genesis epoch (0) always requires GENESIS_ATTESTOR_THRESHOLD — the certificate can
    ///      never choose its own difficulty. For epoch > 0 the superAdmin override applies;
    ///      a zero (unset/corrupted) override falls back to ACTIVE_ATTESTOR_THRESHOLD so a
    ///      bad override can never satisfy a `signatures.length >= 0` check (defense-in-depth).
    /// @param epoch Attestor epoch the certificate is verified against.
    /// @return Required number of distinct attestor signatures.
    function _bridgeAttestorThreshold(uint256 epoch) internal view returns (uint256) {
        if (epoch == 0) {
            return GENESIS_ATTESTOR_THRESHOLD;
        }
        uint256 threshold = GNUSBridgeValidatorStorage.layout().activeAttestorThreshold;
        if (threshold == 0) {
            return ACTIVE_ATTESTOR_THRESHOLD;
        }
        return threshold;
    }

    /// @notice Computes the V2 composite replay key for a bridge message (BRIDGE-12, SPEC :272-290).
    /// @dev keccak256 over (BRIDGE_MESSAGE_ID_V2, srcChainID, sourceBridgeID, sourceTxHash,
    ///      sourceEventIndex). Recipient and amount are deliberately NOT in the replay key —
    ///      they are bound by the certificate digest instead. Feeds the existing slot-0
    ///      `processedMessages` mapping (D-07 reuse — no storage migration); legacy
    ///      transferId keys and V2 messageIds coexist collision-free in one namespace
    ///      (domain-separated hashes).
    /// @param message The canonical bridge message being released.
    /// @return The V2 messageId replay key.
    function _bridgeMessageId(BridgeMessage calldata message) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                BRIDGE_MESSAGE_ID_V2,
                message.srcChainID,
                message.sourceBridgeID,
                message.sourceTxHash,
                message.sourceEventIndex
            )
        );
    }

    /// @notice Computes the EIP-191-wrapped BRIDGE_CERTIFICATE_V2 digest attestors sign
    ///         (BRIDGE-13, D-02, SPEC :357-395).
    /// @dev SPLIT-ENCODE (D-02, locked): three partial `abi.encode` groups joined by
    ///      `bytes.concat`. Every field is a value type occupying exactly one 32-byte word
    ///      (`bytes32`, `uint256`, `uint64` zero-padded, `address`), so the concatenation is
    ///      BYTE-IDENTICAL to the SPEC's flat 13-field `abi.encode` — the flat form hits
    ///      CompilerError: Stack too deep under 0.8.19 + optimizer(1000) + no viaIR in every
    ///      facet shape probed (15-RESEARCH Pattern 2). Do NOT flatten and do NOT reorder —
    ///      the field order is protocol (pinned by the BRIDGE-18 cross-language vectors).
    ///      `block.chainid` binds the destination chain and `address(this)` binds the diamond
    ///      (D-08/D-10 carried forward); the root/epoch/nextRoot triple binds the attestor
    ///      transition (cross-root replay impossible).
    /// @param message The canonical bridge message being released.
    /// @param currentAttestorRoot Root the certificate must verify against.
    /// @param currentAttestorEpoch Epoch of `currentAttestorRoot` (uint64 in the digest
    ///        signature; abi.encode pads it to one 32-byte word identically to uint256).
    /// @param nextAttestorRoot Root the certificate installs (may equal the current root).
    /// @return The EIP-191 message hash attestors sign.
    function _bridgeInDigestV2(
        BridgeMessage calldata message,
        bytes32 currentAttestorRoot,
        uint64 currentAttestorEpoch,
        bytes32 nextAttestorRoot
    ) internal view returns (bytes32) {
        // Split-encode: byte-identical to the flat 13-field abi.encode (every field is one
        // 32-byte word) — required to stay under the 0.8.19 stack limit (no viaIR).
        bytes32 structHash = keccak256(
            bytes.concat(
                abi.encode(BRIDGE_CERTIFICATE_V2, currentAttestorEpoch, currentAttestorRoot, nextAttestorRoot),
                abi.encode(message.srcChainID, message.sourceBridgeID, message.sourceTxHash, message.sourceEventIndex),
                abi.encode(block.chainid, address(this), message.recipient, GNUS_TOKEN_ID, message.amount)
            )
        );
        return ECDSAUpgradeable.toEthSignedMessageHash(structHash);
    }

    /// @notice Verifies a threshold ECDSA certificate against the CURRENT attestor root
    ///         (BRIDGE-14, SPEC :415-458).
    /// @dev Mechanics carried verbatim from the Phase 10 verifier (GNUSBridge
    ///      `_verifyThresholdCertificate` conventions): sig/proof length parity, threshold
    ///      floor, `tryRecover` + `RecoverError.NoError` require, strictly-ascending
    ///      recovered signers (D-13 — deterministic order + duplicate protection), and the
    ///      20-byte packed merkle leaf `keccak256(abi.encodePacked(signer))` (Pitfall 3 —
    ///      NOT abi.encode which pads to 32). New in V2: the MAX_ATTESTOR_SIGNATURES cap
    ///      (bounds verify gas, T-15-15) and proofs verify against `currentRoot` ONLY —
    ///      never `nextAttestorRoot`: a rogue attestor admitted in the next root cannot
    ///      authorize the certificate that installs it (SPEC :349, T-15-10). ECDSAUpgradeable
    ///      / MerkleProofUpgradeable only — never hand-rolled crypto.
    /// @param digest EIP-191-wrapped digest (output of `_bridgeInDigestV2`).
    /// @param currentRoot Root every recovered signer must be a member of.
    /// @param requiredSignatures Epoch-derived threshold (the certificate cannot choose
    ///        its own difficulty — SPEC :199).
    /// @param signatures Attestor signatures over `digest` (strictly ascending by signer).
    /// @param merkleProofs Parallel merkle proofs, one per signature.
    function _verifyBridgeAttestorCertificate(
        bytes32 digest,
        bytes32 currentRoot,
        uint256 requiredSignatures,
        bytes[] calldata signatures,
        bytes32[][] calldata merkleProofs
    ) internal view {
        require(signatures.length == merkleProofs.length, _ERR_SIG_PROOF_MISMATCH);
        require(signatures.length >= requiredSignatures, _ERR_BELOW_THRESHOLD);
        require(signatures.length <= MAX_ATTESTOR_SIGNATURES, _ERR_TOO_MANY_SIGNATURES);
        address lastSigner = address(0);
        for (uint256 i = 0; i < signatures.length; ++i) {
            (address signer, ECDSAUpgradeable.RecoverError err) = ECDSAUpgradeable.tryRecover(
                digest,
                signatures[i]
            );
            require(err == ECDSAUpgradeable.RecoverError.NoError, _ERR_BAD_SIGNATURE);
            require(signer > lastSigner, _ERR_NOT_ASCENDING);
            lastSigner = signer;
            bytes32 leaf = keccak256(abi.encodePacked(signer)); // 20-byte packed (Pitfall 3)
            require(MerkleProofUpgradeable.verify(merkleProofs[i], currentRoot, leaf), _ERR_NOT_ATTESTOR);
        }
    }

    /// @notice Internal function to mint tokens with a bridge fee applied.
    /// @dev TWIN REPLICA (Phase 15 Pitfall 1): VERBATIM copy of GNUSBridge._mintWithBridgeFee —
    ///      the sibling facets never call each other, so the V2 bridge-in mint carries its own
    ///      semantics-identical copy (fee math, WR-02 zero-post-fee guard, WR-04 denominator
    ///      guard, global cap + chainSupply accounting, _mint + Transfer). Any change here
    ///      MUST be mirrored in GNUSBridge.sol and vice versa — drift = forked fee behavior.
    /// @param user Address receiving the minted tokens.
    /// @param tokenID Token ID being minted.
    /// @param amount Amount of tokens to mint.
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

    /// @notice Creates `amount` tokens of token type `id`, and assigns them to `to`.
    /// @dev TWIN REPLICA (Phase 15 Pitfall 1): VERBATIM copy of the GNUSBridge._mint override
    ///      (GNUSRedeemAdapter._mint shape) — no ERC-1155 receiver acceptance check, so
    ///      contract recipients (Safes, smart wallets, ERC-20 proxies) can receive bridged
    ///      GNUS. Any change here MUST be mirrored in GNUSBridge.sol and vice versa.
    ///      Emits a {TransferSingle} event.
    /// @param to The address to which the minted tokens will be assigned.
    /// @param id The ID of the token type to mint.
    /// @param amount The amount of tokens to mint.
    /// @param data Additional data with no specified format.
    ///
    /// Requirements:
    /// - `to` cannot be the zero address.
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

    /// @notice Executes a destination-chain bridge release against a V2 attestor certificate
    ///         and performs the rolling-root transition (BRIDGE-15, D-07, SPEC :476-567).
    /// @dev SPEC ordering, steps (a)-(j):
    ///       (a) pause check FIRST (D-20/D-21 — before any certificate work);
    ///       (b) V2 bootstrap gate;
    ///       (c) destination/message validation (dest-chain + cross-chain + nonzero fields);
    ///       (d) replay check under the V2 messageId (slot-0 mapping reuse, D-07);
    ///       (e) cache current root/epoch + Genesis must-advance gate (Pitfall 5 — epoch 0
    ///           cannot persist 1-of-1 mode);
    ///       (f) exact signed digest (split-encode, D-02);
    ///       (g) threshold certificate verification against the CURRENT root only;
    ///       (h) EFFECTS BEFORE MINT (CEI, D-07): replay mark, then — only when
    ///           nextAttestorRoot != currentRoot — install the new root, increment the
    ///           epoch by exactly one, and emit BridgeAttestorSetAdvanced (an unchanged
    ///           root processes the claim with NO epoch bump and no event);
    ///       (i) `_mintWithBridgeFee` via the inline replica;
    ///       (j) BridgeReleased under the canonical V2 message identity.
    ///      A reverting mint reverts the root update and the replay marker with the whole
    ///      transaction (T-15-09 atomicity). Permissionless — authorization is the
    ///      certificate, not the caller (D-09). `GNUS_TOKEN_ID` is hardcoded (D-14).
    ///      No D-24 policy gate and no limiter charge on this path by design: bridge-in
    ///      mints GNUS_TOKEN_ID only (the Phase-13 policy predicate's carve-out) and never
    ///      charged the withdrawal limiter (that is bridgeOut-only).
    /// @param message Canonical source-event bridge message.
    /// @param nextAttestorRoot Root the certificate installs (nonzero; at epoch 0 it MUST
    ///        differ from the current root).
    /// @param signatures Attestor signatures over the certificate digest (strictly ascending
    ///        by recovered address).
    /// @param merkleProofs Parallel per-signer membership proofs against the current root.
    function bridgeIn(
        BridgeMessage calldata message,
        bytes32 nextAttestorRoot,
        bytes[] calldata signatures,
        bytes32[][] calldata merkleProofs
    ) external {
        // (a) Pause check FIRST (D-20/D-21) — before any certificate work.
        require(!GNUSControlStorage.layout().paused, _ERR_BRIDGE_PAUSED);
        GNUSBridgeValidatorStorage.Layout storage v = GNUSBridgeValidatorStorage.layout();
        // (b) The V2 attestor set must be bootstrapped.
        require(v.bridgeAttestorV2Initialized, _ERR_V2_NOT_INITIALIZED);
        // (c) Destination and message validation.
        require(block.chainid == GNUSControlStorage.layout().chainID, _ERR_WRONG_DESTINATION_CHAIN);
        require(message.srcChainID != block.chainid, _ERR_SAME_CHAIN);
        require(message.sourceBridgeID != bytes32(0), _ERR_ZERO_SOURCE_BRIDGE);
        require(message.sourceTxHash != bytes32(0), _ERR_ZERO_SOURCE_TX);
        require(message.recipient != address(0), _ERR_ZERO_RECIPIENT);
        require(message.amount > 0, _ERR_ZERO_AMOUNT);
        require(nextAttestorRoot != bytes32(0), _ERR_ZERO_NEXT_ROOT);
        // (d) Replay check under the V2-derived composite key (slot-0 mapping reuse, D-07).
        bytes32 messageId = _bridgeMessageId(message);
        require(!v.processedMessages[messageId], _ERR_MESSAGE_PROCESSED);
        // (e) Cache the current set; root gate + Genesis must-advance rule (Pitfall 5).
        bytes32 currentRoot = v.bridgeAttestorRoot;
        uint256 currentEpoch = v.bridgeAttestorEpoch;
        require(currentRoot != bytes32(0), _ERR_ROOT_NOT_CONFIGURED);
        if (currentEpoch == 0) {
            require(nextAttestorRoot != currentRoot, _ERR_GENESIS_MUST_ADVANCE);
        }
        // (f) Exact signed digest (epoch cast to uint64 — one padded word, D-02).
        bytes32 digest = _bridgeInDigestV2(message, currentRoot, uint64(currentEpoch), nextAttestorRoot);
        // (g) Certificate verification against the CURRENT root only (T-15-10).
        _verifyBridgeAttestorCertificate(
            digest,
            currentRoot,
            _bridgeAttestorThreshold(currentEpoch),
            signatures,
            merkleProofs
        );
        // (h) EFFECTS BEFORE MINT (CEI, D-07 / T-15-09).
        v.processedMessages[messageId] = true;
        if (nextAttestorRoot != currentRoot) {
            v.bridgeAttestorRoot = nextAttestorRoot;
            v.bridgeAttestorEpoch = currentEpoch + 1;
            emit BridgeAttestorSetAdvanced(
                uint64(currentEpoch),
                uint64(currentEpoch + 1),
                currentRoot,
                nextAttestorRoot
            );
        }
        // (i) Fee-mint through the inline replica (economics identical to GNUSBridge).
        _mintWithBridgeFee(message.recipient, GNUS_TOKEN_ID, message.amount);
        // (j) Release event under the canonical V2 message identity.
        emit BridgeReleased(messageId, message.recipient, message.amount, message.srcChainID, block.chainid);
    }

    /// @notice Returns the current V2 attestor merkle root.
    /// @dev bytes32(0) means the V2 set is not bootstrapped.
    /// @return Current bridgeAttestorRoot.
    function bridgeAttestorRoot() external view returns (bytes32) {
        return GNUSBridgeValidatorStorage.layout().bridgeAttestorRoot;
    }

    /// @notice Returns the current V2 attestor epoch.
    /// @dev 0 = Genesis epoch (or not bootstrapped — check bridgeAttestorRoot/init flag).
    /// @return Current bridgeAttestorEpoch.
    function bridgeAttestorEpoch() external view returns (uint256) {
        return GNUSBridgeValidatorStorage.layout().bridgeAttestorEpoch;
    }

    /// @notice Returns the effective active attestor threshold for the current epoch.
    /// @dev Returns the epoch-derived value from `_bridgeAttestorThreshold(bridgeAttestorEpoch)`
    ///      — GENESIS_ATTESTOR_THRESHOLD at epoch 0, otherwise the stored override with the
    ///      zero-guard fallback.
    /// @return Effective required signature count at the current epoch.
    function activeBridgeAttestorThreshold() external view returns (uint256) {
        return _bridgeAttestorThreshold(GNUSBridgeValidatorStorage.layout().bridgeAttestorEpoch);
    }
}
