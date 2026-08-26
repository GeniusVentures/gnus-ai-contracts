// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/ERC1155Storage.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/extensions/ERC1155SupplyStorage.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSLifecycleStorage.sol";
import "./GNUSLifecycleTypes.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title GNUSLifecycle
/// @notice Time-bound ERC-1155 lifecycle CONFIG & VIEW facet (Phase 13, SC2/SC5/SC8, D2/D4/D13).
/// @dev Plan 13-03 facet split: this facet owns configuration + read paths only. Minting and
///      settlement live on the sibling GNUSLifecycleMint facet. The two facets NEVER call each
///      other — they share state only through diamond storage (GNUSNFTFactoryStorage for the NFT
///      struct lifecycle fields, GNUSLifecycleStorage for per-holder clocks / caps / registry).
///
///      This facet reads/writes:
///        - GNUSNFTFactoryStorage.layout().NFTs[id]   (lifecycle config fields, slots +8/+9/+10)
///        - GNUSLifecycleStorage.layout()             (per-holder clocks [view], caps, registry)
///        - ERC1155SupplyStorage.layout()._totalSupply (first-mint immutability gate)
///
///      Authorization: creator-or-admin per GNUSNFTFactory.sol:92 precedent.
///      Immutability (D4 / Q6): policy-class fields gate on _totalSupply[id] == 0 — once any
///      token of id has been minted, configureLifecycle and setAllowlistRegistry revert.
///      Timestamps (validFrom, validUntil) remain mutable post-mint to support subscription
///      renewal and event rescheduling (D4).
/// @custom:security-contact support@gnus.ai
contract GNUSLifecycle is GNUSERC1155MaxSupply, GeniusAccessControl {
    /// @dev Role identifier for creators — identical value to GNUSNFTFactory.CREATOR_ROLE
    ///      (keccak256("CREATOR_ROLE")). Re-declared locally because GNUSLifecycle cannot import
    ///      GNUSNFTFactory (circular) but needs the same role for createNFTWithLifecycle auth.
    bytes32 private constant _CREATOR_ROLE = keccak256("CREATOR_ROLE");

    /// @notice Checks if the contract supports a specific interface.
    /// @dev Overrides the diamond-aware supportsInterface (matches GNUSNFTFactory.sol:129
    ///      and GNUSRedeemAdapter.sol:38) — combines ERC1155 and AccessControlEnumerable
    ///      interfaces with any interfaces registered in the diamond's supportedInterfaces
    ///      mapping.
    /// @param interfaceId The ID of the interface to check.
    /// @return True if the interface is supported.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) || AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
        (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /// @notice Emitted when a token's lifecycle configuration is written (D4 / security #15).
    /// @param id Token id configured.
    /// @param cfg The full LifecycleConfig payload that was written.
    /// @param operator The creator or admin who performed the configuration.
    event LifecycleConfigured(uint256 indexed id, LifecycleConfig cfg, address indexed operator);

    /// @notice Emitted when validFrom is mutated post-mint (D4).
    /// @param id Token id.
    /// @param oldValidFrom Previous value.
    /// @param newValidFrom New value.
    /// @param operator The creator or admin who performed the mutation.
    event ValidFromUpdated(uint256 indexed id, uint64 oldValidFrom, uint64 newValidFrom, address indexed operator);

    /// @notice Emitted when validUntil is mutated post-mint (D4).
    /// @param id Token id.
    /// @param oldValidUntil Previous value.
    /// @param newValidUntil New value.
    /// @param operator The creator or admin who performed the mutation.
    event ValidUntilUpdated(uint256 indexed id, uint64 oldValidUntil, uint64 newValidUntil, address indexed operator);

    // NOTE (plan 13-03 facet split): the `HolderExpiryUpdated` and `Settled` events are declared
    // on the GNUSLifecycleMint facet — the single owner of settlement / renewal / mint enforcement.
    // They are NOT re-declared here. The two facets never call each other; they share state only
    // through diamond storage (GNUSNFTFactoryStorage + GNUSLifecycleStorage).

    /// @notice Emitted when a per-wallet mint cap is set (D10).
    /// @param id Token id.
    /// @param cap Maximum cumulative minions a single wallet may mint (0 = uncapped).
    /// @param operator The creator or admin who set the cap.
    event PerWalletCapSet(uint256 indexed id, uint256 cap, address indexed operator);

    /// @notice Creator-or-admin authorization helper (Phase 13 D4).
    /// @dev Matches GNUSNFTFactory.sol:92 pattern — creator of the token OR any address with
    ///      DEFAULT_ADMIN_ROLE. Reverts with a consistent message on unauthorized callers.
    /// @param nft The NFT storage record being authorized against.
    /// @param sender The caller attempting the mutation.
    function _requireCreatorOrAdmin(NFT storage nft, address sender) internal view {
        require(nft.nftCreated, "Token not created");
        require(
            (sender == nft.creator) || hasRole(DEFAULT_ADMIN_ROLE, sender),
            "Only creator or admin"
        );
    }

    /// @notice D13 view: is the token class currently usable at the ID level?
    /// @dev Reverts when the token has not been created (matches uri() precedent at
    ///      GNUSNFTFactory.sol:73). Applies the D2 validity predicate at the ID level:
    ///      - validFrom gate: block.timestamp < validFrom → false
    ///      - None: true (never expires at ID level)
    ///      - PerTokenId: validUntil == 0 || block.timestamp < validUntil
    ///      - PerHolder: true (per-holder is holder-specific; ID-level gate does not expire)
    /// @param id Token id.
    /// @return True if the token class is usable at the ID level.
    function isTokenActive(uint256 id) external view returns (bool) {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        require(nft.nftCreated, "Token not created");

        if (nft.validFrom != 0 && block.timestamp < nft.validFrom) {
            return false;
        }
        if (nft.expirationMode == uint8(ExpirationMode.PerTokenId)) {
            return nft.validUntil == 0 || block.timestamp < nft.validUntil;
        }
        // None and PerHolder are always active at the ID level (D2).
        return true;
    }

    /// @notice D13 view: can this holder currently spend/transfer this token?
    /// @dev Applies the D2 validity predicate verbatim:
    ///      - validFrom gate (shared)
    ///      - None → true
    ///      - PerTokenId → validUntil gate (shared)
    ///      - PerHolder → block.timestamp < holderExpiresAt[id][holder] (per-holder clock)
    ///      Reverts when the token has not been created (uri() precedent).
    /// @param holder The holder whose entitlement is queried.
    /// @param id Token id.
    /// @return True if the holder's balance of id is currently spendable.
    function isSpendable(address holder, uint256 id) external view returns (bool) {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        require(nft.nftCreated, "Token not created");

        if (nft.validFrom != 0 && block.timestamp < nft.validFrom) {
            return false;
        }
        if (nft.expirationMode == uint8(ExpirationMode.None)) {
            return true;
        }
        if (nft.expirationMode == uint8(ExpirationMode.PerTokenId)) {
            return nft.validUntil == 0 || block.timestamp < nft.validUntil;
        }
        // PerHolder (D2): per-holder clock in GNUSLifecycleStorage.
        return block.timestamp < GNUSLifecycleStorage.layout().holderExpiresAt[id][holder];
    }

    /// @notice D13 view: read the per-holder expiry clock for (id, holder).
    /// @dev Returns 0 when no clock has been set (never minted to this holder, or clock was
    ///      cleared by settlement). Reverts when the token has not been created (uri()
    ///      precedent) — never silently returns 0 for an uncreated id.
    /// @param id Token id.
    /// @param holder The holder whose clock is read.
    /// @return The holder's expiry timestamp (0 = no active clock).
    function holderExpiresAt(uint256 id, address holder) external view returns (uint64) {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        require(nft.nftCreated, "Token not created");
        return GNUSLifecycleStorage.layout().holderExpiresAt[id][holder];
    }

    /// @notice Write the full lifecycle configuration for a token class (D1/D4).
    /// @dev Authorization: creator-or-admin. Immutability (Q6): reverts once _totalSupply[id] > 0 —
    ///      policy/disposition/mode/recipient are immutable after first mint (D4).
    ///      Configuration validation gates (locked resolutions):
    ///        - Q2: PerHolder requires SOULBOUND or ISSUER_ONLY (no transferable per-holder clock).
    ///        - Q1: REDEEM_TO_PARENT requires !nft.nonConvertible (only collateralized/convertible
    ///              tokens may settle into the parent).
    ///        - RETURN_TO_ADDRESS requires a non-zero expirationRecipient (D8).
    ///      Writes all 8 fields atomically; emits LifecycleConfigured.
    /// @param id Token id (must be created, must have zero total supply).
    /// @param cfg The full LifecycleConfig payload.
    function configureLifecycle(uint256 id, LifecycleConfig calldata cfg) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        address sender = _msgSender();
        _requireCreatorOrAdmin(nft, sender);

        // Q6: policy-class fields are immutable after first mint (D4).
        require(
            ERC1155SupplyStorage.layout()._totalSupply[id] == 0,
            "Policy immutable after first mint"
        );

        // WR-01 (13 review): enum-ordinal range validation. Downstream consumers dispatch with
        // == equality and silently fall through on out-of-range ordinals (an invalid policy
        // behaves like UNRESTRICTED, an invalid mode like PerHolder). Reject at the entry point.
        require(cfg.expirationMode <= uint8(ExpirationMode.PerHolder), "Invalid expirationMode");
        require(cfg.transferPolicy <= uint8(TransferPolicy.LOCKED_AFTER_START), "Invalid transferPolicy");
        require(cfg.expirationDisposition <= uint8(ExpirationDisposition.REDEEM_TO_PARENT), "Invalid disposition");

        // Q2: PerHolder + transferable policy combination is forbidden (D2).
        if (cfg.expirationMode == uint8(ExpirationMode.PerHolder)) {
            require(
                cfg.transferPolicy == uint8(TransferPolicy.SOULBOUND) ||
                cfg.transferPolicy == uint8(TransferPolicy.ISSUER_ONLY),
                "PerHolder requires non-transferable policy"
            );
            // Codex P1 (PR #77): PerHolder + NONE/KEEP_INERT would let a renewal mint
            // re-activate the whole expired pile (settlement is balance-neutral for those
            // dispositions, then the fresh clock covers the old balance). Require a
            // balance-removing disposition so "expired balances are never resurrected" (D3)
            // holds for every PerHolder configuration.
            require(
                cfg.expirationDisposition != uint8(ExpirationDisposition.NONE) &&
                cfg.expirationDisposition != uint8(ExpirationDisposition.KEEP_INERT),
                "PerHolder requires balance-removing disposition"
            );
        }

        // Q1: REDEEM_TO_PARENT only on convertible (collateralized) tokens (D8).
        if (cfg.expirationDisposition == uint8(ExpirationDisposition.REDEEM_TO_PARENT)) {
            require(!nft.nonConvertible, "REDEEM_TO_PARENT requires convertible token");
        }

        // D8: RETURN_TO_ADDRESS requires a configured non-zero recipient.
        if (cfg.expirationDisposition == uint8(ExpirationDisposition.RETURN_TO_ADDRESS)) {
            require(cfg.expirationRecipient != address(0), "RETURN_TO_ADDRESS needs recipient");
        }

        nft.validFrom = cfg.validFrom;
        nft.validUntil = cfg.validUntil;
        nft.defaultDuration = cfg.defaultDuration;
        nft.expirationMode = cfg.expirationMode;
        nft.transferPolicy = cfg.transferPolicy;
        nft.expirationDisposition = cfg.expirationDisposition;
        nft.expirationRecipient = cfg.expirationRecipient;
        nft.credentialVerifier = cfg.credentialVerifier;

        emit LifecycleConfigured(id, cfg, sender);
    }

    /// @notice Mutate validFrom post-mint (D4 timestamp mutability).
    /// @dev Creator-or-admin only. Post-mint mutation is permitted because timestamps support
    ///      subscription renewal and event rescheduling — they do NOT change value flow
    ///      (disposition/recipient remain immutable). Emits ValidFromUpdated.
    /// @param id Token id.
    /// @param newValidFrom New validFrom timestamp.
    function setValidFrom(uint256 id, uint64 newValidFrom) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        address sender = _msgSender();
        _requireCreatorOrAdmin(nft, sender);

        uint64 old = nft.validFrom;
        nft.validFrom = newValidFrom;
        emit ValidFromUpdated(id, old, newValidFrom, sender);
    }

    /// @notice Mutate validUntil post-mint (D4 timestamp mutability).
    /// @dev Creator-or-admin only. D4 ordering constraint: after a BURN settlement has occurred
    ///      for a holder/token, timestamp mutation cannot un-burn it — settlement is a final
    ///      state transition; timestamps only affect the predicate going forward.
    /// @param id Token id.
    /// @param newValidUntil New validUntil timestamp.
    function setValidUntil(uint256 id, uint64 newValidUntil) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        address sender = _msgSender();
        _requireCreatorOrAdmin(nft, sender);

        uint64 old = nft.validUntil;
        nft.validUntil = newValidUntil;
        emit ValidUntilUpdated(id, old, newValidUntil, sender);
    }

    /// @notice Set the per-wallet mint cap for a token class (D10).
    /// @dev Creator-or-admin only. Storage lives in GNUSLifecycleStorage (not the NFT struct)
    ///      because cap state is per-token, not part of the lifecycle config payload.
    ///      The setter belongs on this facet so plan 13-03's beforeMint only needs to read.
    ///      Cap is documented as Sybil-vulnerable — not identity-proof (D10).
    /// @param id Token id.
    /// @param cap Maximum cumulative minions a single wallet may mint (0 = uncapped).
    function setPerWalletMintCap(uint256 id, uint256 cap) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        address sender = _msgSender();
        _requireCreatorOrAdmin(nft, sender);

        GNUSLifecycleStorage.layout().perWalletMintCap[id] = cap;
        emit PerWalletCapSet(id, cap, sender);
    }

    /// @notice Set the allowlist registry for a token class (D5 ALLOWLISTED policy).
    /// @dev Creator-or-admin only. Gated by _totalSupply[id] == 0 (Q6 policy-class field) —
    ///      swapping the registry after issuance would retroactively change who may hold the
    ///      token, a policy change that must be locked at first mint (D4).
    /// @param id Token id.
    /// @param registry IAllowlistRegistry plug-in address.
    function setAllowlistRegistry(uint256 id, address registry) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        address sender = _msgSender();
        _requireCreatorOrAdmin(nft, sender);

        require(
            ERC1155SupplyStorage.layout()._totalSupply[id] == 0,
            "Policy immutable after first mint"
        );

        GNUSLifecycleStorage.layout().allowlistRegistry[id] = registry;
    }

    /// @notice Internal expiry predicate (D2).
    /// @dev Returns true when the (account, id) pair is past its expiration point under the
    ///      token's expirationMode:
    ///        - None       → false (never expires)
    ///        - PerTokenId → validUntil != 0 && block.timestamp >= validUntil (shared window)
    ///        - PerHolder  → holderExpiresAt[id][account] != 0 && block.timestamp >= expiry
    ///      A PerHolder clock of 0 is treated as "not expired" — never minted to this holder,
    ///      or already settled.
    /// @param account The holder being checked.
    /// @param id Token id.
    /// @param nft The NFT storage record.
    /// @return True when the (account, id) pair is expired.
    function _isExpired(address account, uint256 id, NFT storage nft) internal view returns (bool) {
        if (nft.expirationMode == uint8(ExpirationMode.None)) {
            return false;
        }
        if (nft.expirationMode == uint8(ExpirationMode.PerTokenId)) {
            return nft.validUntil != 0 && block.timestamp >= nft.validUntil;
        }
        // PerHolder
        uint64 expiry = GNUSLifecycleStorage.layout().holderExpiresAt[id][account];
        return expiry != 0 && block.timestamp >= expiry;
    }

    /// @notice Atomically create a token AND configure its lifecycle (Phase 13 Q5).
    /// @dev Eliminates the UNRESTRICTED-default window between createNFT and configureLifecycle.
    ///      Authorization and ID derivation match createNFTs exactly (GNUS child →
    ///      DEFAULT_ADMIN_ROLE or CREATOR_ROLE; otherwise parent-creator only). Applies the same
    ///      validation gates as configureLifecycle (Q2 PerHolder-requires-non-transferable,
    ///      RETURN_TO_ADDRESS recipient check). REDEEM_TO_PARENT is always permitted here because
    ///      a freshly created token has nonConvertible=false unless the disposition is BURN.
    ///      D11: BURN disposition forces nonConvertible=true (burn-only tokens never redeem).
    ///      Emits LifecycleConfigured with the identical signature as GNUSLifecycle (topic-equal).
    /// @param parentID The parent token id (GNUS_TOKEN_ID for a direct child of GNUS).
    /// @param name Token name.
    /// @param symbol Token symbol.
    /// @param exchRate Display exchange rate (minions per child unit, 1e18 scale).
    /// @param max_supply Maximum supply (minions).
    /// @param newuri Metadata URI.
    /// @param cfg The full LifecycleConfig payload.
    /// @return newTokenID The id of the newly created token.
    function createNFTWithLifecycle(
        uint256 parentID,
        string memory name,
        string memory symbol,
        uint256 exchRate,
        uint256 max_supply,
        string memory newuri,
        LifecycleConfig memory cfg
    ) external returns (uint256 newTokenID) {
        GNUSNFTFactoryStorage.Layout storage fstore = GNUSNFTFactoryStorage.layout();
        address sender = _msgSender();
        if (parentID == GNUS_TOKEN_ID) {
            require(
                hasRole(DEFAULT_ADMIN_ROLE, sender) || hasRole(_CREATOR_ROLE, sender),
                "Only Creators or Admins can create NFT child of GNUS"
            );
        } else {
            require(fstore.NFTs[parentID].nftCreated, "Parent NFT Should have been created already");
            require(sender == fstore.NFTs[parentID].creator, "Only parent creator can create child NFTs");
        }

        // WR-01 (13 review): enum-ordinal range validation — same gates as configureLifecycle.
        require(cfg.expirationMode <= uint8(ExpirationMode.PerHolder), "Invalid expirationMode");
        require(cfg.transferPolicy <= uint8(TransferPolicy.LOCKED_AFTER_START), "Invalid transferPolicy");
        require(cfg.expirationDisposition <= uint8(ExpirationDisposition.REDEEM_TO_PARENT), "Invalid disposition");

        // Q2: PerHolder + transferable policy combination is forbidden (D2).
        if (cfg.expirationMode == uint8(ExpirationMode.PerHolder)) {
            require(
                cfg.transferPolicy == uint8(TransferPolicy.SOULBOUND) ||
                cfg.transferPolicy == uint8(TransferPolicy.ISSUER_ONLY),
                "PerHolder requires non-transferable policy"
            );
            // Codex P1 (PR #77): same balance-removing-disposition gate as
            // configureLifecycle — a renewal mint must never re-activate an expired pile.
            require(
                cfg.expirationDisposition != uint8(ExpirationDisposition.NONE) &&
                cfg.expirationDisposition != uint8(ExpirationDisposition.KEEP_INERT),
                "PerHolder requires balance-removing disposition"
            );
        }
        // D8: RETURN_TO_ADDRESS requires a configured non-zero recipient.
        if (cfg.expirationDisposition == uint8(ExpirationDisposition.RETURN_TO_ADDRESS)) {
            require(cfg.expirationRecipient != address(0), "RETURN_TO_ADDRESS needs recipient");
        }
        // D11: BURN disposition → burn-only (nonConvertible) at creation.
        bool burnOnly = cfg.expirationDisposition == uint8(ExpirationDisposition.BURN);

        uint256 childIndex = fstore.NFTs[parentID].childCurIndex;
        newTokenID = (parentID << 128) | childIndex;
        require(!fstore.NFTs[newTokenID].nftCreated, "Token ID collision"); // D7
        fstore.NFTs[parentID].childCurIndex = uint128(childIndex + 1);

        fstore.NFTs[newTokenID] = NFT({
            name: name,
            symbol: symbol,
            exchangeRate: exchRate,
            maxSupply: max_supply,
            uri: newuri,
            creator: sender,
            childCurIndex: 0,
            nftCreated: true,
            parentId: parentID,           // D7 - recorded, not derived
            nonConvertible: burnOnly,     // D5/D11 - BURN disposition → burn-only
            validFrom: cfg.validFrom,
            validUntil: cfg.validUntil,
            defaultDuration: cfg.defaultDuration,
            expirationMode: cfg.expirationMode,
            transferPolicy: cfg.transferPolicy,
            expirationDisposition: cfg.expirationDisposition,
            expirationRecipient: cfg.expirationRecipient,
            credentialVerifier: cfg.credentialVerifier,
            // Phase 14 licensing defaults (D-03/D-25) - zero-default preserves legacy behavior
            companyAdmin: address(0),      // unset; operator sets at license creation
            privateNetworkId: 0,           // no private network
            networkScope: 0,               // NetworkScope.PublicOnly
            publicSettlementEnabled: false // informational flag off
        });

        emit LifecycleConfigured(newTokenID, cfg, sender);
    }
}
