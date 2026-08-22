// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/ERC1155Storage.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/extensions/ERC1155SupplyStorage.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSLifecycleStorage.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @notice Expiration mode for a token class (Phase 13 D2).
/// @dev Enum ordinals are stored on-chain in NFT.expirationMode (uint8). Ordinal 0 is the
///      backwards-compatible default for existing tokens. Append-only — never reorder.
enum ExpirationMode {
    None,        // 0 — no expiry
    PerTokenId,  // 1 — shared validUntil on the token ID (tickets, events, albums)
    PerHolder    // 2 — per-holder clock (SOULBOUND subscriptions, AI Credits)
}

/// @notice Transfer policy for a token class (Phase 13 D5).
/// @dev Enum ordinals are stored on-chain in NFT.transferPolicy (uint8). Ordinal 0 is the
///      backwards-compatible default (UNRESTRICTED). Append-only — never reorder.
enum TransferPolicy {
    UNRESTRICTED,        // 0 — default, current behavior
    SOULBOUND,           // 1 — no holder-to-holder transfers
    ISSUER_ONLY,         // 2 — only creator/approved operator can move
    ALLOWLISTED,         // 3 — destination/operator must satisfy registry check
    CONTROLLED_RESALE,   // 4 — ordinary transfers blocked; resale mechanism v2
    LOCKED_AFTER_START   // 5 — transferable before validFrom, locked after
}

/// @notice Expiration disposition for a token class (Phase 13 D8).
/// @dev Enum ordinals are stored on-chain in NFT.expirationDisposition (uint8). Ordinal 0 is the
///      backwards-compatible default (NONE — balance untouched). Append-only — never reorder.
enum ExpirationDisposition {
    NONE,              // 0 — balance untouched, entitlement off
    KEEP_INERT,        // 1 — balance stays (collectible), entitlement off
    BURN,              // 2 — expired units destroyed, no value returned
    RETURN_TO_ADDRESS, // 3 — expired units move to fixed expirationRecipient
    REDEEM_TO_PARENT   // 4 — settle into direct parent token (Q3 no-custody)
}

/// @notice Lifecycle configuration payload for configureLifecycle (Phase 13 D1).
/// @dev Field order matches NFT struct slots +8/+9/+10. Struct is calldata-only (not stored).
/// @param validFrom Sale/window start timestamp; 0 = active immediately.
/// @param validUntil Per-ID expiry timestamp (PerTokenId mode); 0 = no expiry.
/// @param defaultDuration Purchase duration in seconds (PerHolder mode); 0 = unset.
/// @param expirationMode ExpirationMode enum ordinal (0/1/2).
/// @param transferPolicy TransferPolicy enum ordinal (0-5).
/// @param expirationDisposition ExpirationDisposition enum ordinal (0-4).
/// @param expirationRecipient Destination for RETURN_TO_ADDRESS; 0x0 for other dispositions.
/// @param credentialVerifier ICredentialVerifier plug-in address; 0x0 = open minting.
struct LifecycleConfig {
    uint64  validFrom;
    uint64  validUntil;
    uint64  defaultDuration;
    uint8   expirationMode;
    uint8   transferPolicy;
    uint8   expirationDisposition;
    address expirationRecipient;
    address credentialVerifier;
}

/// @title GNUSLifecycle
/// @notice Time-bound ERC-1155 lifecycle facet (Phase 13, SC2/SC5/SC8, D2/D4/D8/D9/D13).
/// @dev Single owner of lifecycle state transitions. Reads NFT struct fields (validFrom,
///      validUntil, defaultDuration, expirationMode, transferPolicy, expirationDisposition,
///      expirationRecipient, credentialVerifier — slots +8/+9/+10) and the per-holder
///      expiry clocks in GNUSLifecycleStorage. All enforcement read paths (transfer policy
///      predicate, mint hooks in 13-03) read the config this facet writes.
///
///      Storage discipline: this facet holds NO state of its own. It reads/writes:
///        - GNUSNFTFactoryStorage.layout().NFTs[id]   (lifecycle config fields)
///        - GNUSLifecycleStorage.layout()             (per-holder clocks, caps, registry)
///        - ERC1155SupplyStorage.layout()._totalSupply (first-mint immutability gate)
///
///      Authorization: creator-or-admin per GNUSNFTFactory.sol:92 precedent.
///      Immutability (D4 / Q6): policy-class fields gate on _totalSupply[id] == 0 — once any
///      token of id has been minted, configureLifecycle and setAllowlistRegistry revert.
///      Timestamps (validFrom, validUntil) remain mutable post-mint to support subscription
///      renewal and event rescheduling (D4).
///
///      Security: settleExpired is permissionless but fixed-outcome (D9) — no recipient
///      parameter, no caller-controlled value flow, disposition read from immutable config.
///      CEI ordering: per-holder clock cleared BEFORE any burn/transfer in settlement.
/// @custom:security-contact support@gnus.ai
contract GNUSLifecycle is GNUSERC1155MaxSupply, GeniusAccessControl {
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

    /// @notice Emitted when a per-holder expiry clock is set or extended (D3).
    /// @param id Token id.
    /// @param holder The holder whose clock was updated.
    /// @param oldExpiry Previous expiry timestamp (0 if unset).
    /// @param newExpiry New expiry timestamp.
    event HolderExpiryUpdated(uint256 indexed id, address indexed holder, uint64 oldExpiry, uint64 newExpiry);

    /// @notice Emitted when a per-wallet mint cap is set (D10).
    /// @param id Token id.
    /// @param cap Maximum cumulative minions a single wallet may mint (0 = uncapped).
    /// @param operator The creator or admin who set the cap.
    event PerWalletCapSet(uint256 indexed id, uint256 cap, address indexed operator);

    /// @notice Emitted when settleExpired routes an expired balance to its disposition (D8/D9).
    /// @param account The holder whose expired balance was settled.
    /// @param id Token id.
    /// @param amount Minion amount moved (0 for NONE/KEEP_INERT).
    /// @param disposition The disposition that was applied.
    /// @param destination 0x0 for NONE/KEEP_INERT/BURN; recipient for RETURN_TO_ADDRESS;
    ///        account for REDEEM_TO_PARENT (parent minions minted back to the holder).
    event Settled(
        address indexed account,
        uint256 indexed id,
        uint256 amount,
        ExpirationDisposition disposition,
        address destination
    );

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

        // Q2: PerHolder + transferable policy combination is forbidden (D2).
        if (cfg.expirationMode == uint8(ExpirationMode.PerHolder)) {
            require(
                cfg.transferPolicy == uint8(TransferPolicy.SOULBOUND) ||
                cfg.transferPolicy == uint8(TransferPolicy.ISSUER_ONLY),
                "PerHolder requires non-transferable policy"
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
}
