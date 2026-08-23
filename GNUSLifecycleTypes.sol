// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

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

/// @notice Lifecycle configuration payload for configureLifecycle / createNFTWithLifecycle (Phase 13 D1).
/// @dev Field order matches NFT struct slots +8/+9/+10. Struct is calldata-only (not stored).
///      Declared in this types-only file (not GNUSLifecycle.sol) so the shared base
///      GNUSERC1155MaxSupply, the GNUSLifecycle facet, and GNUSNFTFactory can all import the
///      canonical definition without a circular import.
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
