// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Network scope for a token class (Phase 14 D-03).
/// @dev Enum ordinals are stored on-chain in the appended NFT fields (uint8). Ordinal 0 is the
///      backwards-compatible zero default for existing tokens (PublicOnly). Append-only — never reorder.
enum NetworkScope {
    PublicOnly,   // 0 — zero default; public-network execution only
    PrivateOnly,  // 1 — SuperGenius private-network execution only
    Hybrid        // 2 — both public and private execution
}

/// @notice SKU / product registry entry (Phase 14 D-04).
/// @dev Prices are fixed and minion-denominated — NO USD oracle, no USD-denominated field (D-04).
///      Credit SKUs that drive PerHolder-expiry credits must comply with D-17: the token's
///      expiration disposition must be balance-removing (BURN / RETURN_TO_ADDRESS / REDEEM_TO_PARENT,
///      never NONE / KEEP_INERT). License SKUs target PerTokenId validUntil licenses (D-12).
/// @param priceInMinions Purchase price in minions of GNUS; must be > 0.
/// @param creditAmount Units of credit minted per purchase (0 for license-only SKUs).
/// @param duration Entitlement duration in seconds; must be > 0.
/// @param createsLicense True when this SKU creates a new License NFT (mutually exclusive with renewsLicense).
/// @param renewsLicense True when this SKU renews an existing license (mutually exclusive with createsLicense).
/// @param active True when the SKU is purchasable; inactive SKUs remain stored and queryable.
struct SKU {
    uint256 priceInMinions;
    uint256 creditAmount;
    uint64  duration;
    bool    createsLicense;
    bool    renewsLicense;
    bool    active;
}

/// @title IGNUSLicensingEvents
/// @notice Cross-system event surface for the GNUS Licensing facets (Phase 14).
/// @dev Solidity 0.8.19 does not support file-level events (added in 0.8.22), so the event is
///      declared in this interface; facets inherit it to emit. ABI signature is identical to a
///      file-level declaration.
interface IGNUSLicensingEvents {
    /// @notice Emitted when a license is created or renewed (Phase 14 D-14 / LIC-05).
    /// @dev Field order is the SuperGenius cross-system contract (A3) — do NOT reorder. Emitted on
    ///      creation AND on every renewal; SuperGenius consumers derive license state from events alone.
    /// @param companyAdmin Company administrator address recorded at license creation.
    /// @param licenseId License token id.
    /// @param privateNetworkId SuperGenius private network id.
    /// @param expiresAt License expiry timestamp (PerTokenId validUntil).
    event LicenseActivated(address indexed companyAdmin, uint256 indexed licenseId, uint256 privateNetworkId, uint64 expiresAt);
}
