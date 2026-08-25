// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./GNUSLicensingTypes.sol";
/// @title GNUSLicensingStorage
/// @notice Diamond storage library for the GNUS Licensing facets (Phase 14)
/// @dev SKU registry (D-04) shared by the GNUSLicensing (config) and GNUSLicensingPurchase
///      (purchase) facets. Mirrors GNUSLifecycleStorage / GNUSTreasuryStorage precedent; the
///      single import pulls the file-level SKU type (GNUSLifecycleStorage needed no imports only
///      because it referenced no file-level types).
/// @custom:security-contact support@gnus.ai

library GNUSLicensingStorage {
    /// @notice Storage layout for the Licensing facets.
    /// @dev Field order is load-bearing for append-only compatibility — Phase 15+ appends after these.
    struct Layout {
        // D-04 SKU registry
        mapping(uint256 => SKU) skus;
        // license token id → SKU id (renewal SKUs look up their governing license)
        mapping(uint256 => uint256) licenseSku;
    }

    /// @notice Storage position for the GNUS Licensing storage.
    bytes32 constant GNUS_LICENSING_STORAGE_POSITION = keccak256("gnus.ai.licensing.storage");

    /// @notice Retrieves the storage layout for the GNUS Licensing facets.
    /// @dev Uses inline assembly to access the storage slot (matches GNUSNFTFactoryStorage pattern).
    /// @return l The storage layout.
    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = GNUS_LICENSING_STORAGE_POSITION;
        assembly {
            l.slot := slot
        }
    }
}
