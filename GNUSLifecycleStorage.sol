// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title GNUSLifecycleStorage
/// @notice Diamond storage library for the GNUS Lifecycle facet (Phase 13)
/// @dev Per-holder expiry clocks (D2), per-wallet mint caps (D10), allowlist registry (D5 ALLOWLISTED).
///      Pure library with no imports — mirrors GNUSTreasuryStorage / GNUSBridgeValidatorStorage precedent.
/// @custom:security-contact support@gnus.ai

library GNUSLifecycleStorage {
    /// @notice Storage layout for the Lifecycle facet.
    /// @dev Field order is load-bearing for append-only compatibility — Phase 14+ appends after these.
    struct Layout {
        // PerHolder expiry clocks (D2)
        mapping(uint256 => mapping(address => uint64)) holderExpiresAt;
        // Per-wallet mint cap state (D10)
        mapping(uint256 => mapping(address => uint256)) mintedPerWallet;
        mapping(uint256 => uint256) perWalletMintCap;
        // Allowlist registry hook (D5 ALLOWLISTED)
        mapping(uint256 => address) allowlistRegistry;
    }

    /// @notice Storage position for the GNUS Lifecycle storage.
    bytes32 constant GNUS_LIFECYCLE_STORAGE_POSITION = keccak256("gnus.ai.lifecycle.storage");

    /// @notice Retrieves the storage layout for the GNUS Lifecycle facet.
    /// @dev Uses inline assembly to access the storage slot (matches GNUSNFTFactoryStorage pattern).
    /// @return l The storage layout.
    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = GNUS_LIFECYCLE_STORAGE_POSITION;
        assembly {
            l.slot := slot
        }
    }
}
