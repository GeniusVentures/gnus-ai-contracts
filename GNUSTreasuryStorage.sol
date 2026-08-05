// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title GNUSTreasuryStorage
/// @notice Diamond storage library for the GNUS Treasury facet (Phase 9 - conversion-native model)
/// @dev Holds the B1 provenance counter and initialization guard. See 09-CONTEXT.md D8 for semantics.
/// @custom:security-contact support@gnus.ai

library GNUSTreasuryStorage {
    /// @notice Storage layout for the Treasury provenance counter.
    /// @dev Field order per D8: globalSupply first (the counter), provenanceInitialized second (the guard).
    ///      Do NOT reorder - Phase 13 will append after these fields.
    struct Layout {
        uint256 globalSupply;          ///< B1 provenance counter (minions) - cumulative minted supply across all chains
        bool provenanceInitialized;    ///< One-time initializer guard (D8: revert when uninitialized)
    }

    /// @notice Storage position for the GNUS Treasury storage.
    bytes32 constant GNUS_TREASURY_STORAGE_POSITION = keccak256("gnus.ai.treasury.storage");

    /// @notice Retrieves the storage layout for the GNUS Treasury.
    /// @dev Uses inline assembly to access the storage slot (matches GNUSNFTFactoryStorage pattern).
    /// @return l The storage layout.
    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = GNUS_TREASURY_STORAGE_POSITION;
        assembly {
            l.slot := slot
        }
    }
}
