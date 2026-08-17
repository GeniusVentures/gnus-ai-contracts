// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title GNUSBridgeValidatorStorage
/// @notice Diamond storage library for Phase 10 bridge-in (validator set commitment + replay protection)
/// @dev Append-only; Phase 12 may add in-flight accounting after these fields.
/// @custom:security-contact support@gnus.ai

library GNUSBridgeValidatorStorage {
    /// @notice Storage layout for the bridge validator subsystem.
    /// @dev Append-only; Phase 12 may add in-flight accounting after these fields.
    struct Layout {
        /// @dev Replay protection per CONTEXT D-07; set exactly once per transferId on successful bridgeIn.
        mapping(bytes32 => bool) processedMessages;
        /// @dev Merkle root of the authorized validator set per CONTEXT D-15; each leaf is keccak256(abi.encodePacked(validatorAddress)).
        bytes32 validatorMerkleRoot;
        /// @dev m in "m-of-n" per CONTEXT D-12; minimum number of distinct validator signatures required.
        uint256 validatorThreshold;
    }

    /// @notice Storage position for the GNUS Bridge Validator storage.
    bytes32 constant GNUS_BRIDGE_VALIDATOR_STORAGE_POSITION = keccak256("gnus.ai.bridge.validator.storage");

    /// @notice Retrieves the storage layout for the GNUS Bridge Validator.
    /// @dev Uses inline assembly to access the storage slot (matches GNUSTreasuryStorage pattern).
    /// @return l The storage layout.
    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = GNUS_BRIDGE_VALIDATOR_STORAGE_POSITION;
        assembly {
            l.slot := slot
        }
    }
}
