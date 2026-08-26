// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title GNUSBridgeValidatorStorage
/// @notice Diamond storage library for Phase 10 bridge-in (validator set commitment + replay protection)
/// @dev Append-only; Phase 15 appended the V2 rolling-attestor fields (BRIDGE-10, D-11) after the legacy fields.
/// @custom:security-contact support@gnus.ai

library GNUSBridgeValidatorStorage {
    /// @notice Storage layout for the bridge validator subsystem.
    /// @dev Append-only; Phase 15 appended the V2 rolling-attestor fields (BRIDGE-10, D-11) below.
    struct Layout {
        /// @dev Replay protection per CONTEXT D-07; set exactly once per transferId on successful bridgeIn.
        mapping(bytes32 => bool) processedMessages;
        /// @dev Merkle root of the authorized validator set per CONTEXT D-15; each leaf is keccak256(abi.encodePacked(validatorAddress)).
        bytes32 validatorMerkleRoot;
        /// @dev m in "m-of-n" per CONTEXT D-12; minimum number of distinct validator signatures required.
        uint256 validatorThreshold;
        // Phase 15 appends below - do not reorder, do not insert above this line
        // Slot annotations verified by storage probe in GNUSBridgeAttestorUpgrade.test.ts (BRIDGE-10):
        /// @dev V2 rolling attestor merkle root (slot +3, full slot per D-11); one-leaf Genesis root
        ///      keccak256(abi.encodePacked(genesisAttestor)) at bootstrap; bytes32(0) = not bootstrapped.
        bytes32 bridgeAttestorRoot;
        /// @dev V2 attestor epoch (slot +4, full slot per D-11 — deliberately NOT packed with the bool);
        ///      0 = Genesis epoch; incremented by exactly one on every root transition and emergency recovery.
        uint256 bridgeAttestorEpoch;
        /// @dev V2 one-shot bootstrap flag (slot +5) per CONTEXT D-04; written once by
        ///      initializeBridgeAttestorV2 and never reset — not even by emergencyRecoverAttestorSet.
        bool bridgeAttestorV2Initialized;
        /// @dev PD-BR-2 revised active attestor-threshold override (slot +6); init writes
        ///      ACTIVE_ATTESTOR_THRESHOLD (2); superAdmin setter bounds 2..16. 0 = unset/corrupted —
        ///      the epoch-derived threshold helper zero-guards to the default (defense-in-depth).
        uint256 activeAttestorThreshold;
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
