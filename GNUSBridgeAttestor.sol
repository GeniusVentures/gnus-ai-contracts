// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSBridgeValidatorStorage.sol";
import "./GNUSControlStorage.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

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
}

/// @title GNUSBridgeAttestor
/// @notice V2 bridge-in attestor ADMIN facet: Genesis bootstrap, threshold override, emergency recovery (Phase 15).
/// @dev Plan 15-01 facet split (D-01): this facet owns the Phase 15 V2 attestor-admin surface
///      only — the one-time Genesis bootstrap `initializeBridgeAttestorV2`, the epoch-derived
///      threshold helper with its bounded superAdmin override `setBridgeAttestorActiveThreshold`,
///      the paused-gated `emergencyRecoverAttestorSet`, and the V2 view getters. The V2
///      certificate `bridgeIn` path lands on this facet in Plan 15-02. GNUSBridge owns
///      bridgeOut, policy gating, and the mint/burn paths. The two facets NEVER call each
///      other — state is shared only through diamond storage (GNUSBridgeValidatorStorage /
///      GNUSControlStorage).
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
