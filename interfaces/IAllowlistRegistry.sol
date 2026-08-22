// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title IAllowlistRegistry
/// @notice Allowlist registry plug-in for ALLOWLISTED transfer policy.
/// @dev Per-token registry address lives in GNUSLifecycleStorage.allowlistRegistry[id].
///      Implementations decide the allowlist semantics (merkle, mapping, etc.).
interface IAllowlistRegistry {
    /// @notice Check whether an address is allowed as a destination.
    /// @param account The candidate destination.
    /// @return True if allowed.
    function isAllowed(address account) external view returns (bool);
}
