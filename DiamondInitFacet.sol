// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/utils/ContextUpgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/proxy/utils/Initializable.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC20/IERC20Upgradeable.sol";
import "./GeniusAccessControl.sol";
import "./GNUSWithdrawLimiterStorage.sol";

/// @title Diamond Initialization Facet
/// @author Genius DAO
/// @notice Handles initialization logic for the Diamond contract
/// @dev Implements role-based access control and diamond storage initialization
contract DiamondInitFacet is ContextUpgradeable, GeniusAccessControl {
    using LibDiamond for LibDiamond.DiamondStorage;

    /// @notice Role identifier for minting privileges
    /// @dev Keccak256 hash of "MINTER_ROLE"
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @notice Emitted when initialization functions are called
    /// @param sender Address that triggered the initialization
    /// @param initializer Name of the initialization function called
    event InitLog(address indexed sender, string initializer);

    /// @notice Checks if the contract supports a specific interface.
    /// @dev Overrides ERC-165 to include Diamond storage supported interfaces.
    /// @param interfaceId The interface identifier to check.
    /// @return True if the interface is supported, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return super.supportsInterface(interfaceId) ||
            (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true);
    }

    /// @notice Initializes the diamond with version 2.5.0
    /// @dev Sets up initial roles and permissions for the contract
    /// @custom:security Verify roles are properly set up
    function diamondInitialize250() public onlySuperAdminRole {
        address sender = _msgSender();
        emit InitLog(sender, "diamondInitialize Function called");

        // Set up roles and permissions
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(MINTER_ROLE, _msgSender());
        _grantRole(UPGRADER_ROLE, _msgSender());

        // Enable ERC20 interface support
        LibDiamond.diamondStorage().supportedInterfaces[type(IERC20Upgradeable).interfaceId] = true;

        // Initialize withdrawal limiter with defaults
        initializeGNUSWithdrawLimiter();
    }

    /// @notice Initializes the GNUS withdrawal limiter with default values
    /// @dev Sets default configuration for the rate limiter system
    function initializeGNUSWithdrawLimiter() internal {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        l.defaultLimitAmount = 100_000 * 10 ** 18; // 100,000 GNUS tokens
        l.defaultWindowSeconds = 86400; // 1 day (24 hours)
        l.defaultBinCount = 24; // hourly bins
        l.limiterEnabled = true;
    }
}
