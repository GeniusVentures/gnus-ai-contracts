// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./GeniusAccessControl.sol";
import "./GNUSWithdrawLimiterStorage.sol";

/**
 * @title GNUSWithdrawLimiter
 * @notice Facet providing administrative functions for the GNUS withdrawal rate limiter system.
 * @dev Implements per-account configurable withdrawal limits with bin-based aggregation.
 *
 * This facet provides administrative controls for:
 * - Setting default global limits (limit amount, window duration, bin count)
 * - Configuring per-account custom limits
 * - Enabling/disabling the limiter globally
 * - Querying account withdrawal status
 *
 * All administrative functions require the super admin role.
 * Super admins bypass withdrawal limits when performing transfers.
 *
 * ## Security Considerations
 * - Only super admin can modify configurations
 * - Bin count must be > 0 to prevent division by zero
 * - Changes to defaults affect accounts using default configs
 * - Per-account configs override defaults
 *
 * ## Gas Optimization
 * - View functions use cached storage reads
 * - Config queries return effective values (custom or defaults)
 * - Status calculation uses bin aggregation (O(binCount) not O(n))
 */
contract GNUSWithdrawLimiter is GeniusAccessControl {
    // Events

    /**
     * @notice Emitted when default limiter configuration is updated.
     * @param defaultLimitAmount New default withdrawal limit amount.
     * @param defaultWindowSeconds New default time window in seconds.
     * @param defaultBinCount New default number of bins.
     */
    event WithdrawLimiterConfigUpdated(
        uint256 defaultLimitAmount,
        uint256 defaultWindowSeconds,
        uint256 defaultBinCount
    );

    /**
     * @notice Emitted when a per-account configuration is updated.
     * @param account The account whose configuration was updated.
     * @param binCount Number of bins for the account.
     * @param windowSeconds Time window in seconds for the account.
     * @param limitAmount Withdrawal limit amount for the account.
     */
    event AccountConfigUpdated(
        address indexed account,
        uint32 binCount,
        uint64 windowSeconds,
        uint256 limitAmount
    );

    // Administrative Functions

    /**
     * @notice Sets the default withdrawal limit amount.
     * @dev Only super admin can call. Affects all accounts using default config.
     * @param limitAmount The new default limit amount in GNUS token units (wei).
     */
    function setDefaultLimitAmount(uint256 limitAmount) external onlySuperAdminRole {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        l.defaultLimitAmount = limitAmount;
        emit WithdrawLimiterConfigUpdated(
            l.defaultLimitAmount,
            l.defaultWindowSeconds,
            l.defaultBinCount
        );
    }

    /**
     * @notice Sets the default time window duration.
     * @dev Only super admin can call. Affects all accounts using default config.
     * @param windowSeconds The new default window duration in seconds.
     */
    function setDefaultWindowSeconds(uint256 windowSeconds) external onlySuperAdminRole {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        l.defaultWindowSeconds = windowSeconds;
        emit WithdrawLimiterConfigUpdated(
            l.defaultLimitAmount,
            l.defaultWindowSeconds,
            l.defaultBinCount
        );
    }

    /**
     * @notice Sets the default number of bins for aggregation.
     * @dev Only super admin can call. Must be > 0 to prevent division by zero.
     * Affects all accounts using default config.
     * @param binCount The new default number of bins (must be > 0).
     */
    function setDefaultBinCount(uint256 binCount) external onlySuperAdminRole {
        require(binCount > 0, "Bin count must be greater than 0");
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        l.defaultBinCount = binCount;
        emit WithdrawLimiterConfigUpdated(
            l.defaultLimitAmount,
            l.defaultWindowSeconds,
            l.defaultBinCount
        );
    }

    /**
     * @notice Sets a per-account custom configuration.
     * @dev Only super admin can call. Custom config overrides defaults for the account.
     * Set all values to 0 to revert to default configuration.
     * @param account The account to configure.
     * @param binCount Number of bins (0 = use default).
     * @param windowSeconds Time window in seconds (0 = use default).
     * @param limitAmount Withdrawal limit amount (0 = use default).
     */
    function setAccountConfig(
        address account,
        uint32 binCount,
        uint64 windowSeconds,
        uint256 limitAmount
    ) external onlySuperAdminRole {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        l.accountConfigs[account] = AccountConfig({
            binCount: binCount,
            windowSeconds: windowSeconds,
            limitAmount: limitAmount
        });
        emit AccountConfigUpdated(account, binCount, windowSeconds, limitAmount);
    }

    /**
     * @notice Enables or disables the withdrawal limiter globally.
     * @dev Only super admin can call. When disabled, all withdrawal checks are bypassed.
     * Super admins always bypass the limiter regardless of this setting.
     * @param enabled True to enable limiter, false to disable.
     */
    function setLimiterEnabled(bool enabled) external onlySuperAdminRole {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        l.limiterEnabled = enabled;
        emit WithdrawLimiterConfigUpdated(
            l.defaultLimitAmount,
            l.defaultWindowSeconds,
            l.defaultBinCount
        );
    }

    // Query Functions

    /**
     * @notice Returns the default limiter configuration.
     * @dev Returns global defaults applied to accounts without custom configs.
     * @return defaultLimitAmount Default withdrawal limit amount.
     * @return defaultWindowSeconds Default time window in seconds.
     * @return defaultBinCount Default number of bins.
     * @return limiterEnabled Whether the limiter is globally enabled.
     */
    function getWithdrawLimiterConfig()
        external
        view
        returns (
            uint256 defaultLimitAmount,
            uint256 defaultWindowSeconds,
            uint256 defaultBinCount,
            bool limiterEnabled
        )
    {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        return (l.defaultLimitAmount, l.defaultWindowSeconds, l.defaultBinCount, l.limiterEnabled);
    }

    /**
     * @notice Returns the effective configuration for an account.
     * @dev Returns custom config if set, otherwise returns defaults.
     * This is the actual config used for withdrawal validation.
     * @param account The account to query.
     * @return binCount Effective bin count for the account.
     * @return windowSeconds Effective time window for the account.
     * @return limitAmount Effective withdrawal limit for the account.
     */
    function getAccountConfig(
        address account
    ) external view returns (uint32 binCount, uint64 windowSeconds, uint256 limitAmount) {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        AccountConfig storage custom = l.accountConfigs[account];

        // Use custom values if non-zero, otherwise use defaults
        binCount = custom.binCount == 0 ? uint32(l.defaultBinCount) : custom.binCount;
        windowSeconds = custom.windowSeconds == 0
            ? uint64(l.defaultWindowSeconds)
            : custom.windowSeconds;
        limitAmount = custom.limitAmount == 0 ? l.defaultLimitAmount : custom.limitAmount;
    }

    /**
     * @notice Returns the current withdrawal status for an account.
     * @dev Calculates active withdrawal total and remaining capacity.
     * @param account The account to query.
     * @return currentUsage Total amount withdrawn in the current time window.
     * @return remainingCapacity Amount that can still be withdrawn without exceeding limit.
     * @return windowEnd Timestamp when the current window expires (approximate).
     */
    function getAccountWithdrawStatus(
        address account
    ) external view returns (uint256 currentUsage, uint256 remainingCapacity, uint256 windowEnd) {
        GNUSWithdrawLimiterStorage.Layout storage l = GNUSWithdrawLimiterStorage.layout();
        AccountConfig memory config = GNUSWithdrawLimiterStorage.getAccountConfigOrDefaults(
            account
        );

        uint256 currentTime = block.timestamp;
        currentUsage = GNUSWithdrawLimiterStorage.sumActiveBins(account, currentTime, config);

        if (currentUsage >= config.limitAmount) {
            remainingCapacity = 0;
        } else {
            remainingCapacity = config.limitAmount - currentUsage;
        }

        // Calculate approximate window end (baseTimestamp + windowSeconds)
        // This is approximate because bins roll over
        AccountState storage state = l.accountStates[account];
        if (state.baseTimestamp == 0) {
            windowEnd = currentTime + config.windowSeconds;
        } else {
            windowEnd = state.baseTimestamp + config.windowSeconds;
        }
    }

    /**
     * @notice Checks if the contract supports a given interface.
     * @dev Implements ERC-165 interface detection.
     * @param interfaceId The interface identifier to check.
     * @return True if the interface is supported, false otherwise.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
