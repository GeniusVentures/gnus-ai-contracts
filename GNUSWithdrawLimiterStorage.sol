// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "./GeniusAccessControl.sol";

/// @title GNUSWithdrawLimiterStorage
/// @notice Diamond storage library for limiter configuration and bin-based withdrawal tracking
/// @dev Uses bin-based aggregation with fixed-size arrays for O(binCount) complexity and predictable gas costs
/// @custom:security-contact support@gnus.ai

/// @notice Struct representing a time bin for withdrawal aggregation
/// @dev Stores bin timestamp and accumulated withdrawal amount
struct WithdrawBin {
    uint128 timestamp; ///< Timestamp when this bin was last updated
    uint128 totalAmount; ///< Total GNUS amount accumulated in this bin
}

/// @notice Struct representing per-account configuration
/// @dev Zero values indicate use of default configuration
struct AccountConfig {
    uint32 binCount; ///< Number of bins for this account (0 = use default)
    uint64 windowSeconds; ///< Window duration in seconds (0 = use default)
    uint256 limitAmount; ///< Withdrawal limit for this account (0 = use default)
}

/// @notice Struct representing per-account state
/// @dev Contains base timestamp and dynamic bin array
struct AccountState {
    uint128 baseTimestamp; ///< First withdrawal timestamp (establishes bin timeline)
    WithdrawBin[] bins; ///< Array of withdrawal bins (size = binCount)
}

/// @custom:security-contact support@gnus.ai
library GNUSWithdrawLimiterStorage {
    /// @notice Struct representing the storage layout for the Withdraw Limiter
    /// @dev Uses diamond storage pattern to avoid collisions
    struct Layout {
        mapping(address => AccountState) accountStates; ///< Per-account bin state
        mapping(address => AccountConfig) accountConfigs; ///< Per-account custom configs
        uint256 defaultBinCount; ///< Default number of bins
        uint256 defaultWindowSeconds; ///< Default window duration
        uint256 defaultLimitAmount; ///< Default withdrawal limit
        bool limiterEnabled; ///< Global enable/disable flag
    }

    /// @notice Storage position for the Withdraw Limiter storage
    bytes32 constant GNUS_WITHDRAW_LIMITER_STORAGE_POSITION =
        keccak256("gnus.ai.withdraw.limiter.storage");

    /// @notice Event emitted when a withdrawal is recorded
    /// @param account The account making the withdrawal
    /// @param amount The amount of GNUS tokens withdrawn
    /// @param timestamp The timestamp of the withdrawal
    /// @param binIndex The bin index where the withdrawal was recorded
    event WithdrawRecorded(
        address indexed account,
        uint256 amount,
        uint256 timestamp,
        uint256 binIndex
    );

    /// @notice Event emitted when a withdrawal is blocked by the limiter
    /// @param account The account attempting withdrawal
    /// @param requestedAmount The amount requested
    /// @param activeTotal The current total in active bins
    /// @param limit The configured limit
    event WithdrawLimiterTriggered(
        address indexed account,
        uint256 requestedAmount,
        uint256 activeTotal,
        uint256 limit
    );

    /// @notice Retrieves the storage layout for the Withdraw Limiter
    /// @dev Uses inline assembly to access the storage slot
    /// @return l The storage layout
    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = GNUS_WITHDRAW_LIMITER_STORAGE_POSITION;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Gets effective configuration for an account (custom or defaults)
    /// @dev Zero values in account config trigger use of defaults
    /// @param account The account address
    /// @return config The effective AccountConfig
    function getAccountConfigOrDefaults(
        address account
    ) internal view returns (AccountConfig memory config) {
        Layout storage l = layout();
        AccountConfig storage custom = l.accountConfigs[account];

        // Use custom values if non-zero, otherwise use defaults
        config.binCount = custom.binCount == 0 ? uint32(l.defaultBinCount) : custom.binCount;
        config.windowSeconds = custom.windowSeconds == 0
            ? uint64(l.defaultWindowSeconds)
            : custom.windowSeconds;
        config.limitAmount = custom.limitAmount == 0 ? l.defaultLimitAmount : custom.limitAmount;
    }

    /// @notice Calculates the current bin index for an account
    /// @dev Uses formula: ((currentTime - baseTimestamp) / binLengthSeconds) % binCount
    /// @param account The account address
    /// @param currentTime The current timestamp
    /// @param config The account's configuration
    /// @return binIndex The calculated bin index
    function calculateCurrentBin(
        address account,
        uint256 currentTime,
        AccountConfig memory config
    ) internal view returns (uint256 binIndex) {
        Layout storage l = layout();
        AccountState storage state = l.accountStates[account];

        // If no base timestamp, return 0 (will be set on first withdrawal)
        if (state.baseTimestamp == 0) {
            return 0;
        }

        // Calculate bin length: windowSeconds / binCount
        uint256 binLengthSeconds = config.windowSeconds / config.binCount;

        // Calculate elapsed time since base
        uint256 elapsedSeconds = currentTime - state.baseTimestamp;

        // Calculate bin index with modulo wrap-around
        binIndex = (elapsedSeconds / binLengthSeconds) % config.binCount;
    }

    /// @notice Zeros expired bins for an account (lazy cleanup)
    /// @dev Bins are expired if bin.timestamp < (currentTime - windowSeconds)
    /// @param account The account address
    /// @param currentTime The current timestamp
    /// @param config The account's configuration
    function zeroExpiredBins(
        address account,
        uint256 currentTime,
        AccountConfig memory config
    ) internal {
        Layout storage l = layout();
        AccountState storage state = l.accountStates[account];

        uint256 windowCutoff = currentTime - config.windowSeconds;

        // Iterate through bins and zero expired ones
        for (uint256 i = 0; i < state.bins.length; i++) {
            if (state.bins[i].timestamp < windowCutoff && state.bins[i].timestamp != 0) {
                state.bins[i].totalAmount = 0;
                state.bins[i].timestamp = 0;
            }
        }
    }

    /// @notice Sums all active bins within the window
    /// @dev Active bins have timestamp >= (currentTime - windowSeconds)
    /// @param account The account address
    /// @param currentTime The current timestamp
    /// @param config The account's configuration
    /// @return total The sum of all active bin amounts
    function sumActiveBins(
        address account,
        uint256 currentTime,
        AccountConfig memory config
    ) internal view returns (uint256 total) {
        Layout storage l = layout();
        AccountState storage state = l.accountStates[account];

        uint256 windowCutoff = currentTime - config.windowSeconds;

        // Sum bins that are still within the active window
        for (uint256 i = 0; i < state.bins.length; i++) {
            if (state.bins[i].timestamp >= windowCutoff && state.bins[i].timestamp != 0) {
                total += state.bins[i].totalAmount;
            }
        }
    }

    /// @notice Core validation and recording logic for withdrawals
    /// @dev Implements full limiter logic: check enabled, validate limit, update bins
    /// @param account The account making the withdrawal
    /// @param amount The amount of GNUS tokens to withdraw
    function checkAndRecordWithdraw(address account, uint256 amount) internal {
        Layout storage l = layout();

        // If limiter is disabled, allow withdrawal without checks
        if (!l.limiterEnabled) {
            return;
        }

        AccountConfig memory config = getAccountConfigOrDefaults(account);
        AccountState storage state = l.accountStates[account];
        uint256 currentTime = block.timestamp;

        // Initialize base timestamp on first withdrawal
        if (state.baseTimestamp == 0) {
            state.baseTimestamp = uint128(currentTime);
            // Initialize bins array with binCount elements
            for (uint256 i = 0; i < config.binCount; i++) {
                state.bins.push(WithdrawBin({timestamp: 0, totalAmount: 0}));
            }
        }

        // Zero expired bins (lazy cleanup)
        zeroExpiredBins(account, currentTime, config);

        // Sum active bins
        uint256 activeTotal = sumActiveBins(account, currentTime, config);

        // Check if withdrawal would exceed limit
        if (activeTotal + amount > config.limitAmount) {
            emit WithdrawLimiterTriggered(account, amount, activeTotal, config.limitAmount);
            revert("Withdrawal limit exceeded for time window");
        }

        // Calculate current bin and add withdrawal amount
        uint256 binIndex = calculateCurrentBin(account, currentTime, config);
        state.bins[binIndex].timestamp = uint128(currentTime);
        state.bins[binIndex].totalAmount += uint128(amount);

        emit WithdrawRecorded(account, amount, currentTime, binIndex);
    }
}
