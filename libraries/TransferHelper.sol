// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

/// @title Transfer Helper Library
/// @author Genius DAO
/// @notice Helper methods for safe token transfers and approvals
/// @dev Provides safe methods for ERC20 token interactions and ETH transfers
library TransferHelper {
    /// @notice Safely approves ERC20 token spending
    /// @dev Calls approve on ERC20 token and requires successful execution
    /// @param token The address of the ERC20 token
    /// @param to Address to approve spending for
    /// @param value Amount of tokens to approve
    /// @custom:security Reverts if approval fails or returns false
    function safeApprove(address token, address to, uint value) internal {
        // bytes4(keccak256(bytes('approve(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'SA');
    }

    /// @notice Safely transfers ERC20 tokens
    /// @dev Calls transfer on ERC20 token and requires successful execution
    /// @param token The address of the ERC20 token
    /// @param to Address to transfer tokens to
    /// @param value Amount of tokens to transfer
    /// @custom:security Reverts if transfer fails or returns false
    function safeTransfer(address token, address to, uint value) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'ST');
    }

    /// @notice Safely transfers ERC20 tokens using transferFrom
    /// @dev Calls transferFrom on ERC20 token and requires successful execution
    /// @param token The address of the ERC20 token
    /// @param from Address to transfer tokens from
    /// @param to Address to transfer tokens to
    /// @param value Amount of tokens to transfer
    /// @custom:security Reverts if transfer fails or returns false
    function safeTransferFrom(address token, address from, address to, uint value) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'STF');
    }

    /// @notice Safely transfers ETH to an address
    /// @dev Transfers ETH and requires successful execution
    /// @param to Address to transfer ETH to
    /// @param value Amount of ETH to transfer
    /// @custom:security Reverts if ETH transfer fails
    function safeTransferETH(address to, uint value) internal {
        (bool success,) = to.call{value:value}(new bytes(0));
        require(success, 'STE');
    }
}
