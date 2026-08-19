// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @notice Minimal mock of an external ERC-20 proxy contract for testing GNUSRedeemAdapter.
 * @dev Intentionally NOT the real erc20-gnus-proxy contract — this proves the adapter is
 *      generic (D-05): any contract that knows the user address can drive a redemption.
 */
interface IGNUSRedeemAdapter {
    function redeem(address from, uint256 childId, uint256 amount, address recipient) external;
}

contract MockERC20Proxy {
    IGNUSRedeemAdapter public immutable diamond;

    constructor(address _diamond) {
        diamond = IGNUSRedeemAdapter(_diamond);
    }

    /**
     * @notice Forwards a redemption to the diamond's redeem adapter on behalf of `from`.
     * @dev In the real deployment, the proxy would call this after its own ERC-20 allowance
     *      bookkeeping (PROXY-01 work, erc20-gnus-proxy workstream); here we test only the
     *      diamond-side contract-caller path. The adapter's own approval check (from must
     *      have approved the diamond as ERC-1155 operator) is the security boundary.
     */
    function redeemOnBehalf(address from, uint256 childId, uint256 amount, address recipient) external {
        diamond.redeem(from, childId, amount, recipient);
    }
}
