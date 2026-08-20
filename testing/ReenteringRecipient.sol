// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IRedeemAdapter {
    function redeem(address from, uint256 childId, uint256 amount, address recipient) external;
}

interface IERC1155 {
    function balanceOf(address account, uint256 id) external view returns (uint256);
}

/**
 * @notice Malicious recipient for GNUSRedeemAdapter CEI/reentrancy tests (Phase 11, IN-03).
 * @dev Its onERC1155Received hook (fired on the mint leg, AFTER the limiter charge, pull,
 *      and burn are finalized) reenters redeem. Under correct CEI ordering the reentrant
 *      call must fail on the operator-approval gate (msg.sender == this contract, which is
 *      neither `from` nor approved) — no state corruption is possible.
 */
contract ReenteringRecipient {
    IRedeemAdapter public immutable diamond;
    uint256 public reentryAttempts;
    bool public inHook;

    // Parameters for the reentrant redeem attempt; zeroed when no attempt is armed.
    address public attackFrom;
    uint256 public attackChildId;
    uint256 public attackAmount;

    constructor(address _diamond) {
        diamond = IRedeemAdapter(_diamond);
    }

    /// @notice Arm (or disarm with amount == 0) a reentrant redeem inside the hook.
    function armReentry(address from, uint256 childId, uint256 amount) external {
        attackFrom = from;
        attackChildId = childId;
        attackAmount = amount;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4) {
        if (!inHook && attackAmount > 0) {
            inHook = true;
            reentryAttempts += 1;
            // solhint-disable-next-line avoid-low-level-calls
            (bool ok, bytes memory ret) = address(diamond).call(
                abi.encodeCall(IRedeemAdapter.redeem, (attackFrom, attackChildId, attackAmount, address(this)))
            );
            // Record the outcome; the outer redeem must succeed regardless.
            ok; ret; // intentionally discarded — assertion happens off-chain via reentryAttempts/state
            inHook = false;
        }
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        returns (bytes4)
    {
        revert("ReenteringRecipient: batch not accepted");
    }

    function childBalance(uint256 childId) external view returns (uint256) {
        return IERC1155(address(diamond)).balanceOf(address(this), childId);
    }
}
