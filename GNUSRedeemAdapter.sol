// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/proxy/utils/Initializable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/IERC1155ReceiverUpgradeable.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSWithdrawLimiterStorage.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title GNUSRedeemAdapter
/// @notice Generic adapter for external ERC-20 proxies to redeem proxied-child tokens for GNUS (Phase 11, PROXY-03).
/// @dev Pull-then-burn/mint model (D-08 option (a)): the caller (typically an external ERC-20 proxy
///      contract or an EOA) passes the end user as `from`; the adapter pulls the child ERC-1155 from
///      `from` into the diamond via `_safeTransferFrom` (the user pre-approves the diamond as operator,
///      one-time `setApprovalForAll`), then burns the child tokens and mints GNUS to `recipient`.
///      Pull + burn + mint are atomic within one transaction — the diamond never holds child tokens
///      across transactions (Phase 10 no-custody model). The WR-07 limiter charge is keyed to `from`
///      (the user), NOT to the diamond and NOT to the proxy, preserving per-caller limiter semantics.
///      The burn/mint pair is deliberately inlined rather than routed through an external self-call
///      to the treasury's convert function — such a call would re-key `_msgSender()` to the diamond
///      and charge the limiter against it (per-diamond DoS). Accepted risk (T-11-06): direct user transfers of child tokens TO the
///      diamond outside redeem are stranded (same as any ERC-1155 contract without a sweep function).
/// @custom:security-contact support@gnus.ai
contract GNUSRedeemAdapter is Initializable, GNUSERC1155MaxSupply, GeniusAccessControl, IERC1155ReceiverUpgradeable {
    /// @notice Emitted when an adapter-mediated redemption completes.
    /// @param caller The proxy or EOA that invoked redeem (`_msgSender()`).
    /// @param from The token holder whose child balance was debited.
    /// @param childId Child token id burned.
    /// @param amount Minion amount converted (1:1 to GNUS, Phase 9 D2).
    /// @param recipient Recipient of the minted GNUS.
    event RedeemedViaAdapter(address indexed caller, address indexed from, uint256 indexed childId, uint256 amount, address recipient);

    /// @inheritdoc ERC1155Upgradeable
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable, IERC165Upgradeable)
        returns (bool)
    {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) ||
            AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
            (interfaceId == type(IERC1155ReceiverUpgradeable).interfaceId) ||
            (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /// @notice Accepts ERC-1155 transfers into the diamond ONLY while a redeem is in progress.
    /// @dev Gated on a transient "redeem in progress" flag (dedicated diamond-storage slot,
    ///      WR-01): the flag is set immediately before redeem's `_safeTransferFrom` and cleared
    ///      immediately after (a revert mid-reem auto-clears via refund, and the explicit clear
    ///      covers success). Direct user transfers into the diamond still revert at the hook,
    ///      preserving the pre-facet revert-on-direct-transfer posture (Phase 10 no-custody
    ///      model). Reads storage, so `view` rather than `pure`.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external view override returns (bytes4) {
        require(msg.sender == address(this) && _redeemInProgress(), "GNUSRedeemAdapter: unexpected transfer");
        return IERC1155ReceiverUpgradeable.onERC1155Received.selector;
    }

    /// @notice Dedicated diamond-storage slot for the redeem-in-progress flag (append-only layout).
    bytes32 private constant REDEEM_IN_PROGRESS_SLOT = keccak256("gnus.ai.redeem.adapter.storage");

    /// @notice Reads the redeem-in-progress flag.
    function _redeemInProgress() private view returns (bool flag) {
        bytes32 slot = REDEEM_IN_PROGRESS_SLOT;
        assembly {
            flag := sload(slot)
        }
    }

    /// @notice Writes the redeem-in-progress flag.
    function _setRedeemInProgress(bool value) private {
        bytes32 slot = REDEEM_IN_PROGRESS_SLOT;
        assembly {
            sstore(slot, value)
        }
    }

    /// @notice Rejects batch transfers — the adapter never sends batches to itself.
    /// @dev The adapter only pulls single tokens via `_safeTransferFrom`; a batch arriving at the
    ///      diamond is a user error or an attack probe. Rejecting loudly avoids stranded custody
    ///      of tokens the adapter will never burn (Phase 10 no-custody model, T-11-05).
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert("GNUSRedeemAdapter: batch transfers not accepted");
    }

    /// @notice Redeem `amount` of child token `childId` held by `from` for GNUS minted to `recipient`.
    /// @dev Caller (msg.sender) is typically an external ERC-20 proxy contract; `from` is the end
    ///      user. Two gates (Codex P1, PR #75): (1) AUTHORIZATION — `from` must be the caller or
    ///      have operator-approved the caller (`setApprovalForAll(proxy, true)`), so approval of
    ///      the diamond alone never authorizes an arbitrary third party to redeem a holder's
    ///      balance; (2) TRANSFER — `from` must have ERC-1155-approved this diamond as operator
    ///      (`setApprovalForAll(diamond, true)`, one-time), the mechanism for the pull below.
    ///      Atomic: pull + burn + mint happen in this transaction; the diamond never holds child
    ///      tokens across transactions. Conversion is 1:1 minion-denominated (Phase 9 D2). CEI
    ///      ordering: limiter charge -> pull -> burn -> mint -> event (T-11-01).
    /// @param from The token holder whose child balance is debited (must have approved the caller AND the diamond as ERC-1155 operators).
    /// @param childId Child token id (must not be GNUS_TOKEN_ID, must be created, must be convertible).
    /// @param amount Minion amount (1:1 to GNUS per Phase 9 D2).
    /// @param recipient Recipient of the minted GNUS.
    function redeem(address from, uint256 childId, uint256 amount, address recipient) external {
        address caller = _msgSender();

        require(childId != GNUS_TOKEN_ID, "Cannot redeem GNUS itself");
        require(amount > 0, "Amount must be greater than zero");
        require(recipient != address(0), "ERC1155: mint to the zero address");
        require(from != address(0), "ERC1155: transfer from the zero address");

        NFT storage childNft = GNUSNFTFactoryStorage.layout().NFTs[childId];
        require(childNft.nftCreated, "Token not created.");
        require(!childNft.nonConvertible, "Token is non-convertible");

        // Authorization gate (Codex P1, PR #75): approval of the diamond is the TRANSFER
        // mechanism for the pull below — it is NOT authorization for any arbitrary caller to
        // redeem on `from`'s behalf. Without this check, once `from` grants the diamond
        // operator approval (required for redeem), anyone could call redeem(victim, …,
        // attacker) and drain the victim's approved balance. Bind authorization to the
        // actual caller: `from` must BE the caller or have operator-approved the caller
        // (the ERC-20 proxy contract). The allowance chain is then user → approves proxy →
        // proxy forwards `from` — and the proxy's own ERC-20 allowance logic (PROXY-01)
        // governs the spend.
        require(
            from == caller || isApprovedForAll(from, caller),
            "GNUSRedeemAdapter: caller not authorized by token holder"
        );

        // Transfer gate: the internal _safeTransferFrom has no approval check (it lives
        // only in the public safeTransferFrom), so enforce it here for the pull leg.
        require(
            from == caller || isApprovedForAll(from, address(this)),
            "ERC1155: caller is not token owner or approved"
        );

        // WR-07 GNUS-terminal limiter charge keyed to `from` (the user), NOT the diamond/proxy.
        // Replaces the charge GNUSTreasury.convert would apply to _msgSender(). The mint leg
        // below is hook-exempt from the limiter, so this is the only charge (no double-charge).
        // NOTE: the super-admin bypass below is keyed to `from`, not to the caller (differs
        // from GNUSTreasury.convert, which keys to `sender`); the actual caller identity is
        // captured in the RedeemedViaAdapter event for auditability.
        if (LibDiamond.diamondStorage().contractOwner != from) {
            GNUSWithdrawLimiterStorage.checkAndRecordWithdraw(from, amount);
        } else {
            emit GNUSWithdrawLimiterStorage.SuperAdminBypass(from, amount, "GNUSRedeemAdapter.redeem");
        }

        _setRedeemInProgress(true);
        _safeTransferFrom(from, address(this), childId, amount, "");
        _setRedeemInProgress(false);
        _burn(address(this), childId, amount);
        _mint(recipient, GNUS_TOKEN_ID, amount, "");

        emit RedeemedViaAdapter(caller, from, childId, amount, recipient);
    }
}
