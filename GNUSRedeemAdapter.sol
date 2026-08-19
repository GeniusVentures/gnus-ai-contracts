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

    /// @notice Accepts ERC-1155 self-transfers into the diamond during redeem.
    /// @dev Always returns the magic selector; the adapter's redeem function pulls tokens into
    ///      address(this) atomically before burning them, so custody never persists across
    ///      transactions. Stateless and pure — enables only the self-transfer redeem initiates.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC1155ReceiverUpgradeable.onERC1155Received.selector;
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
    ///      user. `from` must have ERC-1155-approved this diamond as operator
    ///      (`setApprovalForAll(diamond, true)`, one-time). Atomic: pull + burn + mint happen in
    ///      this transaction; the diamond never holds child tokens across transactions. Conversion
    ///      is 1:1 minion-denominated (Phase 9 D2). CEI ordering: limiter charge -> pull -> burn
    ///      -> mint -> event (T-11-01).
    /// @param from The token holder whose child balance is debited (must have approved the diamond as ERC-1155 operator).
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

        // WR-07 GNUS-terminal limiter charge keyed to `from` (the user), NOT the diamond/proxy.
        // Replaces the charge GNUSTreasury.convert would apply to _msgSender(). The mint leg
        // below is hook-exempt from the limiter, so this is the only charge (no double-charge).
        if (LibDiamond.diamondStorage().contractOwner != from) {
            GNUSWithdrawLimiterStorage.checkAndRecordWithdraw(from, amount);
        } else {
            emit GNUSWithdrawLimiterStorage.SuperAdminBypass(from, amount, "GNUSRedeemAdapter.redeem");
        }

        _safeTransferFrom(from, address(this), childId, amount, "");
        _burn(address(this), childId, amount);
        _mint(recipient, GNUS_TOKEN_ID, amount, "");

        emit RedeemedViaAdapter(caller, from, childId, amount, recipient);
    }
}
