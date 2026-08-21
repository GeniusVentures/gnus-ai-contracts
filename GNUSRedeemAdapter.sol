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
/// @notice Caller-bound adapter for redeeming child tokens for GNUS (Phase 11, PROXY-03).
/// @dev Direct-burn/mint model: the caller (`_msgSender()`) IS the token holder — `redeem`
///      burns `amount` of the caller's child token `childId` and mints the same amount of
///      GNUS back to the caller, atomically in one transaction (supply-neutral reallocation,
///      Phase 9 D1). Because no third-party `from` parameter exists, no operator approvals
///      are required for redeem — the pre-Codex-P1 vulnerability class (an arbitrary caller
///      draining an approved victim) is unrepresentable in this interface. The WR-07 limiter
///      charge is keyed to the caller. Conversion is 1:1 minion-denominated (Phase 9 D2);
///      the diamond never holds child tokens across transactions (Phase 10 no-custody model).
/// @custom:security-contact support@gnus.ai
contract GNUSRedeemAdapter is Initializable, GNUSERC1155MaxSupply, GeniusAccessControl, IERC1155ReceiverUpgradeable {
    /// @notice Emitted when a redemption completes.
    /// @param from The holder whose child balance was burned (always `_msgSender()`).
    /// @param childId Child token id burned.
    /// @param amount Minion amount converted (1:1 to GNUS, Phase 9 D2).
    event Redeemed(address indexed from, uint256 indexed childId, uint256 amount);

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

    /// @notice Rejects ERC-1155 transfers into the diamond unconditionally.
    /// @dev The diamond never legitimately receives ERC-1155 tokens (redeem burns in place,
    ///      no pull leg), so any inbound single transfer is a user error or attack probe.
    ///      Rejecting loudly preserves the pre-facet revert-on-direct-transfer posture and
    ///      avoids stranded custody (Phase 10 no-custody model, T-11-06).
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        revert("GNUSRedeemAdapter: unexpected transfer");
    }

    /// @notice Rejects batch transfers into the diamond unconditionally.
    /// @dev The diamond never sends or receives batches. Rejecting loudly avoids stranded
    ///      custody of tokens the diamond will never burn (Phase 10 no-custody model, T-11-05).
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert("GNUSRedeemAdapter: batch transfers not accepted");
    }

    /// @notice Redeem `amount` of the caller's child token `childId` for GNUS minted to the caller.
    /// @dev Caller (`_msgSender()`) is the token holder and the GNUS recipient. Atomic
    ///      supply-neutral reallocation: `_burn(caller, childId, amount)` +
    ///      `_mint(caller, GNUS_TOKEN_ID, amount)` in one transaction. Conversion is 1:1
    ///      minion-denominated (Phase 9 D2). CEI ordering: limiter charge -> burn -> mint ->
    ///      event (T-11-01). No operator approval is required — the caller IS the holder.
    /// @param childId Child token id (must not be GNUS_TOKEN_ID, must be created, must be convertible).
    /// @param amount Minion amount (1:1 to GNUS per Phase 9 D2).
    function redeem(uint256 childId, uint256 amount) external {
        address from = _msgSender();

        require(childId != GNUS_TOKEN_ID, "Cannot redeem GNUS itself");
        require(amount > 0, "Amount must be greater than zero");

        NFT storage childNft = GNUSNFTFactoryStorage.layout().NFTs[childId];
        require(childNft.nftCreated, "Token not created.");
        require(!childNft.nonConvertible, "Token is non-convertible");

        // WR-07 GNUS-terminal limiter charge keyed to the caller (the holder). The mint leg
        // below is hook-exempt from the limiter, so this is the only charge (no double-charge).
        if (LibDiamond.diamondStorage().contractOwner != from) {
            GNUSWithdrawLimiterStorage.checkAndRecordWithdraw(from, amount);
        } else {
            emit GNUSWithdrawLimiterStorage.SuperAdminBypass(from, amount, "GNUSRedeemAdapter.redeem");
        }

        _burn(from, childId, amount);
        _mint(from, GNUS_TOKEN_ID, amount, "");

        emit Redeemed(from, childId, amount);
    }
}
