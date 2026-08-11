// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/proxy/utils/Initializable.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSTreasuryStorage.sol";
import "./GNUSWithdrawLimiterStorage.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title GNUSTreasury
/// @notice Conversion-native facet for the GNUS ecosystem (Phase 9 - D1/D2/D3/D5/D8).
/// @dev Supply-neutral reallocation is the canonical state transition for everything that is NOT
///      a depth-1 mint, a bridge op, or a root mint. The exchangeRate stored on each NFT is
///      display-only (D2); conversion moves minions 1:1 between ids.
/// @custom:security-contact support@gnus.ai
contract GNUSTreasury is Initializable, GNUSERC1155MaxSupply, GeniusAccessControl {
    using GNUSNFTFactoryStorage for GNUSNFTFactoryStorage.Layout;
    using GNUSTreasuryStorage for GNUSTreasuryStorage.Layout;

    /// @notice Display-rate scale (D2). NFT.exchangeRate is denominated against this factor.
    uint256 internal constant RATE_SCALE = 1e18;

    /// @notice Emitted when a supply-neutral reallocation completes.
    /// @param fromId Source token id (burned from sender).
    /// @param toId Destination token id (minted to `to`).
    /// @param minionAmount Amount reallocated (always in minions, 1:1 both legs).
    /// @param to Recipient of the minted leg.
    event Converted(uint256 indexed fromId, uint256 indexed toId, uint256 minionAmount, address indexed to);

    /// @notice Emitted once by GNUSTreasury_Initialize260 to record the cross-chain provenance seed.
    /// @param seedGlobalSupply Initial value of globalSupply (chain-specific; 0 for first chain).
    /// @param operator Address that invoked the initializer (always the super admin).
    event GlobalSupplyInitialized(uint256 seedGlobalSupply, address indexed operator);

    /// @notice Emitted every time syncGlobalSupply runs (D8 honesty valve; auditable).
    /// @param oldGlobal Previous value of globalSupply.
    /// @param newGlobal New value being written.
    /// @param operator Address that invoked the sync (DEFAULT_ADMIN_ROLE holder).
    event GlobalSupplySynced(uint256 oldGlobal, uint256 newGlobal, address indexed operator);

    /// @inheritdoc ERC1155Upgradeable
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) ||
            AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
            (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /// @notice Supply-neutral reallocation between two token ids (D3, D5).
    /// @dev Burns `minionAmount` of `fromId` from the caller and mints the same amount of `toId`
    ///      to `to`. The global provenance counter is intentionally untouched (Pitfall 2) —
    ///      conversion preserves total minions across the diamond.
    ///
    ///      Limiter charge matrix (WR-07, research §G):
    ///        - GNUS-terminal (toId == GNUS_TOKEN_ID): explicit charge HERE, because the
    ///          subsequent `_mint` leg is hook-exempt (mints skip the limiter aggregation).
    ///        - GNUS-source (fromId == GNUS_TOKEN_ID): NO explicit charge — the `_burn`
    ///          routes through `_beforeTokenTransfer` (non-mint, id == 0) and the hook
    ///          charges automatically. Adding an explicit charge would double-charge.
    ///        - child->child: no limiter charge (neither leg is GNUS).
    /// @param fromId Source token id (must be created; non-convertible only allowed when id == 0).
    /// @param toId Destination token id (must be created; non-convertible only allowed when id == 0).
    /// @param minionAmount Amount of minions to reallocate (same units on both legs, 1:1).
    /// @param to Recipient of the minted leg (must not be address(0)).
    function convert(uint256 fromId, uint256 toId, uint256 minionAmount, address to) external {
        address sender = _msgSender();

        require(fromId != toId, "Cannot convert to same id");
        require(minionAmount > 0, "Amount must be greater than zero");
        require(to != address(0), "ERC1155: mint to the zero address");

        GNUSNFTFactoryStorage.Layout storage nftLayout = GNUSNFTFactoryStorage.layout();
        NFT storage fromNft = nftLayout.NFTs[fromId];
        NFT storage toNft = nftLayout.NFTs[toId];

        require(fromNft.nftCreated, "Token not created.");
        require(toNft.nftCreated, "Token not created.");

        // D5: GNUS itself is always convertible. nonConvertible applies to child ids only.
        require(fromId == GNUS_TOKEN_ID || !fromNft.nonConvertible, "Token is non-convertible");
        require(toId == GNUS_TOKEN_ID || !toNft.nonConvertible, "Token is non-convertible");

        // WR-07 explicit limiter charge — ONLY on the GNUS-terminal leg (research §G).
        // Mint leg is hook-exempt from the limiter, so we charge here. Super admin bypasses.
        if (toId == GNUS_TOKEN_ID) {
            if (LibDiamond.diamondStorage().contractOwner != sender) {
                GNUSWithdrawLimiterStorage.checkAndRecordWithdraw(sender, minionAmount);
            } else {
                emit GNUSWithdrawLimiterStorage.SuperAdminBypass(
                    sender,
                    minionAmount,
                    "GNUSTreasury.convert"
                );
            }
        }
        // NOTE: no explicit charge when fromId == GNUS_TOKEN_ID. The `_burn` below routes
        // through `_beforeTokenTransfer` (non-mint, id == 0) and the hook charges automatically.
        // Adding an explicit charge here would double-charge the caller (research §G).

        _burn(sender, fromId, minionAmount);
        _mint(to, toId, minionAmount, "");

        emit Converted(fromId, toId, minionAmount, to);
    }

    /// @notice Display-view: the caller-visible "child units" of `account` for token `id` (D2).
    /// @dev Read-only. Floor-rounds. Reverts on id 0 and when no display rate is set.
    ///      Stored `NFTs[0].exchangeRate` is 1 by default; exposing it as a display view
    ///      would inflate balances by 1e18 (Pitfall 6), so id 0 is rejected outright.
    /// @param id Token id (must not be GNUS_TOKEN_ID).
    /// @param account Holder whose balance is converted to display units.
    /// @return Display units: floor(balance * 1e18 / exchangeRate).
    function unitsOf(uint256 id, address account) external view returns (uint256) {
        require(id != GNUS_TOKEN_ID, "GNUS has no child units");
        uint256 rate = GNUSNFTFactoryStorage.layout().NFTs[id].exchangeRate;
        require(rate > 0, "No display rate");
        return (balanceOf(account, id) * RATE_SCALE) / rate;
    }

    /// @notice Display-view: the total "child units" in circulation for token `id` (D2).
    /// @dev Same revert matrix as `unitsOf`. Floor-rounds against totalSupply.
    /// @param id Token id (must not be GNUS_TOKEN_ID).
    /// @return Display units: floor(totalSupply(id) * 1e18 / exchangeRate).
    function totalUnitsOf(uint256 id) external view returns (uint256) {
        require(id != GNUS_TOKEN_ID, "GNUS has no child units");
        uint256 rate = GNUSNFTFactoryStorage.layout().NFTs[id].exchangeRate;
        require(rate > 0, "No display rate");
        return (totalSupply(id) * RATE_SCALE) / rate;
    }

    /// @notice Cross-chain provenance view (D8 - B1 model).
    /// @dev Fails loudly when the provenance seed has not been written yet — a misconfigured
    ///      deploy must not silently return 0 (Open Question 4 resolution: revert per research).
    /// @return The current value of `globalSupply` (cumulative minted minions across all chains).
    function totalSupplyOfAll() external view returns (uint256) {
        GNUSTreasuryStorage.Layout storage l = GNUSTreasuryStorage.layout();
        require(l.provenanceInitialized, "Global supply not initialized");
        return l.globalSupply;
    }

    /// @notice One-shot provenance initializer (D8).
    /// @dev Seeds `globalSupply` for this chain. The seed is the current global GNUS figure at
    ///      deploy time for this chain: the FIRST chain seeds 0 (or genesis); subsequent chains
    ///      seed the then-current global figure from off-chain coordination. Guard is a one-shot
    ///      bool, NOT a version compare (PATTERNS section 3) — re-seeding must be impossible
    ///      because the seed is chain-specific.
    /// @param seedGlobalSupply Initial value for `globalSupply` on this chain (minions).
    function GNUSTreasury_Initialize260(uint256 seedGlobalSupply) external onlySuperAdminRole {
        GNUSTreasuryStorage.Layout storage l = GNUSTreasuryStorage.layout();
        require(!l.provenanceInitialized, "Already initialized");
        l.globalSupply = seedGlobalSupply;
        l.provenanceInitialized = true;
        emit GlobalSupplyInitialized(seedGlobalSupply, _msgSender());
    }

    /// @notice Auditable honesty valve for cross-chain drift (D8).
    /// @dev Every call emits GlobalSupplySynced — observers can reconcile off-chain. Routine
    ///      paths should never need this; Phase 12 owns fuller reconciliation. Emits BEFORE
    ///      the write so the event captures the old value.
    /// @param newGlobal New value for `globalSupply` (minions, cumulative across all chains).
    function syncGlobalSupply(uint256 newGlobal) external onlyRole(DEFAULT_ADMIN_ROLE) {
        GNUSTreasuryStorage.Layout storage l = GNUSTreasuryStorage.layout();
        require(l.provenanceInitialized, "Not initialized");
        emit GlobalSupplySynced(l.globalSupply, newGlobal, _msgSender());
        l.globalSupply = newGlobal;
    }
}
