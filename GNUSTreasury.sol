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

    /// @notice Emitted once by GNUSTreasury_SetSeedSupply when the provenance seed is written.
    /// @param seedGlobalSupply Initial value of this chain's supply (= totalSupply() at onboard; 0 on fresh chains).
    /// @param operator Address that invoked the seeder (DEFAULT_ADMIN_ROLE holder).
    event GlobalSupplyInitialized(uint256 seedGlobalSupply, address indexed operator);

    /// @notice Emitted every time setSisterChainSupply records a sister chain's supply (auditable).
    /// @param chainId Sister chain id (never this chain's own id).
    /// @param oldSupply Previously recorded supply for that chain (0 if first registration).
    /// @param newSupply New recorded supply.
    /// @param operator Address that invoked the update (DEFAULT_ADMIN_ROLE holder).
    event SisterChainSupplyUpdated(uint256 indexed chainId, uint256 oldSupply, uint256 newSupply, address indexed operator);

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

    /// @notice Cut-safe provenance initializer (D8, per-chain model).
    /// @dev Records this deployment's chain id. Runs inside the diamond cut, so it takes no
    ///      arguments (the deployment tooling encodes protocol initializers with zero args).
    ///      Does NOT flip provenanceInitialized and does NOT seed any supply — this chain's
    ///      starting supply is written post-deploy by GNUSTreasury_SetSeedSupply, and sister
    ///      chains are registered via setSisterChainSupply; only then does the provenance view
    ///      go live.
    function GNUSTreasury_Initialize260() external onlySuperAdminRole {
        GNUSTreasuryStorage.Layout storage l = GNUSTreasuryStorage.layout();
        require(l.ownChainId == 0, "Chain id already recorded");
        l.ownChainId = block.chainid;
    }

    /// @notice One-shot provenance seeder (D8). Post-deploy only.
    /// @dev Writes THIS chain's starting supply — its totalSupply() of GNUS at onboard time,
    ///      which is 0 on a fresh chain and the existing minted figure when retrofitting a live
    ///      chain. globalSupply starts at the seed and grows as sister chains are registered
    ///      via setSisterChainSupply. Flips provenanceInitialized, which unblocks
    ///      totalSupplyOfAll(). One-shot: re-seeding must be impossible because the seed is
    ///      chain-specific (PATTERNS section 3).
    /// @param seedGlobalSupply This chain's starting supply (minions).
    function GNUSTreasury_SetSeedSupply(uint256 seedGlobalSupply) external onlyRole(DEFAULT_ADMIN_ROLE) {
        GNUSTreasuryStorage.Layout storage l = GNUSTreasuryStorage.layout();
        require(l.ownChainId != 0, "Chain id not recorded");
        require(!l.provenanceInitialized, "Already initialized");
        l.chainSupply[l.ownChainId] = seedGlobalSupply;
        l.globalSupply = seedGlobalSupply;
        l.provenanceInitialized = true;
        emit GlobalSupplyInitialized(seedGlobalSupply, _msgSender());
    }

    /// @notice Record sister-chain supplies and adjust the aggregate by delta (D8 revision).
    /// @dev Post-deploy onboarding path (one call per chain, or a batch — arrays of 1 are fine)
    ///      and the reconciliation path after any out-of-band mint on a sister chain. Each
    ///      entry replaces the recorded figure for that chain; globalSupply moves by the delta.
    ///      This chain's own entry is maintained by the mint/burn paths and SetSeedSupply —
    ///      passing ownChainId here is rejected.
    /// @param chainIds Sister chain ids.
    /// @param newSupplies New total supply for each chain (minions), parallel to chainIds.
    function setSisterChainSupply(uint256[] calldata chainIds, uint256[] calldata newSupplies)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        GNUSTreasuryStorage.Layout storage l = GNUSTreasuryStorage.layout();
        require(l.provenanceInitialized, "Not initialized");
        require(chainIds.length == newSupplies.length, "Array length mismatch");
        for (uint256 i; i < chainIds.length; ) {
            uint256 chainId = chainIds[i];
            require(chainId != l.ownChainId, "Cannot set own chain supply");
            uint256 oldSupply = l.chainSupply[chainId];
            uint256 newSupply = newSupplies[i];
            l.chainSupply[chainId] = newSupply;
            l.globalSupply = l.globalSupply - oldSupply + newSupply;
            emit SisterChainSupplyUpdated(chainId, oldSupply, newSupply, _msgSender());
            unchecked {
                ++i;
            }
        }
    }
}
