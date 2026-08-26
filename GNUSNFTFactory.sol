// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/proxy/utils/Initializable.sol";
import "./GNUSERC1155MaxSupply.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";

/// @custom:security-contact support@gnus.ai
/// @title GNUSNFTFactory
/// @notice This contract manages the creation, minting, and management of NFTs within the GNUS ecosystem.
/// @dev This contract extends GNUSERC1155MaxSupply and GeniusAccessControl for additional functionality.
contract GNUSNFTFactory is Initializable, GNUSERC1155MaxSupply, GeniusAccessControl {
    using GNUSNFTFactoryStorage for GNUSNFTFactoryStorage.Layout;
    using ERC1155SupplyStorage for ERC1155SupplyStorage.Layout;

    /// @notice Role identifier for creators.
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");

    /// @notice Initializes the GNUSNFTFactory contract.
    /// @dev This function is called only once and subsequent calls are ignored due to the initializer modifier.
    function GNUSNFTFactory_Initialize() public onlySuperAdminRole {
        InitializableStorage.layout()._initializing = true;
        __ERC1155_init("");
        __ERC1155Burnable_init();
        __ERC1155Supply_init();
        __GeniusAccessControl_init();

        address superAdmin = _msgSender();
        _grantRole(CREATOR_ROLE, superAdmin);

        createNFT(GNUS_TOKEN_ID, GNUS_NAME, GNUS_SYMBOL, 1.0, GNUS_MAX_SUPPLY, GNUS_URI);

        InitializableStorage.layout()._initialized = false;
    }

    /// @notice Initializes the GNUSNFTFactory contract for version 2.3.0.
    /// @dev This function ensures that the GNUS token is created if it hasn't been already.
    function GNUSNFTFactory_Initialize230() public onlySuperAdminRole {
        if (!GNUSNFTFactoryStorage.layout().NFTs[GNUS_TOKEN_ID].nftCreated) {
            GNUSNFTFactory_Initialize();
        }
    }

    /// @notice Sets the top-level URI for the GNUS Token NFT.
    /// @dev This function can only be called by an account with the DEFAULT_ADMIN_ROLE.
    /// @param newuri The new URI to set.
    function setURI(string memory newuri) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _setURI(newuri);
        GNUSNFTFactoryStorage.layout().NFTs[GNUS_TOKEN_ID].uri = newuri;
    }

    /// @notice Sets the URI for a specific NFT.
    /// @dev This function can only be called by the creator of the NFT or an account with the DEFAULT_ADMIN_ROLE.
    /// @param id The ID of the NFT.
    /// @param newuri The new URI to set.
    function setURI(uint256 id, string memory newuri) public {
        address sender = _msgSender();
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        require(nft.nftCreated, "NFT must have been created to set the URI for");
        require((nft.creator == sender) || hasRole(DEFAULT_ADMIN_ROLE, sender), "Only Admin or Creator can set URI of NFT");
        nft.uri = newuri;
    }

    /// @notice Retrieves the URI for a specific NFT.
    /// @dev This function overrides the uri function from ERC1155Upgradeable.
    /// @param id The ID of the NFT.
    /// @return The URI of the NFT.
    function uri(uint256 id) public view virtual override(ERC1155Upgradeable) returns (string memory) {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        require(nft.nftCreated, "NFT must already be created to get the URI for it");
        return nft.uri;
    }

    /// @notice Internal function to perform checks before minting an NFT.
    /// @dev This function ensures that the minting conditions are met.
    ///      Phase 9 (D1/D6): `amount` is now MINIONS of GNUS, not child units.
    ///      The caller pays exactly `amount` id-0 minions and the child supply
    ///      increases by exactly `amount`. Depth is gated to direct children only;
    ///      issuance deeper in the tree goes through `GNUSTreasury.convert`.
    /// @param to The address to mint the NFT to.
    /// @param id The ID of the NFT (must be a direct child of GNUS).
    /// @param nft The NFT storage object.
    /// @param amount The amount of id-0 minions to convert into child minions (1:1).
    function beforeMint(address to, uint256 id, NFT storage nft, uint256 amount) internal {
        address sender = _msgSender();
        require(id != GNUS_TOKEN_ID, "Shouldn't mint GNUS tokens tokens, only deposit and withdraw");
        require(to != address(0), "ERC1155: mint to the zero address");
        require(nft.nftCreated, "Cannot mint NFT that doesn't exist");
        require((sender == nft.creator) || hasRole(DEFAULT_ADMIN_ROLE, sender), "Creator or Admin can only mint NFT");
        require((id >> 128) == GNUS_TOKEN_ID, "Direct children only; use convert() for descendants"); // D6 depth gate
        require(balanceOf(sender, GNUS_TOKEN_ID) >= amount, "Not enough GNUS_TOKEN to convert");
        _burn(sender, GNUS_TOKEN_ID, amount); // D1: 1:1 minion move; amount IS minions
    }

    /// @notice Mints a new NFT.
    /// @dev This function mints a new NFT to the specified address.
    /// @param to The address to mint the NFT to.
    /// @param id The ID of the NFT.
    /// @param amount The amount of the NFT to mint.
    /// @param data Additional data with no specified format.
    function mint(address to, uint256 id, uint256 amount, bytes memory data) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        beforeMint(to, id, nft, amount);
        _mint(to, id, amount, data);
    }

    /// @notice Mints a batch of new NFTs.
    /// @dev This function mints a batch of new NFTs to the specified address.
    /// @param to The address to mint the NFTs to.
    /// @param ids The IDs of the NFTs.
    /// @param amounts The amounts of the NFTs to mint.
    /// @param data Additional data with no specified format.
    function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data) external {
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
            beforeMint(to, id, nft, amounts[i]);
        }
        _mintBatch(to, ids, amounts, data);
    }

    /// @notice Checks if the contract supports a specific interface.
    /// @dev This function overrides the supportsInterface function from ERC1155Upgradeable and AccessControlEnumerableUpgradeable.
    /// @param interfaceId The ID of the interface to check.
    /// @return True if the interface is supported, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) || AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
        (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /// @notice Creates a new NFT.
    /// @dev This function creates a new NFT with the specified parameters.
    /// @param parentID The ID of the parent NFT.
    /// @param name The name of the NFT.
    /// @param symbol The symbol of the NFT.
    /// @param exchRate The exchange rate of the NFT.
    /// @param max_supply The maximum supply of the NFT.
    /// @param newuri The URI of the NFT.
    function createNFT(uint256 parentID, string memory name, string memory symbol, uint256 exchRate, uint256 max_supply, string memory newuri) public {
        createNFTs(parentID, asSingletonArray(name), asSingletonArray(symbol), asSingletonArray(exchRate), asSingletonArray(max_supply), asSingletonArray(newuri));
    }

    /// @notice Creates multiple new NFTs.
    /// @dev This function creates multiple new NFTs with the specified parameters.
    /// @param parentID The ID of the parent NFT.
    /// @param names The names of the NFTs.
    /// @param symbols The symbols of the NFTs.
    /// @param exchRates The exchange rates of the NFTs.
    /// @param max_supplies The maximum supplies of the NFTs.
    /// @param newuris The URIs of the NFTs.
    function createNFTs(uint256 parentID, string[] memory names, string[] memory symbols, uint256[] memory exchRates, uint256[] memory max_supplies, string[] memory newuris) public {
        address sender = _msgSender();
        NFT memory nft = GNUSNFTFactoryStorage.layout().NFTs[parentID];
        if (parentID == GNUS_TOKEN_ID) {
            require(hasRole(DEFAULT_ADMIN_ROLE, sender) || (hasRole(CREATOR_ROLE, sender)), "Only Creators or Admins can create NFT child of GNUS");
        } else {
            require(nft.nftCreated, "Parent NFT Should have been created already");
            require(sender == nft.creator, "Only parent creator can create child NFTs");
        }
        uint numToCreate = names.length;
        require((numToCreate == symbols.length) && (numToCreate == exchRates.length) && (numToCreate == max_supplies.length) && (numToCreate == newuris.length),
            "NFT creation array lengths, should be the same");
        for (uint256 i = 0; i < names.length; i++) {
            if (parentID == GNUS_TOKEN_ID) {
                require(exchRates[i] > 0, "Exchange Rate has to be > 0 for creating a new Child NFT of GNUS");
            }
            uint256 newTokenID = (parentID << 128) | nft.childCurIndex++;
            require(!GNUSNFTFactoryStorage.layout().NFTs[newTokenID].nftCreated, "Token ID collision"); // D7
            // EIP-170 relief (Phase 14, 13-04 Option A precedent): write only the non-zero
            // fields. The collision guard above plus the monotonic childCurIndex guarantee a
            // virgin (all-zero) storage record, so zero-default fields — childCurIndex,
            // nonConvertible, the Phase 13 lifecycle defaults (D1), and the Phase 14
            // licensing defaults (D-03/D-25: companyAdmin, privateNetworkId, networkScope,
            // publicSettlementEnabled) — decode correctly without explicit zero stores.
            NFT storage newNft = GNUSNFTFactoryStorage.layout().NFTs[newTokenID];
            newNft.name = names[i];
            newNft.symbol = symbols[i];
            newNft.exchangeRate = exchRates[i];
            newNft.maxSupply = max_supplies[i];
            newNft.uri = newuris[i];
            newNft.creator = sender;
            newNft.nftCreated = true;
            newNft.parentId = parentID;    // D7 - recorded, not derived
        }
        GNUSNFTFactoryStorage.layout().NFTs[parentID].childCurIndex = nft.childCurIndex;
    }

    /// @notice Retrieves information about a specific NFT.
    /// @dev This function returns the NFT storage object for the specified ID.
    /// @param id The ID of the NFT.
    /// @return The NFT storage object.
    function getNFTInfo(uint256 id) public view returns (NFT memory) {
        require(GNUSNFTFactoryStorage.layout().NFTs[id].nftCreated, "No Token created for this ID");
        return GNUSNFTFactoryStorage.layout().NFTs[id];
    }
}
