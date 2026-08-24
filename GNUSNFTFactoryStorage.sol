// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title GNUSNFTFactoryStorage
/// @notice This library provides storage layout and functions for managing NFTs within the GNUS ecosystem.
/// @dev This library uses a struct to define the storage layout and provides functions to access and manipulate the storage.

/// @notice Struct representing an NFT.
/// @dev This struct contains various properties related to an NFT, including its name, symbol, URI, exchange rate, max supply, creator, child index, and creation status.
struct NFT {
    string name;            ///< Token/NFT Name
    string symbol;          ///< Token/NFT Symbol
    string uri;             ///< Token/NFT URI for metadata
    uint256 exchangeRate;   ///< Display-only fixed-point rate: minions per 1 child unit, 1e18 scale (D2)
    uint256 maxSupply;      ///< Maximum supply of NFTs (minion cap per research section C)
    address creator;        ///< The creator of the token
    uint128 childCurIndex;  ///< The current child NFT count created
    bool nftCreated;        ///< Indicates if the NFT has been created
    // Phase 9 appends below - do not reorder, do not insert above this line
    uint256 parentId;       ///< D7 - parent token ID; 0 = direct child of GNUS (zero-default correct for existing direct children)
    bool nonConvertible;    ///< D5 - false (zero-default) = convertible, opt-out; true = burn-only (Phase 13 sets at creation)
    // Phase 13 appends below - do not reorder, do not insert above this line
    // Slot annotations verified by storage probe in GNUSLifecycleUpgrade.test.ts (IN-04, 13 review):
    // nonConvertible (1B) + 3x uint64 (24B) + 3x uint8 (3B) = 28B pack into slot +8;
    // the two addresses occupy full slots +9 and +10.
    uint64  validFrom;             ///< D1 - sale/window start (slot +8 bytes 1-8, packed after nonConvertible); 0 = active immediately
    uint64  validUntil;            ///< D1 - per-ID expiry timestamp (slot +8 bytes 9-16); 0 = no expiry (used in PerTokenId mode)
    uint64  defaultDuration;       ///< D1 - purchase duration for PerHolder mode (slot +8 bytes 17-24); 0 = unset
    uint8   expirationMode;        ///< D1 - ExpirationMode enum ordinal (slot +8 byte 25); 0 = None
    uint8   transferPolicy;        ///< D1 - TransferPolicy enum ordinal (slot +8 byte 26); 0 = UNRESTRICTED
    uint8   expirationDisposition; ///< D1 - ExpirationDisposition enum ordinal (slot +8 byte 27); 0 = NONE
    address expirationRecipient;   ///< D1 - destination for RETURN_TO_ADDRESS (slot +9 bytes 0-19); 0x0 = unset
    address credentialVerifier;    ///< D1 - ICredentialVerifier plug-in (slot +10 bytes 0-19); 0x0 = no credential required to mint
}

/// @custom:security-contact support@gnus.ai
library GNUSNFTFactoryStorage {
    /// @notice Struct representing the storage layout for the GNUS NFT Factory.
    /// @dev This struct contains a mapping from token IDs to NFT information.
    struct Layout {
        mapping(uint256 => NFT) NFTs; ///< Mapping from token ID to NFT information
    }

    /// @notice The storage position for the GNUS NFT Factory storage.
    /// @dev This constant is used to identify the storage slot for the GNUS NFT Factory storage.
    bytes32 constant GNUS_NFT_FACTORY_STORAGE_POSITION = keccak256("gnus.ai.nft.factory.storage");

    /// @notice Retrieves the storage layout for the GNUS NFT Factory.
    /// @dev This function uses inline assembly to access the storage slot for the GNUS NFT Factory storage.
    /// @return l The storage layout for the GNUS NFT Factory.
    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = GNUS_NFT_FACTORY_STORAGE_POSITION;
        assembly {
            l.slot := slot
        }
    }
}
