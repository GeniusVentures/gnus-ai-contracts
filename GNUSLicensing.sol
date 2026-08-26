// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/ERC1155Storage.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/extensions/ERC1155SupplyStorage.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSLicensingStorage.sol";
import "./GNUSLicensingTypes.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title GNUSLicensing
/// @notice Private-network AI licensing SKU registry CONFIG & VIEW facet (Phase 14, LIC-03, D-04/D-12).
/// @dev Plan 14-02 facet split: this facet owns SKU configuration + read paths only. Purchase,
///      payment burn, and license creation/renewal live on the sibling GNUSLicensingPurchase facet
///      (plan 14-03). The two facets NEVER call each other — they share state only through diamond
///      storage (GNUSLicensingStorage for the SKU registry).
///
///      Authorization: CREATOR_ROLE or DEFAULT_ADMIN_ROLE per D-12 — no new role machinery.
/// @custom:security-contact support@gnus.ai
contract GNUSLicensing is GNUSERC1155MaxSupply, GeniusAccessControl, IGNUSLicensingEvents {
    /// @dev Role identifier for creators — identical value to GNUSNFTFactory.CREATOR_ROLE
    ///      (keccak256("CREATOR_ROLE")). Re-declared locally because this facet cannot import
    ///      GNUSNFTFactory (circular) but needs the same role for SKU administration auth.
    bytes32 private constant _CREATOR_ROLE = keccak256("CREATOR_ROLE");

    /// @dev Validation revert reasons — named constants (no magic strings).
    string private constant _ERR_ONLY_CREATOR_OR_ADMIN = "Only creator or admin";
    string private constant _ERR_PRICE_ZERO = "Price must be greater than zero";
    string private constant _ERR_DURATION_ZERO = "Duration must be greater than zero";
    string private constant _ERR_SKU_MODE_CONFLICT = "SKU cannot both create and renew a license";
    string private constant _ERR_SKU_NO_CREDITS = "SKU mints no credits";

    /// @notice Checks if the contract supports a specific interface.
    /// @dev Overrides the diamond-aware supportsInterface (matches GNUSLifecycle.sol:45-48) —
    ///      combines ERC1155 and AccessControlEnumerable interfaces with any interfaces
    ///      registered in the diamond's supportedInterfaces mapping.
    /// @param interfaceId The ID of the interface to check.
    /// @return True if the interface is supported.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) || AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
        (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /// @notice Emitted when a SKU is created or updated (D-04 / T-14-02-02 audit trail).
    /// @param skuId SKU id configured.
    /// @param sku The full SKU payload that was written.
    /// @param operator The creator or admin who performed the configuration.
    event SKUConfigured(uint256 indexed skuId, SKU sku, address indexed operator);

    /// @notice Emitted when a SKU's active flag is toggled (D-04).
    /// @param skuId SKU id.
    /// @param active New active state (inactive SKUs remain stored and queryable).
    /// @param operator The creator or admin who performed the toggle.
    event SKUActiveToggled(uint256 indexed skuId, bool active, address indexed operator);

    /// @notice Creator-or-admin authorization helper (D-12).
    /// @dev CREATOR_ROLE or DEFAULT_ADMIN_ROLE — role-based (no per-NFT creator binding for the
    ///      registry, unlike GNUSLifecycle._requireCreatorOrAdmin). Reverts on unauthorized callers.
    /// @param sender The caller attempting the mutation.
    function _requireCreatorOrAdminRole(address sender) internal view {
        require(
            hasRole(_CREATOR_ROLE, sender) || hasRole(DEFAULT_ADMIN_ROLE, sender),
            _ERR_ONLY_CREATOR_OR_ADMIN
        );
    }

    /// @notice Create or update a SKU in the registry (D-04).
    /// @dev Writes GNUSLicensingStorage.layout().skus[skuId]. Credit SKUs driving PerHolder-expiry
    ///      credits must target tokens with a balance-removing disposition (D-17 — enforced at
    ///      purchase/config-of-lifecycle time, not here; this facet only owns the SKU record).
    /// @param skuId SKU id.
    /// @param sku SKU payload (exactly the seven D-04 fields).
    function configureSKU(uint256 skuId, SKU calldata sku) external {
        _requireCreatorOrAdminRole(msg.sender);
        require(sku.priceInMinions > 0, _ERR_PRICE_ZERO);
        require(sku.duration > 0, _ERR_DURATION_ZERO);
        require(!(sku.createsLicense && sku.renewsLicense), _ERR_SKU_MODE_CONFLICT);
        // Phase 14 gap-closure: a credit SKU must mint at least one leg (private or public).
        // License/renewal SKUs are unaffected (their credit fields are ignored, as today).
        if (!sku.createsLicense && !sku.renewsLicense) {
            require(sku.creditAmount + sku.publicCreditAmount > 0, _ERR_SKU_NO_CREDITS);
        }

        GNUSLicensingStorage.layout().skus[skuId] = sku;
        emit SKUConfigured(skuId, sku, msg.sender);
    }

    /// @notice Enable or disable a SKU without rewriting its payload (D-04).
    /// @dev Inactive SKUs stay stored and queryable; the purchase facet reverts on inactive SKUs.
    /// @param skuId SKU id.
    /// @param active New active state.
    function setSKUActive(uint256 skuId, bool active) external {
        _requireCreatorOrAdminRole(msg.sender);

        GNUSLicensingStorage.layout().skus[skuId].active = active;
        emit SKUActiveToggled(skuId, active, msg.sender);
    }

    /// @notice Read a SKU from the registry (D-04).
    /// @param skuId SKU id.
    /// @return The stored SKU payload (zero-initialized when never configured).
    function getSKU(uint256 skuId) external view returns (SKU memory) {
        return GNUSLicensingStorage.layout().skus[skuId];
    }
}
