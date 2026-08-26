// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/token/ERC20/IERC20Upgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC20/ERC20Storage.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSLicensingStorage.sol";
import "./GNUSLicensingTypes.sol";
import "./GNUSLifecycleStorage.sol";
import "./GNUSLifecycleTypes.sol";
import "./GNUSTreasuryStorage.sol";
import "./interfaces/ICredentialVerifier.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title GNUSLicensingPurchase
/// @notice Private-network AI licensing PURCHASE / LICENSE-CREATION / RENEWAL facet
///         (Phase 14 plan 14-03, LIC-04 per D-26/D-10, LIC-01, LIC-05).
/// @dev Plan 14-02 facet split sibling of GNUSLicensing: this facet owns the money-touching
///      action surface (permissionless purchase + renewal, operator license creation); SKU
///      configuration lives on GNUSLicensing. The two facets NEVER call each other — they share
///      state only through diamond storage (GNUSLicensingStorage SKU registry). This facet also
///      NEVER calls GNUSLifecycle / GNUSLifecycleMint (13-03 facet split discipline): the mint
///      leg routes through the shared internal `_mint` → `_beforeTokenTransfer` hook, so
///      GNUSLifecyclePolicy.enforceMintGate applies max-supply, validFrom window, PerTokenId
///      "Sale ended", and the per-wallet mint cap on EVERY purchase mint (single write point,
///      13-03 REPLAN ADDENDUM). Small predicates duplicated from the lifecycle facets
///      (creation-path body, D3 renewal clock) follow the GNUSLifecycleMint._isExpired
///      duplication precedent — "the two facets never call each other".
///
///      PAYMENT (D-10): the paid GNUS is BURNED. The buyer pulls via the ERC-20 allowance
///      (spender = the diamond) and the id-0 balance is burned DIRECTLY from the buyer through
///      the ERC-1155 burn machinery with the GNUSBridge.burn globalSupply/chainSupply
///      decrements — totalSupply decreases by exactly priceInMinions. No diamond custody at
///      any point (Phase 10 no-custody invariant), so the withdrawal limiter charges only the
///      buyer (mintWithCredential precedent) and the diamond address never accumulates limiter
///      debt. NOT the treasury conversion path (supply-neutral — Pitfall 5).
///
///      Security (plan 14-03 threat model):
///        - T-14-03-01: payment pulled from msg.sender via allowance; mint destination is the
///          caller-chosen deviceWallet (D-19) but SOULBOUND policy makes credits unsellable.
///        - T-14-03-02: renewal extends validUntil only to max(current, now) + duration via an
///          active renewsLicense SKU governing that license; LicenseActivated re-emitted.
///        - T-14-03-04: createLicense is CREATOR_ROLE/ADMIN-gated (D-12); permissionless
///          surface is limited to credit top-up + renewal (D-27).
///        - CEI: allowance/state effects precede the mint; the per-holder clock is cleared
///          before any settle dispatch (Pitfall P5).
/// @custom:security-contact support@gnus.ai
contract GNUSLicensingPurchase is GNUSERC1155MaxSupply, GeniusAccessControl, IGNUSLicensingEvents {
    /// @dev Role identifier for creators — identical value to GNUSNFTFactory.CREATOR_ROLE
    ///      (keccak256("CREATOR_ROLE")). Re-declared locally (GNUSLifecycle.sol:36 precedent)
    ///      to avoid the circular import.
    bytes32 private constant _CREATOR_ROLE = keccak256("CREATOR_ROLE");

    // ---- Validation revert reasons — named constants (no magic strings) ----
    string private constant _ERR_SKU_INACTIVE = "SKU inactive";
    string private constant _ERR_NOT_CREDIT_SKU = "SKU does not mint credits";
    string private constant _ERR_NOT_LICENSE_SKU = "SKU does not create licenses";
    string private constant _ERR_NOT_RENEWAL_SKU = "SKU does not renew licenses";
    string private constant _ERR_LICENSE_NOT_CREATED = "License not created";
    string private constant _ERR_CREDIT_TOKEN_MISSING = "Credit token not created";
    string private constant _ERR_INSUFFICIENT_ALLOWANCE = "ERC20: insufficient allowance";
    string private constant _ERR_ONLY_CREATORS_OR_ADMINS = "Only Creators or Admins can create NFT child of GNUS";
    string private constant _ERR_TOKEN_COLLISION = "Token ID collision";
    string private constant _ERR_INVALID_SCOPE = "Invalid networkScope";
    string private constant _ERR_CREDENTIAL_FAILED = "Credential verification failed";

    /// @dev License NFTs are namespace-only records (D-20) — nothing in this facet mints
    ///      license units, but hybrid-scope children (D-05) redeem INTO the license token via
    ///      REDEEM_TO_PARENT, and that parent-mint leg still runs the hook's hard max-supply
    ///      check (WR-04: only the window/cap are carved out). Keep redemption headroom.
    uint256 private constant _LICENSE_MAX_SUPPLY = 1_000_000 * GNUS_DECIMALS;
    /// @dev Company credit tokens are the FIRST child created under the license NFT (D-02
    ///      hierarchy: GNUS root → license → company credits).
    uint256 private constant _FIRST_CHILD_INDEX = 0;

    // ---- Topic-equal event re-declarations (single ABI surface across facets) ----
    // NOTE (facet split): these mirror the declarations on GNUSLifecycle / GNUSLifecycleMint
    // with IDENTICAL signatures — the diamond ABI sees one event; indexers cannot tell which
    // facet emitted (createNFTWithLifecycle's "topic-equal" LifecycleConfigured precedent).

    /// @notice Emitted when a token's lifecycle configuration is written (topic-equal to
    ///         GNUSLifecycle.LifecycleConfigured).
    event LifecycleConfigured(uint256 indexed id, LifecycleConfig cfg, address indexed operator);

    /// @notice Emitted when a per-holder expiry clock is set or extended (topic-equal to
    ///         GNUSLifecycleMint.HolderExpiryUpdated).
    event HolderExpiryUpdated(uint256 indexed id, address indexed holder, uint64 oldExpiry, uint64 newExpiry);

    /// @notice Emitted when an expired balance is routed to its disposition (topic-equal to
    ///         GNUSLifecycleMint.Settled).
    event Settled(
        address indexed account,
        uint256 indexed id,
        uint256 amount,
        ExpirationDisposition disposition,
        address destination
    );

    /// @notice ERC-20 Transfer event for the payment-burn leg (topic-equal to
    ///         IERC20Upgradeable.Transfer — Solidity 0.8.19 cannot emit through a qualified
    ///         interface name, so the identical signature is declared locally).
    event Transfer(address indexed from, address indexed to, uint256 value);

    /// @notice ERC-20 Approval event for the allowance spend (topic-equal to
    ///         IERC20Upgradeable.Approval — declared locally, same reason as Transfer).
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// @notice Checks if the contract supports a specific interface.
    /// @dev Diamond-aware triple-OR override (matches GNUSLifecycle.sol:45-48).
    /// @param interfaceId The ID of the interface to check.
    /// @return True if the interface is supported.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) || AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
        (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /// @notice Permissionless credit top-up: burn GNUS payment, mint credits into a device wallet (D-27/D-19/D-10).
    /// @dev Credit SKUs only (`!createsLicense && !renewsLicense`, active). Body order (CEI):
    ///        (1) SKU + token existence checks;
    ///        (2) credential verifier check when the credit token configures one (empty
    ///            credential — permissionless surface, D-27; a verifier that requires a
    ///            credential simply rejects the purchase);
    ///        (3) payment leg — ERC-20 allowance pull + DIRECT buyer burn (D-10,
    ///            totalSupply decreases by exactly priceInMinions);
    ///        (4) D3 settle-first per-holder renewal (PRE-mint balance semantics, Pitfall P5)
    ///            — a credit top-up gets the renewal free (Pitfall 6);
    ///        (5) `_mint` — the shared hook applies max-supply, validFrom, PerTokenId
    ///            "Sale ended", and the per-wallet mint cap (single write point).
    /// @param skuId Credit SKU id (must be active, non-license, non-renewal).
    /// @param licenseId License NFT id whose first child is the company credit token (D-02).
    /// @param deviceWallet Embedded device wallet receiving the credits (D-19).
    function purchaseCredits(uint256 skuId, uint256 licenseId, address deviceWallet) external {
        GNUSLicensingStorage.Layout storage ls = GNUSLicensingStorage.layout();
        SKU storage sku = ls.skus[skuId];
        require(sku.active, _ERR_SKU_INACTIVE);
        require(!sku.createsLicense && !sku.renewsLicense, _ERR_NOT_CREDIT_SKU);
        require(deviceWallet != address(0), "ERC1155: mint to the zero address");

        // D-02 hierarchy: company credits are the first child of the license NFT.
        uint256 creditTokenId = (licenseId << 128) | _FIRST_CHILD_INDEX;
        NFT storage licenseNft = GNUSNFTFactoryStorage.layout().NFTs[licenseId];
        require(licenseNft.nftCreated, _ERR_LICENSE_NOT_CREATED);
        NFT storage creditNft = GNUSNFTFactoryStorage.layout().NFTs[creditTokenId];
        require(creditNft.nftCreated, _ERR_CREDIT_TOKEN_MISSING);

        // Credential gate (mirror of _checkMintPolicy's verifier leg — the window/cap gates
        // fire on _mint via the shared hook).
        if (creditNft.credentialVerifier != address(0)) {
            require(
                ICredentialVerifier(creditNft.credentialVerifier).verify(deviceWallet, creditTokenId, sku.creditAmount, ""),
                _ERR_CREDENTIAL_FAILED
            );
        }

        // Payment leg (D-10): burn priceInMinions of id-0 GNUS from the buyer.
        _burnPayment(_msgSender(), sku.priceInMinions);

        // D3 renewal clock (PRE-mint balance — must run before _mint, Pitfall P5).
        _applyCreditRenewal(deviceWallet, creditTokenId, creditNft);

        // Mint through the shared hook: max-supply + validFrom + "Sale ended" + per-wallet cap.
        _mint(deviceWallet, creditTokenId, sku.creditAmount, "");
    }

    /// @notice License creation calldata (bundled — the flat 8-arg signature overflows the
    ///         Solidity 0.8.19 stack; D-18 forbids viaIR).
    /// @dev Field semantics identical to the flat parameters they replace.
    struct LicenseCreateParams {
        string name;               ///< License token name.
        string symbol;             ///< License token symbol.
        string newuri;             ///< License metadata URI.
        address companyAdmin;      ///< D-25 operator-set config field — data only, no governance (D-20).
        uint256 privateNetworkId;  ///< D-03 SuperGenius private network id.
        uint8 networkScope;        ///< D-03 NetworkScope ordinal.
        bool publicSettlementEnabled; ///< D-08 informational SG-side flag — gates nothing on-chain.
    }

    /// @notice Operator license creation (CREATOR_ROLE/ADMIN, D-12): License NFT as a direct
    ///         child of the GNUS product root with PerTokenId validUntil from the SKU duration (D-12).
    /// @dev Replicates the GNUSLifecycle.createNFTWithLifecycle creation path inline (facet
    ///      split: sibling facets never call each other; _isExpired duplication precedent).
    ///      License shape (D-12/D-20/D-25): PerTokenId + SOULBOUND + BURN disposition
    ///      (burn-only namespace record, nonConvertible at creation per D11 mapping);
    ///      exchangeRate 0 (namespace-only, D-20). Phase 14 fields (companyAdmin,
    ///      privateNetworkId, networkScope, publicSettlementEnabled) are set from calldata.
    ///      Emits topic-equal LifecycleConfigured, stores licenseSku, and emits LicenseActivated
    ///      (D-14 field order) — the SOLE SuperGenius-side license-state source.
    /// @param skuId License SKU id (active, createsLicense).
    /// @param params Bundled license metadata + Phase 14 fields (see LicenseCreateParams).
    /// @return licenseId The new license token id.
    function createLicense(uint256 skuId, LicenseCreateParams calldata params)
        external
        returns (uint256 licenseId)
    {
        address sender = _msgSender();
        require(hasRole(DEFAULT_ADMIN_ROLE, sender) || hasRole(_CREATOR_ROLE, sender), _ERR_ONLY_CREATORS_OR_ADMINS);
        require(params.networkScope <= uint8(NetworkScope.Hybrid), _ERR_INVALID_SCOPE);

        uint64 duration;
        {
            SKU storage sku = GNUSLicensingStorage.layout().skus[skuId];
            require(sku.active && sku.createsLicense, _ERR_NOT_LICENSE_SKU);
            duration = sku.duration;
        }

        licenseId = _createLicenseNft(params.name, params.symbol, params.newuri, sender, _licenseConfig(duration));

        _finalizeLicense(
            licenseId,
            skuId,
            params.companyAdmin,
            params.privateNetworkId,
            params.networkScope,
            params.publicSettlementEnabled
        );
    }

    /// @notice The D-12 license LifecycleConfig (PerTokenId + SOULBOUND + BURN, SKU duration).
    /// @dev Split out of createLicense purely for the 0.8.19 stack budget (no viaIR, D-18).
    ///      BURN disposition forces burn-only namespace semantics (D11 mapping).
    /// @param duration SKU entitlement duration in seconds.
    /// @return The assembled LifecycleConfig.
    function _licenseConfig(uint64 duration) internal view returns (LifecycleConfig memory) {
        return LifecycleConfig({
            validFrom: 0,
            validUntil: uint64(block.timestamp) + duration,
            defaultDuration: duration,
            expirationMode: uint8(ExpirationMode.PerTokenId),
            transferPolicy: uint8(TransferPolicy.SOULBOUND),
            expirationDisposition: uint8(ExpirationDisposition.BURN),
            expirationRecipient: address(0),
            credentialVerifier: address(0)
        });
    }

    /// @notice Post-creation license finalization: Phase 14 fields + SKU link + LicenseActivated.
    /// @dev Split out of createLicense purely for the 0.8.19 stack budget (no viaIR, D-18).
    /// @param licenseId The freshly created license token id.
    /// @param skuId The governing license SKU id.
    /// @param companyAdmin Company admin config field (D-25).
    /// @param privateNetworkId SuperGenius private network id (D-03).
    /// @param networkScope NetworkScope ordinal (D-03).
    /// @param publicSettlementEnabled Informational SG-side flag (D-08).
    function _finalizeLicense(
        uint256 licenseId,
        uint256 skuId,
        address companyAdmin,
        uint256 privateNetworkId,
        uint8 networkScope,
        bool publicSettlementEnabled
    ) internal {
        NFT storage newNft = GNUSNFTFactoryStorage.layout().NFTs[licenseId];
        newNft.companyAdmin = companyAdmin;                       // D-25 - operator-set config field
        newNft.privateNetworkId = privateNetworkId;               // D-03
        newNft.networkScope = networkScope;                       // D-03
        newNft.publicSettlementEnabled = publicSettlementEnabled; // D-08 - informational only
        uint64 expiresAt = newNft.validUntil;

        GNUSLicensingStorage.layout().licenseSku[licenseId] = skuId;

        // D-14 field order — the SG cross-system contract; do NOT reorder.
        emit LicenseActivated(companyAdmin, licenseId, privateNetworkId, expiresAt);
    }

    /// @notice Permissionless license renewal (D-27): burn payment, extend PerTokenId validUntil (LIC-05).
    /// @dev Requires an ACTIVE renewsLicense SKU (any such SKU may renew any license — the
    ///      operator-controlled SKU payload decides price and duration; T-14-03-02: the
    ///      extension surface is exactly `max(current, block.timestamp) + sku.duration`, never
    ///      caller-supplied). The extension is internal against storage — the role-gated
    ///      setValidUntil external setter is NOT widened (analog's internal-only discipline).
    ///      LicenseActivated is re-emitted with the extended expiry (LIC-05) and the stored
    ///      companyAdmin/privateNetworkId (D-14/D-25).
    /// @param skuId Renewal SKU id (active, renewsLicense).
    /// @param licenseId License token id.
    function renewLicense(uint256 skuId, uint256 licenseId) external {
        SKU storage sku = GNUSLicensingStorage.layout().skus[skuId];
        require(sku.active && sku.renewsLicense, _ERR_NOT_RENEWAL_SKU);

        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[licenseId];
        require(nft.nftCreated, _ERR_LICENSE_NOT_CREATED);

        // Payment leg (D-10) FIRST — no extension without the burn.
        _burnPayment(_msgSender(), sku.priceInMinions);

        // T-14-03-02: stack from the LATER of the current expiry and now — an expired license
        // renewed late buys a full duration from today, never retroactive time.
        uint64 base = nft.validUntil > block.timestamp ? nft.validUntil : uint64(block.timestamp);
        uint64 newExpiry = base + sku.duration;
        nft.validUntil = newExpiry;

        emit LicenseActivated(nft.companyAdmin, licenseId, nft.privateNetworkId, newExpiry);
    }

    /// @notice Base license-record creation (createNFTWithLifecycle GNUS-root branch, inline).
    /// @dev Derives the direct-child id, performs the D7 collision check, writes the base
    ///      NFT record (namespace-only shape: exchangeRate 0 per D-20, burn-only namespace per
    ///      the D11 BURN-disposition mapping), and emits the topic-equal LifecycleConfigured.
    ///      The Phase 14 fields are written by the caller from calldata.
    /// @param name License token name.
    /// @param symbol License token symbol.
    /// @param newuri License metadata URI.
    /// @param sender The creator/admin caller (recorded as the NFT creator).
    /// @param cfg The PerTokenId license LifecycleConfig.
    /// @return licenseId The new license token id.
    function _createLicenseNft(
        string calldata name,
        string calldata symbol,
        string calldata newuri,
        address sender,
        LifecycleConfig memory cfg
    ) internal returns (uint256 licenseId) {
        GNUSNFTFactoryStorage.Layout storage fstore = GNUSNFTFactoryStorage.layout();
        uint256 childIndex = fstore.NFTs[GNUS_TOKEN_ID].childCurIndex;
        licenseId = (GNUS_TOKEN_ID << 128) | childIndex;
        require(!fstore.NFTs[licenseId].nftCreated, _ERR_TOKEN_COLLISION); // D7
        fstore.NFTs[GNUS_TOKEN_ID].childCurIndex = uint128(childIndex + 1);

        NFT storage newNft = fstore.NFTs[licenseId];
        newNft.name = name;
        newNft.symbol = symbol;
        newNft.exchangeRate = 0; // namespace-only (D-20)
        newNft.maxSupply = _LICENSE_MAX_SUPPLY;
        newNft.uri = newuri;
        newNft.creator = sender;
        newNft.childCurIndex = 0;
        newNft.nftCreated = true;
        newNft.parentId = GNUS_TOKEN_ID;      // D7 - recorded, not derived
        newNft.nonConvertible = true;         // D11 mapping: BURN disposition → burn-only
        newNft.validFrom = cfg.validFrom;
        newNft.validUntil = cfg.validUntil;
        newNft.defaultDuration = cfg.defaultDuration;
        newNft.expirationMode = cfg.expirationMode;
        newNft.transferPolicy = cfg.transferPolicy;
        newNft.expirationDisposition = cfg.expirationDisposition;
        newNft.expirationRecipient = cfg.expirationRecipient;
        newNft.credentialVerifier = cfg.credentialVerifier;

        emit LifecycleConfigured(licenseId, cfg, sender);
    }

    /// @notice Payment leg (D-10): ERC-20 allowance pull + direct id-0 burn from the buyer.
    /// @dev The diamond is the spender (purchase executes in the diamond context). The burn
    ///      follows the GNUSBridge.burn pattern verbatim (ERC-1155 `_burn` +
    ///      globalSupply/chainSupply decrements + ERC-20 Transfer event) so
    ///      `totalSupply(GNUS_TOKEN_ID)` decreases by exactly `amount`. Burning directly from
    ///      the buyer (rather than transferring to the diamond first) keeps zero diamond
    ///      custody (Phase 10 invariant) and charges the withdraw limiter only against the
    ///      buyer — the diamond address never accumulates limiter debt (mintWithCredential
    ///      precedent). NOT the treasury conversion path (supply-neutral — Pitfall 5).
    /// @param buyer The purchasing caller whose allowance is spent and whose GNUS is burned.
    /// @param amount priceInMinions to burn.
    function _burnPayment(address buyer, uint256 amount) internal {
        // ERC-20 allowance pull (spender = the diamond).
        uint256 currentAllowance = ERC20Storage.layout()._allowances[buyer][address(this)];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, _ERR_INSUFFICIENT_ALLOWANCE);
            ERC20Storage.layout()._allowances[buyer][address(this)] = currentAllowance - amount;
            emit Approval(buyer, address(this), currentAllowance - amount);
        }

        // ERC-1155 id-0 burn from the buyer (GNUSBridge.burn pattern).
        _burn(buyer, GNUS_TOKEN_ID, amount);
        GNUSTreasuryStorage.Layout storage t = GNUSTreasuryStorage.layout();
        require(t.globalSupply >= amount, "Burn exceeds global supply");
        require(t.chainSupply[block.chainid] >= amount, "Burn exceeds chain supply");
        t.globalSupply -= amount;
        t.chainSupply[block.chainid] -= amount;
        emit Transfer(buyer, address(0), amount);
    }

    /// @notice D3 settle-first per-holder renewal for purchase mints (compact duplicate of
    ///         GNUSLifecycleMint._applyPerHolderRenewal — facet-split duplication precedent).
    /// @dev MUST run BEFORE _mint (Pitfall P5 — reads the PRE-mint balance). Semantics:
    ///        - Active balance: stack — extend the existing clock by defaultDuration.
    ///        - Expired with pre-existing balance: settle FIRST (never resurrect, D17), then
    ///          start a fresh clock at now + defaultDuration.
    ///        - Zero balance / no clock: fresh clock at now + defaultDuration.
    ///      Non-PerHolder tokens: early return.
    /// @param holder The mint recipient (device wallet) whose clock is updated.
    /// @param id The credit token id.
    /// @param nft The credit token storage record.
    function _applyCreditRenewal(address holder, uint256 id, NFT storage nft) internal {
        if (nft.expirationMode != uint8(ExpirationMode.PerHolder)) {
            return;
        }

        GNUSLifecycleStorage.Layout storage lc = GNUSLifecycleStorage.layout();
        uint64 existing = lc.holderExpiresAt[id][holder];
        uint256 balance = balanceOf(holder, id);

        uint64 oldExpiry = existing;
        uint64 newExpiry;

        if (balance > 0 && existing > block.timestamp) {
            // Active balance: extend the existing clock (D3 first branch).
            newExpiry = existing + nft.defaultDuration;
        } else {
            if (existing != 0 && existing <= block.timestamp && balance > 0) {
                // CEI: clear the clock before the disposition transition (Pitfall P5).
                lc.holderExpiresAt[id][holder] = 0;
                _dispatchCreditSettlement(holder, id, balance, nft);
            }
            newExpiry = uint64(block.timestamp) + nft.defaultDuration;
        }
        lc.holderExpiresAt[id][holder] = newExpiry;

        emit HolderExpiryUpdated(id, holder, oldExpiry, newExpiry);
    }

    /// @notice Compact disposition dispatch for the purchase-path settle-first branch.
    /// @dev Same routing as GNUSLifecycleMint._dispatchSettlement for the dispositions legal
    ///      on PerHolder tokens (D17 config gate excludes NONE/KEEP_INERT — those are handled
    ///      defensively as inert). NONE and KEEP_INERT fall through inert because they are
    ///      unreachable for a compliant PerHolder credit token.
    /// @param account The holder whose expired balance is settled.
    /// @param id The credit token id.
    /// @param balance PRE-mint expired balance.
    /// @param nft The credit token storage record.
    function _dispatchCreditSettlement(address account, uint256 id, uint256 balance, NFT storage nft) internal {
        if (nft.expirationDisposition == uint8(ExpirationDisposition.BURN)) {
            _burn(account, id, balance);
            emit Settled(account, id, balance, ExpirationDisposition.BURN, address(0));
            return;
        }
        if (nft.expirationDisposition == uint8(ExpirationDisposition.RETURN_TO_ADDRESS)) {
            address recipient = nft.expirationRecipient;
            require(recipient != address(0), "No expiration recipient configured");
            _safeTransferFrom(account, recipient, id, balance, "");
            emit Settled(account, id, balance, ExpirationDisposition.RETURN_TO_ADDRESS, recipient);
            return;
        }
        if (nft.expirationDisposition == uint8(ExpirationDisposition.REDEEM_TO_PARENT)) {
            uint256 parentId = nft.parentId;
            require(parentId != id, "Invalid parent");
            // WR-04 carve-out: redemption mint must bypass the parent's window/cap (same
            // transient-flag mechanism as GNUSLifecycleMint._settleRedeemToParent).
            GNUSLifecycleStorage.layout().settleRedeemMintActive = true;
            _burn(account, id, balance);
            _mint(account, parentId, balance, "");
            GNUSLifecycleStorage.layout().settleRedeemMintActive = false;
            emit Settled(account, id, balance, ExpirationDisposition.REDEEM_TO_PARENT, account);
            return;
        }
        // NONE / KEEP_INERT: inert (unreachable for compliant PerHolder configs, D17).
        emit Settled(account, id, 0, ExpirationDisposition(nft.expirationDisposition), address(0));
    }
}
