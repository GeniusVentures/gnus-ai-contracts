// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/ERC1155Storage.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/extensions/ERC1155SupplyStorage.sol";
import "./GNUSERC1155MaxSupply.sol";
import "./GeniusAccessControl.sol";
import "./GNUSConstants.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSLifecycleStorage.sol";
import "./GNUSLifecycleTypes.sol";
import "./interfaces/ICredentialVerifier.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title GNUSLifecycleMint
/// @notice Time-bound ERC-1155 MINT & SETTLE facet (Phase 13, SC6, D3/D8/D9/D10).
/// @dev Plan 13-03 facet split: this facet owns the credential-gated mint path and the
///      settlement / renewal state transitions. Configuration and read paths live on the
///      sibling GNUSLifecycle facet. The two facets NEVER call each other — they share state
///      only through diamond storage. This facet READS the config written by GNUSLifecycle
///      (NFT struct lifecycle fields + GNUSLifecycleStorage caps/registry) and WRITES the
///      settlement / renewal / mint-enforcement state.
///
///      Storage discipline: this facet holds NO state of its own. It reads/writes:
///        - GNUSNFTFactoryStorage.layout().NFTs[id]   (lifecycle config fields, slots +8/+9/+10)
///        - GNUSLifecycleStorage.layout()             (per-holder clocks, mint caps, registry)
///
///      Reached ONLY via the diamond fallback (selector routing). No delegatecall / trampoline
///      anywhere — the diamond's fallback already routes by selector into shared storage.
///
///      Security:
///        - settleExpired is permissionless but fixed-outcome (D9) — no recipient parameter,
///          no caller-controlled value flow, disposition read from immutable config.
///        - mintWithCredential is the ONLY credential-gated issuance path. Legacy `mint` /
///          `mintBatch` on GNUSNFTFactory do NOT enforce the per-wallet cap or credential —
///          configured tokens are expected to use mintWithCredential (documented limitation).
///        - CEI ordering (T-13-03-01): the per-wallet cap EFFECT is written BEFORE the external
///          ICredentialVerifier call; the per-holder clock is cleared BEFORE any burn/transfer.
///
///      CAP-INCREMENT LOCATION (13-03 REPLAN ADDENDUM, locked 2026-08-23): the per-wallet cap
///      CHECK-AND-INCREMENT lives ONCE, in `GNUSERC1155MaxSupply._beforeTokenTransfer` (the mint
///      branch) — the SINGLE write point for mintedPerWallet across the whole codebase. This
///      facet's `_checkMintPolicy` does NOT write the cap (its increment was dropped when the
///      hook gate landed, so the lifecycle mint path — which funnels through `_mint` → the hook —
///      is not double-counted). `_checkMintPolicy` keeps only the sale-window check and the
///      credential-verifier call. The hook fires inline on every mint on BOTH the legacy factory
///      path and this facet's mint path (no delegatecall, no cross-facet call — the same
///      mechanism as the existing max-supply check and the withdraw-limiter charge).
///
///      Ordering note (accepted by user, 13-03 REPLAN ADDENDUM): the cap increment now lands
///      inside `_mint`'s hook (step 5 of mintWithCredential), which is AFTER the credential
///      `view` call (step 2). This is safe because `ICredentialVerifier.verify` is `view`
///      (STATICCALL) and cannot reenter-with-effect; the mock's `reenterMint` is a separate
///      non-view driver. Strict "cap-before-credential" ordering is traded away for a single
///      write point — accepted.
/// @custom:security-contact support@gnus.ai
contract GNUSLifecycleMint is GNUSERC1155MaxSupply, GeniusAccessControl {
    /// @notice Checks if the contract supports a specific interface.
    /// @dev Overrides the diamond-aware supportsInterface (matches GNUSNFTFactory.sol:129
    ///      and GNUSLifecycle.sol) — combines ERC1155 and AccessControlEnumerable interfaces
    ///      with any interfaces registered in the diamond's supportedInterfaces mapping.
    /// @param interfaceId The ID of the interface to check.
    /// @return True if the interface is supported.
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return (ERC1155Upgradeable.supportsInterface(interfaceId) || AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) ||
        (LibDiamond.diamondStorage().supportedInterfaces[interfaceId] == true));
    }

    /// @notice Emitted when a per-holder expiry clock is set or extended (D3).
    /// @param id Token id.
    /// @param holder The holder whose clock was updated.
    /// @param oldExpiry Previous expiry timestamp (0 if unset).
    /// @param newExpiry New expiry timestamp.
    event HolderExpiryUpdated(uint256 indexed id, address indexed holder, uint64 oldExpiry, uint64 newExpiry);

    /// @notice Emitted when settleExpired routes an expired balance to its disposition (D8/D9).
    /// @param account The holder whose expired balance was settled.
    /// @param id Token id.
    /// @param amount Minion amount moved (0 for NONE/KEEP_INERT).
    /// @param disposition The disposition that was applied.
    /// @param destination 0x0 for NONE/KEEP_INERT/BURN; recipient for RETURN_TO_ADDRESS;
    ///        account for REDEEM_TO_PARENT (parent minions minted back to the holder).
    event Settled(
        address indexed account,
        uint256 indexed id,
        uint256 amount,
        ExpirationDisposition disposition,
        address destination
    );

    /// @notice Mints a new NFT with an explicit credential for the token's credentialVerifier.
    /// @dev Phase 13 (D10) credential-gated mint path. Body order (locked, plan 13-03; cap
    ///      reconciliation per 13-03 REPLAN ADDENDUM):
    ///        (1) base mint requires (id != GNUS, to != 0, created, creator/admin, direct-child,
    ///            sufficient GNUS) — mirrors GNUSNFTFactory.beforeMint's 6 requires;
    ///        (2) _checkMintPolicy — sale window + credential verifier (cap NOT here — see below);
    ///        (3) _applyPerHolderRenewal — D3 settle-first renewal, PRE-MINT (Pitfall P5);
    ///        (4) _burn(sender, GNUS_TOKEN_ID, amount) — the caller pays id-0 minions 1:1;
    ///        (5) _mint(to, id, amount, data) — fires the _beforeTokenTransfer hook, which applies
    ///            the per-wallet cap CHECK-AND-INCREMENT (single write point, 13-03 REPLAN
    ///            ADDENDUM) and the validFrom mint gate.
    ///      For tokens with no verifier configured (credentialVerifier == 0) the credential is
    ///      ignored and minting is open (window + cap still enforced — the cap by the hook).
    /// @param to The address to mint the NFT to.
    /// @param id The ID of the NFT (must be a direct child of GNUS).
    /// @param amount The amount of id-0 minions to convert into child minions (1:1).
    /// @param data Additional data with no specified format.
    /// @param credential Opaque credential consumed by the token's credentialVerifier.
    function mintWithCredential(address to, uint256 id, uint256 amount, bytes memory data, bytes memory credential) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        address sender = _msgSender();
        // (1) Base mint requires (mirror GNUSNFTFactory.beforeMint).
        require(id != GNUS_TOKEN_ID, "Shouldn't mint GNUS tokens tokens, only deposit and withdraw");
        require(to != address(0), "ERC1155: mint to the zero address");
        require(nft.nftCreated, "Cannot mint NFT that doesn't exist");
        require((sender == nft.creator) || hasRole(DEFAULT_ADMIN_ROLE, sender), "Creator or Admin can only mint NFT");
        require((id >> 128) == GNUS_TOKEN_ID, "Direct children only; use convert() for descendants"); // D6 depth gate
        require(balanceOf(sender, GNUS_TOKEN_ID) >= amount, "Not enough GNUS_TOKEN to convert");
        // (2) Sale window + per-wallet cap (CEI) + credential verifier.
        _checkMintPolicy(to, id, amount, credential);
        // (3) D3 settle-first renewal BEFORE _mint (Pitfall P5 pre-mint balance semantics).
        _applyPerHolderRenewal(to, id, nft);
        // (4) Caller pays id-0 minions 1:1 (D1).
        _burn(sender, GNUS_TOKEN_ID, amount);
        // (5) Mint the child minions.
        _mint(to, id, amount, data);
    }

    /// @notice Phase 13 mint-policy gate: sale window + credential verifier.
    /// @dev Internal — callable only from this facet's mint path (attack surface closed).
    ///      Ordering:
    ///        1. Sale window: validFrom gate; PerTokenId validUntil as the sale end.
    ///        2. Credential verifier: the ONLY external interaction, performed LAST.
    ///      For tokens with zero-default lifecycle fields every gate is a no-op (legacy behavior).
    ///
    ///      CAP-INCREMENT LOCATION (13-03 REPLAN ADDENDUM, locked 2026-08-23): this function
    ///      does NOT write the per-wallet cap. The cap CHECK-AND-INCREMENT lives ONCE, in
    ///      `GNUSERC1155MaxSupply._beforeTokenTransfer` (the mint branch) — the SINGLE write
    ///      point. This facet's mint path calls `_mint` (step 5 of mintWithCredential), which
    ///      fires the hook inline and applies the cap CEI there. Keeping a second increment here
    ///      would double-count on the lifecycle path. The cap logic (including any read-only
    ///      defensive assert) is intentionally DROPPED from this function — the hook is the sole
    ///      owner. See the contract-level CAP-INCREMENT LOCATION paragraph.
    /// @param to The mint recipient (per-wallet cap is keyed by recipient, A7 — enforced in the hook).
    /// @param id The token id being minted.
    /// @param amount The minion amount being minted (cap arithmetic lives in the hook).
    /// @param credential Opaque credential forwarded to the verifier (empty = open mint).
    function _checkMintPolicy(address to, uint256 id, uint256 amount, bytes memory credential) internal {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];

        // (1) Sale window.
        require(nft.validFrom == 0 || block.timestamp >= nft.validFrom, "Sale not started");
        if (nft.expirationMode == uint8(ExpirationMode.PerTokenId)) {
            require(nft.validUntil == 0 || block.timestamp < nft.validUntil, "Sale ended");
        }

        // (2) Credential verifier — the ONLY external interaction, performed LAST.
        //      The per-wallet cap is enforced by the hook on _mint (single write point) — NOT
        //      here. See the Doxygen CAP-INCREMENT LOCATION paragraph above.
        if (nft.credentialVerifier != address(0)) {
            require(
                ICredentialVerifier(nft.credentialVerifier).verify(to, id, amount, credential),
                "Credential verification failed"
            );
        }
    }

    /// @notice Permissionless settlement of an expired (account, id) balance (D9).
    /// @dev Fixed-outcome: the caller cannot redirect value — disposition and recipient are
    ///      read from the immutable NFT config. Caller triggers the transition only.
    ///      Reverts when the pair is not expired (locked discretion; re-entry after a settle
    ///      that cleared the clock/balance will hit this "Not expired" revert, which is the
    ///      documented idempotency shape — second call reverts cleanly with no state change).
    ///
    ///      Zero-balance early return: when balanceOf(account, id) == 0 the function returns
    ///      without emitting — no burn/transfer/event for an empty pile (D9 idempotency).
    ///
    ///      CEI ordering (Pitfall P5 / T-13-02-04): for PerHolder mode, the per-holder clock
    ///      is cleared BEFORE any _burn/_safeTransferFrom so a re-entrant call from a
    ///      recipient hook sees a cleared clock and cannot double-settle.
    ///
    ///      No unbounded loops (D9): settles exactly one (account, id) pair per call.
    /// @param account The holder whose expired balance is being settled.
    /// @param id Token id.
    function settleExpired(address account, uint256 id) external {
        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        require(nft.nftCreated, "Token not created");
        require(_isExpired(account, id, nft), "Not expired");

        uint256 balance = balanceOf(account, id);
        if (balance == 0) {
            // D9 idempotency: nothing to settle on an empty pile.
            return;
        }

        // CEI: clear the per-holder clock BEFORE any state transition / external call.
        GNUSLifecycleStorage.Layout storage lc = GNUSLifecycleStorage.layout();
        if (nft.expirationMode == uint8(ExpirationMode.PerHolder)) {
            lc.holderExpiresAt[id][account] = 0;
        }

        _dispatchSettlement(account, id, balance, nft);
    }

    /// @notice D3 settle-first per-holder renewal (internal — runs on this facet's mint path).
    /// @dev MUST run BEFORE _mint (Pitfall P5): reads balanceOf(holder, id) as the PRE-MINT
    ///      balance. D3 semantics:
    ///        - Active balance (balance > 0 && existing > block.timestamp): stack — extend the
    ///          existing clock by nft.defaultDuration. The new purchase APPENDS time.
    ///        - Expired with pre-existing balance: settle the pre-existing pile FIRST via
    ///          _dispatchSettlement (the incoming mint is not part of that pile), then start a
    ///          fresh clock at now + defaultDuration. Expired balances are NEVER resurrected.
    ///        - Zero balance or no prior clock: start a fresh clock at now + defaultDuration.
    ///      Non-PerHolder tokens: early return — no clock is maintained for None/PerTokenId.
    /// @param holder The recipient of the upcoming mint (the wallet whose clock is updated).
    /// @param id Token id.
    /// @param nft The NFT storage record (read by the caller to avoid a second lookup).
    function _applyPerHolderRenewal(address holder, uint256 id, NFT storage nft) internal {
        if (nft.expirationMode != uint8(ExpirationMode.PerHolder)) {
            return;
        }

        GNUSLifecycleStorage.Layout storage lc = GNUSLifecycleStorage.layout();
        uint64 existing = lc.holderExpiresAt[id][holder];
        // PRE-MINT balance (this function runs BEFORE _mint — see Doxygen above).
        uint256 balance = balanceOf(holder, id);

        uint64 oldExpiry = existing;
        uint64 newExpiry;

        if (balance > 0 && existing > block.timestamp) {
            // Active balance: extend the existing clock (D3 first branch).
            newExpiry = existing + nft.defaultDuration;
            lc.holderExpiresAt[id][holder] = newExpiry;
        } else {
            // Expired or zero balance: settle expired pre-existing balance FIRST (D3 second
            // branch), then start a new clock from now. The settle uses `balance` (pre-mint)
            // directly — the incoming mint amount is NOT part of the expired pile.
            if (existing != 0 && existing <= block.timestamp && balance > 0) {
                // CEI: clear the clock before the disposition transition.
                lc.holderExpiresAt[id][holder] = 0;
                _dispatchSettlement(holder, id, balance, nft);
            }
            newExpiry = uint64(block.timestamp) + nft.defaultDuration;
            lc.holderExpiresAt[id][holder] = newExpiry;
        }

        emit HolderExpiryUpdated(id, holder, oldExpiry, newExpiry);
    }

    /// @notice Shared disposition dispatch used by settleExpired and _applyPerHolderRenewal.
    /// @dev Single source of truth for the five-disposition routing (13-RESEARCH §P5:
    ///      "single biggest risk is introducing a parallel enforcement path that drifts").
    ///      Caller must have already cleared any per-holder clock (CEI).
    ///
    ///      Dispositions (D8):
    ///        NONE              → emit only; balance untouched, entitlement off
    ///        KEEP_INERT        → emit only; balance stays (collectible), entitlement off
    ///        BURN              → _burn(account, id, balance); AI Credits path (D11)
    ///        RETURN_TO_ADDRESS → _safeTransferFrom to nft.expirationRecipient (fixed, D8)
    ///        REDEEM_TO_PARENT  → _settleRedeemToParent(account, id, nft.parentId, balance) (Q3)
    /// @param account The holder whose expired balance is being settled.
    /// @param id Token id.
    /// @param balance Pre-read balanceOf(account, id) — the full expired pile to settle.
    /// @param nft The NFT storage record (disposition + recipient read from immutable config).
    function _dispatchSettlement(address account, uint256 id, uint256 balance, NFT storage nft) internal {
        if (nft.expirationDisposition == uint8(ExpirationDisposition.NONE)) {
            // Balance untouched, entitlement off. No state transition.
            emit Settled(account, id, 0, ExpirationDisposition.NONE, address(0));
            return;
        }
        if (nft.expirationDisposition == uint8(ExpirationDisposition.KEEP_INERT)) {
            // Balance stays (collectible), entitlement off.
            emit Settled(account, id, 0, ExpirationDisposition.KEEP_INERT, address(0));
            return;
        }
        if (nft.expirationDisposition == uint8(ExpirationDisposition.BURN)) {
            // Expired units destroyed, no value returned. AI Credits path (D11).
            _burn(account, id, balance);
            emit Settled(account, id, balance, ExpirationDisposition.BURN, address(0));
            return;
        }
        if (nft.expirationDisposition == uint8(ExpirationDisposition.RETURN_TO_ADDRESS)) {
            // Fixed recipient only (D8). Never an inferred sender, never caller-supplied (P9).
            address recipient = nft.expirationRecipient;
            require(recipient != address(0), "No expiration recipient configured");
            _safeTransferFrom(account, recipient, id, balance, "");
            emit Settled(account, id, balance, ExpirationDisposition.RETURN_TO_ADDRESS, recipient);
            return;
        }
        if (nft.expirationDisposition == uint8(ExpirationDisposition.REDEEM_TO_PARENT)) {
            // Q3 no-custody settle pair — see _settleRedeemToParent.
            uint256 parentId = nft.parentId; // Phase 9 D7 field (recorded at creation)
            _settleRedeemToParent(account, id, parentId, balance);
            emit Settled(account, id, balance, ExpirationDisposition.REDEEM_TO_PARENT, account);
            return;
        }
    }

    /// @notice Q3 no-custody settlement into the direct parent token.
    /// @dev Direct `_burn(account, id, amount)` + `_mint(account, parentId, amount, "")` pair —
    ///      tokens never touch the diamond contract address (Phase 10 no-custody invariant,
    ///      GNUSRedeemAdapter.redeem precedent). Supply-neutral reallocation: minions are
    ///      conserved across the burn/mint pair (Phase 9 D1 1:1 model). Does NOT call
    ///      GNUSTreasury.convert — convert burns from _msgSender() and would target the
    ///      permissionless caller, not `account`.
    /// @param account The holder whose expired child balance is burned and re-minted as parent.
    /// @param id Expired child token id.
    /// @param parentId Direct parent token id (NFT.parentId, Phase 9 D7).
    /// @param amount Minion amount to move 1:1 child → parent.
    function _settleRedeemToParent(address account, uint256 id, uint256 parentId, uint256 amount) internal {
        require(parentId != id, "Invalid parent");
        _burn(account, id, amount);
        _mint(account, parentId, amount, "");
    }

    /// @notice Internal expiry predicate (D2).
    /// @dev KEEP IN SYNC with GNUSLifecycle._isExpired — duplicated here as a small internal
    ///      view (the two facets never call each other; the alternative — a shared base —
    ///      reintroduces the coupling the plan 13-03 facet split removes). Returns true when the
    ///      (account, id) pair is past its expiration point under the token's expirationMode:
    ///        - None       → false (never expires)
    ///        - PerTokenId → validUntil != 0 && block.timestamp >= validUntil (shared window)
    ///        - PerHolder  → holderExpiresAt[id][account] != 0 && block.timestamp >= expiry
    ///      A PerHolder clock of 0 is treated as "not expired" — never minted to this holder,
    ///      or already settled.
    /// @param account The holder being checked.
    /// @param id Token id.
    /// @param nft The NFT storage record.
    /// @return True when the (account, id) pair is expired.
    function _isExpired(address account, uint256 id, NFT storage nft) internal view returns (bool) {
        if (nft.expirationMode == uint8(ExpirationMode.None)) {
            return false;
        }
        if (nft.expirationMode == uint8(ExpirationMode.PerTokenId)) {
            return nft.validUntil != 0 && block.timestamp >= nft.validUntil;
        }
        // PerHolder
        uint64 expiry = GNUSLifecycleStorage.layout().holderExpiresAt[id][account];
        return expiry != 0 && block.timestamp >= expiry;
    }
}
