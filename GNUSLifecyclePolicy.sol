// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/access/AccessControlStorage.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/extensions/ERC1155SupplyStorage.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSLifecycleStorage.sol";
import "./GNUSLifecycleTypes.sol";
import "./GNUSConstants.sol";
import "./interfaces/IAllowlistRegistry.sol";

/// @title GNUSLifecyclePolicy
/// @notice Phase 13 (13-04) compile-time-linked Solidity library carrying the transfer-policy
///         predicate and the mint-window + per-wallet-cap gate extracted out of
///         GNUSERC1155MaxSupply for EIP-170 headroom (GNUSNFTFactory was 26,372 B — over the
///         24,576 B limit by 1,796 B — with the predicate inlined; the library relocation brings
///         every inheriting facet back under the limit).
/// @dev LINKING MODEL: `public` library functions compile to an external DELEGATECALL stub to a
///      fixed pure-code contract address baked in at link time — standard Solidity library
///      linking (Option A, confirmed with the user 2026-08-23). The library is a pure-code
///      contract deployed once per network and LINKED into each facet at deploy time; it is NOT
///      a diamond facet and is NOT registered in geniusdiamond.config.json (no selectors, no
///      state of its own, no selector-routing trampoline). The no-delegatecall rule from the
///      13-03 replan targeted the hand-rolled facet-delegation selector trampoline — NOT
///      standard libraries. The library address is wired into facet bytecode at deploy time by
///      the deployment harness (see scripts/utils/GNUSLifecyclePolicyLinking.ts).
///
///      STORAGE CONTEXT: library code executes in the CALLING facet's storage context via
///      DELEGATECALL, so every read/write below (GNUSNFTFactoryStorage, GNUSLifecycleStorage,
///      AccessControlStorage, ERC1155SupplyStorage) resolves against the SAME diamond-shared
///      storage slots the calling facet itself would touch — identical semantics to the
///      previous inlined bodies (same mechanism as GNUSControlStorage.isBannedTransferor).
///
///      EIP-170 EFFECT: the DELEGATECALL stub keeps the policy bodies OUT of every inheriting
///      facet. With the bodies inlined in GNUSERC1155MaxSupply, GNUSNFTFactory measured
///      26,372 B (1,796 B over the 24,576 B limit); the library stub brings every facet under.
///
///      `totalSupply` is NOT passed as a callback. The max-supply check reads
///      `ERC1155SupplyStorage.layout()._totalSupply[id]` directly — the same diamond-shared slot
///      `ERC1155SupplyUpgradeable.totalSupply(id)` reads — so no function-pointer indirection is
///      needed and no inheritance surface is added to the shared base.
///
///      NO operator exemptions (Pitfall P2 / T-13-04-01): this library NEVER reads the
///      proxy-operator marketplace role or any approval state.
library GNUSLifecyclePolicy {
    /// @notice Mint-branch window + cap gate (13-03 REPLAN ADDENDUM) + max-supply check.
    /// @dev Body relocated VERBATIM from GNUSERC1155MaxSupply._beforeTokenTransfer's mint branch
    ///      (the block previously guarded by `if (isMinting)`), with the totalSupply read swapped
    ///      for the equivalent ERC1155SupplyStorage.layout()._totalSupply[id] slot read (see the
    ///      library-level note — same slot, no behavior change).
    ///
    ///      SINGLE WRITE POINT for mintedPerWallet across the whole codebase (CEI: the require
    ///      precedes the single storage write). GNUSLifecycleMint._checkMintPolicy does NOT write
    ///      the cap — both the legacy GNUSNFTFactory.mint path and the
    ///      GNUSLifecycleMint.mintWithCredential path funnel through _mint → the calling facet's
    ///      _beforeTokenTransfer hook → this function, so the cap fires on BOTH paths with no
    ///      double-count.
    /// @param id The token id being minted.
    /// @param to The mint recipient (per-wallet cap is keyed by recipient, A7).
    /// @param amount The amount being minted.
    function enforceMintGate(uint256 id, address to, uint256 amount) public {
        NFT storage nftMint = GNUSNFTFactoryStorage.layout().NFTs[id];
        require(
            ERC1155SupplyStorage.layout()._totalSupply[id] <= nftMint.maxSupply,
            "Max Supply for NFT would be exceeded"
        );

        // Sale-window gate on the mint path (13-03 REPLAN ADDENDUM). Load-bearing on the LEGACY
        // factory mint/mintBatch path (the mint facet has its own "Sale not started" check in
        // _checkMintPolicy; this is the hook-level defense-in-depth AND the legacy-path gate).
        // WR-04 (13 review): REDEEM_TO_PARENT settlement carve-out. The parent-mint leg of
        // GNUSLifecycleMint._settleRedeemToParent routes through _mint → this gate; redemption
        // of expired child funds must NOT be blockable by the parent's sale window
        // (validFrom/validUntil) or consume the holder's per-wallet mint cap on the parent —
        // it is a redemption of already-collateralized value, not fresh issuance. The
        // max-supply check above still applies (hard supply invariant; same posture as
        // GNUSRedeemAdapter.redeem, whose GNUS mint leg also runs this gate). The transient
        // flag is set ONLY around that single internal _mint.
        if (GNUSLifecycleStorage.layout().settleRedeemMintActive) {
            return;
        }

        require(
            nftMint.validFrom == 0 || block.timestamp >= nftMint.validFrom,
            "Token not yet active"
        );

        // WR-02 (13 review): PerTokenId sale-end gate, symmetric with
        // GNUSLifecycleMint._checkMintPolicy. The hook is the single window authority — the
        // LEGACY factory mint/mintBatch path (which does not run _checkMintPolicy) must not be
        // able to mint tokens after the sale window / after the token class expired.
        if (nftMint.expirationMode == uint8(ExpirationMode.PerTokenId)) {
            require(nftMint.validUntil == 0 || block.timestamp < nftMint.validUntil, "Sale ended");
        }

        // Per-wallet mint cap CHECK-AND-INCREMENT (CEI). Cap of 0 = uncapped (zero-default
        // preserves legacy behavior).
        GNUSLifecycleStorage.Layout storage lc = GNUSLifecycleStorage.layout();
        uint256 cap = lc.perWalletMintCap[id];
        if (cap != 0) {
            uint256 newTotal = lc.mintedPerWallet[id][to] + amount;
            require(newTotal <= cap, "Per-wallet mint cap exceeded");
            lc.mintedPerWallet[id][to] = newTotal;
        }
    }

    /// @notice Phase 13 D6 single-predicate transfer-policy enforcement (SC3).
    /// @dev Body relocated VERBATIM from GNUSERC1155MaxSupply._enforceTransferPolicy — every
    ///      revert string, carve-out, the GNUS_TOKEN_ID early return, and the mint-branch
    ///      validFrom defense-in-depth check are unchanged. Called once per element from the
    ///      calling facet's _beforeTokenTransfer loop. View-only — no state writes (the cap
    ///      write lives in enforceMintGate, NOT here).
    ///
    ///      Carve-outs (D6):
    ///        - !nftCreated       → return (paranoia; existing checks already enforce)
    ///        - id == GNUS_TOKEN_ID → return (GNUS itself is ALWAYS UNRESTRICTED — T-13-04-05)
    ///        - UNRESTRICTED      → return (zero-default preserves legacy behavior)
    ///        - from == 0 (mint)  → enforce validFrom ("Token not yet active") as defense-in-depth,
    ///                              then return (minting is permitted subject to the window)
    ///        - to == 0 (burn)    → return (spend burns, settle burns, redemption burns permitted;
    ///                              D5: SOULBOUND permits consumption burns)
    ///
    ///      Holder-to-holder dispatch (from != 0 && to != 0) per nft.transferPolicy:
    ///        SOULBOUND          → permit fixed-recipient return (to == nft.expirationRecipient,
    ///                             RETURN_TO_ADDRESS settlement path) and issuer correction
    ///                             (operator == nft.creator || DEFAULT_ADMIN_ROLE); else revert.
    ///        ISSUER_ONLY        → require operator == nft.creator || DEFAULT_ADMIN_ROLE.
    ///        ALLOWLISTED        → require registry configured; require IAllowlistRegistry
    ///                             .isAllowed(to).
    ///        CONTROLLED_RESALE  → revert (v1: no resale mechanism — D5 v2 scope).
    ///        LOCKED_AFTER_START → require block.timestamp < nft.validFrom (locked after start).
    ///
    ///      Role-read mechanism (13-04 interfaces block, option b): DEFAULT_ADMIN_ROLE membership
    ///      is read via AccessControlStorage.layout()._roles[DEFAULT_ADMIN_ROLE].members[operator]
    ///      — direct diamond-shared storage (slot =
    ///      keccak256('openzepplin.contracts.storage.AccessControl')), the SAME storage
    ///      AccessControlUpgradeable.hasRole reads. DEFAULT_ADMIN_ROLE == bytes32(0) (declared as
    ///      0x00 in AccessControlUpgradeable).
    /// @param operator The address which initiated the transfer (msg.sender on the entry point).
    /// @param from The address which previously owned the token (0x0 on mint).
    /// @param to The address which will receive the token (0x0 on burn).
    /// @param id The token id being moved.
    /// @param amount The amount being moved (unused by the predicate; part of the D6 signature
    ///        so future policies can reason about amount without changing the call site).
    function enforceTransferPolicy(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) public view {
        // amount is part of the D6 signature for future-proofing; no current policy uses it.
        // Silence the unused-parameter warning without a runtime cost.
        amount;

        NFT storage nft = GNUSNFTFactoryStorage.layout().NFTs[id];
        if (!nft.nftCreated) {
            return; // paranoia; existing checks already enforce
        }
        if (id == GNUS_TOKEN_ID) {
            return; // GNUS itself is always UNRESTRICTED (T-13-04-05)
        }
        if (nft.transferPolicy == uint8(TransferPolicy.UNRESTRICTED)) {
            return; // zero-default preserves legacy behavior
        }

        // System carve-outs (D6): mint (from == 0) and burn (to == 0).
        if (from == address(0)) {
            // Mint path: enforce validFrom (sale window) as defense-in-depth for configured
            // policies. The hook's mint branch already gates validFrom unconditionally (the
            // load-bearing legacy-path gate); this is the policy-predicate-level check per the
            // Pattern 4 skeleton. Minting is then permitted.
            // WR-04 (13 review): the REDEEM_TO_PARENT settlement parent-mint leg is exempt from
            // this window check (redemption of expired funds must not be blockable by the
            // parent's sale window) — see GNUSLifecycleMint._settleRedeemToParent.
            if (!GNUSLifecycleStorage.layout().settleRedeemMintActive) {
                require(
                    nft.validFrom == 0 || block.timestamp >= nft.validFrom,
                    "Token not yet active"
                );
            }
            return;
        }
        if (to == address(0)) {
            // Burn path: always permitted (spend burns, settle burns, redemption burns).
            // D5: SOULBOUND permits consumption burns.
            return;
        }

        // Holder-to-holder transfer (from != 0 && to != 0): policy dispatch.
        if (nft.transferPolicy == uint8(TransferPolicy.SOULBOUND)) {
            // D5: SOULBOUND permits fixed-recipient returns (RETURN_TO_ADDRESS settlement)
            // and narrowly approved issuer corrections under creator/admin authority.
            // ACCEPTED RISK (13 review IN-01, D5 carve-out): this early return is NOT scoped to
            // the settlement flow — the recipient address is a PERMANENT TRANSFER SINK every
            // holder may voluntarily exit to at any time, pre-expiry. expirationRecipient must
            // therefore be a contract that safely handles unsolicited transfers (issuer refund
            // processor, not a hot EOA).
            if (to == nft.expirationRecipient) {
                // Settlement path — settleExpired routes through _safeTransferFrom with
                // to == expirationRecipient. Permitted.
                return;
            }
            // Issuer-correction carve-out: creator or DEFAULT_ADMIN_ROLE can move tokens for
            // refunds/corrections (D5: "narrowly approved issuer correction/refund paths").
            // DEFAULT_ADMIN_ROLE == bytes32(0) — read via diamond-shared AccessControlStorage.
            if (operator == nft.creator || AccessControlStorage.layout()._roles[bytes32(0)].members[operator]) {
                return;
            }
            revert("SOULBOUND: holder-to-holder transfers blocked");
        }

        if (nft.transferPolicy == uint8(TransferPolicy.ISSUER_ONLY)) {
            // WR-03 (13 review): settlement carve-out mirroring the SOULBOUND fixed-recipient
            // return above (D6 lists "to == fixed recipient" as a general system carve-out).
            // RETURN_TO_ADDRESS settlement routes through _safeTransferFrom with
            // to == nft.expirationRecipient and operator == the (permissionless, D9)
            // settleExpired caller — without this carve-out a third-party settle would revert
            // and the expired pile would be stuck until the creator/admin happens to call.
            if (to == nft.expirationRecipient) {
                return;
            }
            // Only creator or DEFAULT_ADMIN_ROLE can move. DEFAULT_ADMIN_ROLE == bytes32(0).
            require(
                operator == nft.creator || AccessControlStorage.layout()._roles[bytes32(0)].members[operator],
                "ISSUER_ONLY: only creator/admin can transfer"
            );
            return;
        }

        if (nft.transferPolicy == uint8(TransferPolicy.ALLOWLISTED)) {
            // Destination must satisfy the per-token registry check (D5).
            address registry = GNUSLifecycleStorage.layout().allowlistRegistry[id];
            require(registry != address(0), "ALLOWLISTED: no registry configured");
            require(
                IAllowlistRegistry(registry).isAllowed(to),
                "ALLOWLISTED: destination not allowed"
            );
            return;
        }

        if (nft.transferPolicy == uint8(TransferPolicy.CONTROLLED_RESALE)) {
            // v1: block all ordinary holder-to-holder transfers (D5 — resale mechanism is v2).
            revert("CONTROLLED_RESALE: resale mechanism v2");
        }

        if (nft.transferPolicy == uint8(TransferPolicy.LOCKED_AFTER_START)) {
            // Transferable before validFrom; locked after (D5).
            require(
                nft.validFrom == 0 || block.timestamp < nft.validFrom,
                "LOCKED_AFTER_START: transfers locked"
            );
            return;
        }
    }
}
