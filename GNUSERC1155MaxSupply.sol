// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/extensions/ERC1155SupplyUpgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC1155/extensions/ERC1155BurnableUpgradeable.sol";
import "./GNUSNFTFactoryStorage.sol";
import "./GNUSControlStorage.sol";
import "./GNUSWithdrawLimiterStorage.sol";
import "./GNUSLifecycleStorage.sol";
import "./GNUSLifecycleTypes.sol";
import "./GNUSLifecyclePolicy.sol";
import "./GNUSConstants.sol";
import {LibDiamond} from "contracts-starter/contracts/libraries/LibDiamond.sol";

/// @title GNUSERC1155MaxSupply
/// @notice This contract extends ERC1155 functionality with supply management and burning capabilities.
/// @dev Diamond-wide emergency pause is enforced via GNUSControlStorage.layout().paused (see _beforeTokenTransfer),
/// not OpenZeppelin's PausableUpgradeable, which was removed as vestigial.
///
///      Phase 13 (D6/D5/D10): the _beforeTokenTransfer hook is the SINGLE enforcement point for
///      the transfer-policy predicate (SC3) and the per-wallet mint-cap increment (SC6 addendum).
///      Every mint/transfer/burn on the diamond routes through this hook — legacy factory mint,
///      GNUSLifecycleMint.mintWithCredential, direct safeTransferFrom, safeBatchTransferFrom,
///      settlement transfers — with NO delegatecall and NO cross-facet call (the hook is an
///      internal function on the shared base, invoked inline by ERC1155Upgradeable._mint/_burn/
///      _safeTransferFrom/_safeBatchTransferFrom on every inheriting facet).
///
///      CAP-INCREMENT LOCATION (13-03 REPLAN ADDENDUM, locked 2026-08-23): the per-wallet cap
///      CHECK-AND-INCREMENT lives HERE, in the mint branch of this hook — the SINGLE write point
///      for mintedPerWallet across the whole codebase. Both the legacy GNUSNFTFactory.mint path
///      and the GNUSLifecycleMint.mintWithCredential path funnel through _mint → this hook, so a
///      single write here enforces the cap on BOTH paths with no double-count. GNUSLifecycleMint
///      ._checkMintPolicy does NOT write the cap (it dropped its increment when this hook gate
///      landed); it keeps only the sale-window check and the credential-verifier call.
///
///      Role-read mechanism (13-04 interfaces block, option b): the ISSUER_ONLY / SOULBOUND
///      correction carve-outs read DEFAULT_ADMIN_ROLE membership via
///      AccessControlStorage.layout()._roles[DEFAULT_ADMIN_ROLE].members[operator] — direct
///      diamond-shared storage (slot = keccak256('openzepplin.contracts.storage.AccessControl')),
///      the SAME storage AccessControlUpgradeable.hasRole reads. DEFAULT_ADMIN_ROLE ==
///      bytes32(0) per AccessControlUpgradeable. The read itself lives in GNUSLifecyclePolicy
///      (13-04 library relocation — see below).
///
///      LIBRARY RELOCATION (13-04, EIP-170): the transfer-policy predicate body and the
///      mint-branch window+cap gate body live in the compile-time-linked Solidity library
///      GNUSLifecyclePolicy (public functions → DELEGATECALL stub to a fixed pure-code
///      contract, standard library linking — NOT a facet, NOT a selector-routing trampoline,
///      NOT the hand-rolled facet-delegation pattern rejected in the 13-03 replan). Library
///      code runs in this facet's diamond-shared storage context, so semantics are identical
///      to the previous inlined bodies. GNUSNFTFactory was 26,372 B deployed (over the
///      24,576 B EIP-170 limit) with the bodies inlined; the relocation brings every
///      inheriting facet back under the limit. The hook keeps the SINGLE call site and the
///      internal _enforceTransferPolicy wrapper preserves the D6 predicate signature.
///
///      NO operator exemptions (Pitfall P2): the predicate NEVER reads the proxy-operator
///      marketplace role or any approval state. The proxy-operator facet auto-approves role
///      holders at the approval layer, but that only skips the approval check — this predicate
///      still runs and blocks the move. The grep gate in plan 13-04 (Task 1 verify) enforces:
///      zero approval-state reads anywhere in this file or the GNUSLifecyclePolicy library.
contract GNUSERC1155MaxSupply is
    ERC1155SupplyUpgradeable,
    ERC1155BurnableUpgradeable
{
    using GNUSNFTFactoryStorage for GNUSNFTFactoryStorage.Layout;
    using GNUSControlStorage for GNUSControlStorage.Layout;

    /// @notice Hook that is called before any token transfer. This includes minting and burning.
    /// @dev This function overrides the _beforeTokenTransfer function from ERC1155Upgradeable and ERC1155SupplyUpgradeable.
    /// It ensures that transfers are not paused, checks for banned transferors, and enforces max supply constraints.
    ///
    ///      Phase 13 ordering inside the per-element loop (mint branch):
    ///        1. existing max-supply check (unchanged)
    ///        2. validFrom sale-window gate (13-03 REPLAN ADDENDUM — load-bearing on legacy path)
    ///        3. per-wallet mint-cap CHECK-AND-INCREMENT (13-03 REPLAN ADDENDUM — single write
    ///           point; fires on every mint on BOTH the legacy factory path and the lifecycle
    ///           mint-facet path, inline, no delegatecall — same mechanism as the max-supply check)
    ///        4. _enforceTransferPolicy (13-04 D6 — policy dispatch; mint carve-out also enforces
    ///           validFrom as defense-in-depth for configured policies)
    ///      The transfer-policy predicate runs for EVERY element of EVERY batch — mixed-token
    ///      batch atomicity falls out of revert semantics (any element reverting reverts the tx).
    /// @param operator The address which initiated the transfer (i.e. msg.sender)
    /// @param from The address which previously owned the token
    /// @param to The address which will receive the token
    /// @param ids An array containing the ids of each token being transferred (order and length must match amounts array)
    /// @param amounts An array containing the amount of each token being transferred (order and length must match ids array)
    /// @param data Additional data with no specified format
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal override(ERC1155Upgradeable, ERC1155SupplyUpgradeable) {
        require(!GNUSControlStorage.layout().paused, "GNUSControl: contract paused");
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);

        // Single-pass loop: aggregate GNUS amounts, check banned transferors, enforce max supply
        uint256 totalGNUSAmount = 0;
        bool isMinting = from == address(0);
        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 id = ids[i];

            // Aggregate GNUS token amounts for withdrawal limiter
            if (!isMinting && id == GNUS_TOKEN_ID) {
                totalGNUSAmount += amounts[i];
            }

            // Check banned transferors
            require(!GNUSControlStorage.isBannedTransferor(id, operator), "Blocked transferor");

            // Enforce max supply, sale window, and per-wallet mint cap on minting.
            // Bodies live in the GNUSLifecyclePolicy library (13-04 EIP-170 relocation) —
            // the library enforces: max-supply check, validFrom sale-window gate (13-03 REPLAN
            // ADDENDUM — load-bearing on the legacy path), and the per-wallet mint-cap
            // CHECK-AND-INCREMENT (CEI, SINGLE WRITE POINT for mintedPerWallet across the whole
            // codebase; fires on every mint on BOTH the legacy factory path and the lifecycle
            // mint-facet path, inline, no facet delegatecall — GNUSLifecycleMint._checkMintPolicy
            // does NOT write the cap).
            if (isMinting) {
                GNUSLifecyclePolicy.enforceMintGate(id, to, amounts[i]);
            }

            // Phase 13 D6: single-predicate transfer-policy enforcement (no operator exemptions).
            // Runs for every element of every batch — mixed-token batch atomicity via revert.
            _enforceTransferPolicy(operator, from, to, id, amounts[i]);
        }

        // Apply withdrawal limiter for GNUS token transfers (non-minting only)
        // WR-07: GNUSBridge.withdraw() and bridgeOut() for id == GNUS_TOKEN_ID rely on THIS hook
        // as the single charge point for the limiter on their _burn path. Do not add a second
        // explicit checkAndRecordWithdraw call on those paths, or users will be double-limited.
        // WR-03: charge the limiter against the token OWNER (`from`), not the operator.
        // In the ERC20 transferFrom path, operator is the approved spender — charging the
        // spender would let an owner circumvent their own rate limit via an approved
        // third party, and would let a rate-limited spender be blocked from executing
        // approved transfers for other users.
        if (!isMinting && totalGNUSAmount > 0) {
            address limiterSubject = (from != address(0) && from != operator) ? from : operator;
            if (LibDiamond.diamondStorage().contractOwner != operator) {
                GNUSWithdrawLimiterStorage.checkAndRecordWithdraw(limiterSubject, totalGNUSAmount);
            } else {
                emit GNUSWithdrawLimiterStorage.SuperAdminBypass(
                    limiterSubject, totalGNUSAmount, "GNUSERC1155MaxSupply._beforeTokenTransfer"
                );
            }
        }
    }

    /// @notice Phase 13 D6 single-predicate transfer-policy enforcement (SC3).
    /// @dev Thin internal wrapper preserving the D6 predicate signature and the single call site
    ///      in _beforeTokenTransfer. The full policy body (carve-outs, GNUS_TOKEN_ID early
    ///      return, mint-branch validFrom defense-in-depth, holder-to-holder dispatch for all six
    ///      policies, exact revert strings, role-read mechanism) lives in the compile-time-linked
    ///      GNUSLifecyclePolicy library — relocated verbatim for EIP-170 headroom (13-04).
    ///      View-only — no state writes (the cap write lives in GNUSLifecyclePolicy
    ///      .enforceMintGate, called from the mint branch of the hook, NOT here).
    /// @param operator The address which initiated the transfer (msg.sender on the entry point).
    /// @param from The address which previously owned the token (0x0 on mint).
    /// @param to The address which will receive the token (0x0 on burn).
    /// @param id The token id being moved.
    /// @param amount The amount being moved (unused by the predicate; part of the D6 signature
    ///        so future policies can reason about amount without changing the call site).
    function _enforceTransferPolicy(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) internal view {
        GNUSLifecyclePolicy.enforceTransferPolicy(operator, from, to, id, amount);
    }

    /// @notice Converts a uint256 element to a singleton array.
    /// @dev This function is used to create an array with a single uint256 element.
    /// @param element The uint256 element to be converted to an array.
    /// @return An array containing the single uint256 element.
    function asSingletonArray(uint256 element) internal pure returns (uint256[] memory) {
        uint256[] memory array = new uint256[](1);
        array[0] = element;

        return array;
    }

    /// @notice Converts a string element to a singleton array.
    /// @dev This function is used to create an array with a single string element.
    /// @param element The string element to be converted to an array.
    /// @return An array containing the single string element.
    function asSingletonArray(string memory element) internal pure returns (string[] memory) {
        string[] memory array = new string[](1);
        array[0] = element;

        return array;
    }
}
