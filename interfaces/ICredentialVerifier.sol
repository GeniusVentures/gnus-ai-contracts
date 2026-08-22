// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title ICredentialVerifier
/// @notice Generic credential verifier plug-in interface for Phase 13 anti-scalping.
/// @dev Called from GNUSNFTFactory.beforeMint AFTER per-wallet cap update (CEI ordering).
///      Implementations may use EIP-712 vouchers, merkle allowlists, or identity providers.
///      The diamond does NOT verify signatures itself — creators bring their own verifier.
interface ICredentialVerifier {
    /// @notice Verify a credential for a mint.
    /// @param minter The address receiving the minted tokens.
    /// @param tokenId The token ID being minted.
    /// @param amount The amount being minted (minions).
    /// @param credential Opaque bytes — format defined by the verifier.
    /// @return True if the credential is valid, false otherwise.
    function verify(
        address minter,
        uint256 tokenId,
        uint256 amount,
        bytes calldata credential
    ) external view returns (bool);
}
