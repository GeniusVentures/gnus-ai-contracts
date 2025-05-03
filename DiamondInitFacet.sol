// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import 'hardhat/console.sol';
import "@gnus.ai/contracts-upgradeable-diamond/utils/ContextUpgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/access/AccessControlEnumerableUpgradeable.sol";
import "@gnus.ai/contracts-upgradeable-diamond/proxy/utils/Initializable.sol";
import "contracts-starter/contracts/libraries/LibDiamond.sol";
import "@gnus.ai/contracts-upgradeable-diamond/token/ERC20/IERC20Upgradeable.sol";

import "hardhat/console.sol";

contract DiamondInitFacet is ContextUpgradeable, AccessControlEnumerableUpgradeable {
    using LibDiamond for LibDiamond.DiamondStorage;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    event InitLog(address indexed sender, string initializer);

    modifier onlySuperAdminRole {
        require(LibDiamond.diamondStorage().contractOwner == _msgSender(), "Only SuperAdmin allowed");
        _;
    }

    /// @notice Main protocol-wide initializer run in `diamondCut`
  function diamondInitialize250() public //onlySuperAdminRole
   {
        console.log("DiamondInitFacet: diamondInitialize250 called");
        address sender = _msgSender();
        emit InitLog(sender, "diamondInitialize Function called");

        // Set up roles and permissions
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(UPGRADER_ROLE, _msgSender());
        // Set up the initial state of the contract
        


        _grantRole(DEFAULT_ADMIN_ROLE, sender);
        _grantRole(MINTER_ROLE, sender);
        _grantRole(UPGRADER_ROLE, sender);
        
        LibDiamond.diamondStorage().supportedInterfaces[type(IERC20Upgradeable).interfaceId] = true;
    }
}
