// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {EnumerableSet} from "../lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title Whitelist
/// @notice A contract that manages which contracts a Multicall contract may access.
/// If no addresses are added to the whitelist, any contract address will be accepted.
/// @author Guilherme Guimarães <gui@pods.finance>
contract Whitelist {
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private whitelist;

    /// @notice Emitted when an address is added to the whitelist.
    /// @param target The address that was added.
    event WhitelistAddressAdded(address indexed target);

    /// @notice Emitted when an address is removed from the whitelist.
    /// @param target The address that was removed.
    event WhitelistAddressRemoved(address indexed target);

    /// @notice Thrown when an address is not allowed to perform an action.
    /// @param target The address that is not allowed.
    error WhitelistNotAllowed(address target);

    /// @notice Adds an address to the whitelist.
    /// @dev Emits a `WhitelistAddressAdded` event on success.
    /// @param target The address to be added to the whitelist.
    function addWhitelistAddress(address target) public virtual {
        if (whitelist.add(target)) {
            emit WhitelistAddressAdded(target);
        }
    }

    /// @notice Removes an address from the whitelist.
    /// @dev Emits a `WhitelistAddressRemoved` event on success.
    /// @param target The address to be removed from the whitelist.
    function removeWhitelistAddress(address target) public virtual {
        if (whitelist.remove(target)) {
            emit WhitelistAddressRemoved(target);
        }
    }

    /// @notice Checks if there are any addresses in the whitelist.
    /// @return A boolean value indicating if the whitelist contains any addresses.
    function hasWhitelist() public view returns (bool) {
        return whitelist.length() > 0;
    }

    /// @notice Checks if a specific address is in the whitelist.
    /// @param target The address to check.
    /// @return A boolean value indicating if the address is in the whitelist.
    function isAllowed(address target) public view returns (bool) {
        return whitelist.contains(target);
    }
}
