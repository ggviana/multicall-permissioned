// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0 <0.9.0;

/// @title EtherSink
/// @notice Receives Ether, that's about it \( o_o )/
/// @author andreas@nascent.xyz
contract EtherSink {

  /// >>>>>>>>>>>>>>>>>>>>>>  ACCEPT CALLS  <<<<<<<<<<<<<<<<<<<<<<< ///

  /// @notice Allows the test to receive eth via low level calls
  receive() external payable {}
}
