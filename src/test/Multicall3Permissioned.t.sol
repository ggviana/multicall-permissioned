// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Multicall3Permissioned} from "../Multicall3Permissioned.sol";
import {Whitelist} from "../Whitelist.sol";
import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {MockCallee} from "./mocks/MockCallee.sol";
import {EtherSink} from "./mocks/EtherSink.sol";

contract Multicall3PermissionedTest is Test {
  address public authorized = address(uint160(uint256(keccak256("authorized"))));
  address public unauthorized = address(uint160(uint256(keccak256("unauthorized"))));

  Multicall3Permissioned public multicall;
  MockCallee public callee;
  EtherSink public etherSink;

  /// @notice Setups up the testing suite
  function setUp() public {
    // Fund wallets
    vm.deal(authorized, 10 ether);
    vm.deal(unauthorized, 10 ether);

    vm.prank(authorized);
    multicall = new Multicall3Permissioned();
    callee = new MockCallee();
    etherSink = new EtherSink();
  }

  /// >>>>>>>>>>>>>>>>>>>>>  AGGREGATE TESTS  <<<<<<<<<<<<<<<<<<<<< ///

  function testAggregation() public {
    // Test successful call
    Multicall3Permissioned.Call[] memory calls = new Multicall3Permissioned.Call[](1);
    calls[0] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("getBlockHash(uint256)", block.number));

    // Test unauthorized call
    _expectUnauthorizedRevert();
    multicall.aggregate(calls);

    // Test authorized call
    vm.prank(authorized);
    (uint256 blockNumber, bytes[] memory returnData) = multicall.aggregate(calls);
    assertEq(blockNumber, block.number);
    assertEq(keccak256(returnData[0]), keccak256(abi.encodePacked(blockhash(block.number))));
  }

  function testUnsuccessfulAggregation() public {
    // Test unexpected revert
    Multicall3Permissioned.Call[] memory calls = new Multicall3Permissioned.Call[](2);
    calls[0] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("thisMethodReverts()"));
    vm.expectRevert(bytes("Multicall3: call failed"));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.aggregate(calls);
  }

  /// >>>>>>>>>>>>>>>>>>>  TRY AGGREGATE TESTS  <<<<<<<<<<<<<<<<<<< ///

  function testTryAggregate() public {
    Multicall3Permissioned.Call[] memory calls = new Multicall3Permissioned.Call[](2);
    calls[0] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("thisMethodReverts()"));

    // Test unauthorized call
    _expectUnauthorizedRevert();
    multicall.tryAggregate(false, calls);

    // Test calling from authorized address
    vm.prank(authorized);
    (Multicall3Permissioned.Result[] memory returnData) = multicall.tryAggregate(false, calls);
    assertTrue(returnData[0].success);
    assertEq(keccak256(returnData[0].returnData), keccak256(abi.encodePacked(blockhash(block.number))));
    assertTrue(!returnData[1].success);
  }

  function testTryAggregateUnsuccessful() public {
    Multicall3Permissioned.Call[] memory calls = new Multicall3Permissioned.Call[](2);
    calls[0] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("thisMethodReverts()"));
    vm.expectRevert(bytes("Multicall3: call failed"));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.tryAggregate(true, calls);
  }

  /// >>>>>>>>>>>>>>  TRY BLOCK AND AGGREGATE TESTS  <<<<<<<<<<<<<< ///

  function testTryBlockAndAggregate() public {
    Multicall3Permissioned.Call[] memory calls = new Multicall3Permissioned.Call[](2);
    calls[0] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("thisMethodReverts()"));

    // Test unauthorized call
    _expectUnauthorizedRevert();
    multicall.tryBlockAndAggregate(false, calls);

    // Test calling from authorized address
    vm.prank(authorized);
    (uint256 blockNumber, bytes32 blockHash, Multicall3Permissioned.Result[] memory returnData) = multicall.tryBlockAndAggregate(false, calls);
    assertEq(blockNumber, block.number);
    assertEq(blockHash, blockhash(block.number));
    assertTrue(returnData[0].success);
    assertEq(keccak256(returnData[0].returnData), keccak256(abi.encodePacked(blockhash(block.number))));
    assertTrue(!returnData[1].success);
  }

  function testTryBlockAndAggregateUnsuccessful() public {
    Multicall3Permissioned.Call[] memory calls = new Multicall3Permissioned.Call[](2);
    calls[0] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("thisMethodReverts()"));
    vm.expectRevert(bytes("Multicall3: call failed"));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.tryBlockAndAggregate(true, calls);
  }

  function testBlockAndAggregateUnsuccessful() public {
    Multicall3Permissioned.Call[] memory calls = new Multicall3Permissioned.Call[](2);
    calls[0] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call(address(callee), abi.encodeWithSignature("thisMethodReverts()"));
    vm.expectRevert(bytes("Multicall3: call failed"));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.blockAndAggregate(calls);
  }

  /// >>>>>>>>>>>>>>>>>>>  AGGREGATE3 TESTS  <<<<<<<<<<<<<<<<<<<<<< ///

  function testAggregate3() public {
    Multicall3Permissioned.Call3[] memory calls = new Multicall3Permissioned.Call3[](3);
    calls[0] = Multicall3Permissioned.Call3(address(callee), false, abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call3(address(callee), true, abi.encodeWithSignature("thisMethodReverts()"));
    calls[2] = Multicall3Permissioned.Call3(address(multicall), true, abi.encodeWithSignature("getCurrentBlockTimestamp()"));

    // Test unauthorized call
    _expectUnauthorizedRevert();
    multicall.aggregate3(calls);

    // Test calling from authorized address
    vm.prank(authorized);
    (Multicall3Permissioned.Result[] memory returnData) = multicall.aggregate3(calls);

    // Call 1.
    assertTrue(returnData[0].success);
    assertEq(blockhash(block.number), abi.decode(returnData[0].returnData, (bytes32)));
    assertEq(keccak256(returnData[0].returnData), keccak256(abi.encodePacked(blockhash(block.number))));

    // Call 2.
    assertTrue(!returnData[1].success);
    assertEq(returnData[1].returnData.length, 4);
    assertEq(bytes4(returnData[1].returnData), bytes4(keccak256("Unsuccessful()")));

    // Call 3.
    assertTrue(returnData[2].success);
    assertEq(abi.decode(returnData[2].returnData, (uint256)), block.timestamp);
  }

  function testAggregate3Unsuccessful() public {
    Multicall3Permissioned.Call3[] memory calls = new Multicall3Permissioned.Call3[](2);
    calls[0] = Multicall3Permissioned.Call3(address(callee), false, abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call3(address(callee), false, abi.encodeWithSignature("thisMethodReverts()"));
    vm.expectRevert(bytes("Multicall3: call failed"));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.aggregate3(calls);
  }

  /// >>>>>>>>>>>>>>>>>  AGGREGATE3VALUE TESTS  <<<<<<<<<<<<<<<<<<< ///

  function testAggregate3Value() public {
    Multicall3Permissioned.Call3Value[] memory calls = new Multicall3Permissioned.Call3Value[](3);
    calls[0] = Multicall3Permissioned.Call3Value(address(callee), false, 0, abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call3Value(address(callee), true, 0, abi.encodeWithSignature("thisMethodReverts()"));
    calls[2] = Multicall3Permissioned.Call3Value(address(callee), true, 1, abi.encodeWithSignature("sendBackValue(address)", address(etherSink)));

    // Test unauthorized call
    _expectUnauthorizedRevert();
    multicall.aggregate3Value{value: 1}(calls);

    // Test calling from authorized address
    vm.prank(authorized);
    (Multicall3Permissioned.Result[] memory returnData) = multicall.aggregate3Value{value: 1}(calls);
    assertTrue(returnData[0].success);
    assertEq(keccak256(returnData[0].returnData), keccak256(abi.encodePacked(blockhash(block.number))));
    assertTrue(!returnData[1].success);
    assertTrue(returnData[2].success);
  }

  function testAggregate3ValueUnsuccessful() public {
    Multicall3Permissioned.Call3Value[] memory calls = new Multicall3Permissioned.Call3Value[](3);
    calls[0] = Multicall3Permissioned.Call3Value(address(callee), false, 0, abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls[1] = Multicall3Permissioned.Call3Value(address(callee), false, 0, abi.encodeWithSignature("thisMethodReverts()"));
    calls[2] = Multicall3Permissioned.Call3Value(address(callee), false, 1, abi.encodeWithSignature("sendBackValue(address)", address(etherSink)));
    vm.expectRevert(bytes("Multicall3: call failed"));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.aggregate3Value(calls);

    // Should fail if we don't provide enough value
    Multicall3Permissioned.Call3Value[] memory calls2 = new Multicall3Permissioned.Call3Value[](3);
    calls2[0] = Multicall3Permissioned.Call3Value(address(callee), true, 0, abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls2[1] = Multicall3Permissioned.Call3Value(address(callee), true, 0, abi.encodeWithSignature("thisMethodReverts()"));
    calls2[2] = Multicall3Permissioned.Call3Value(address(callee), true, 1, abi.encodeWithSignature("sendBackValue(address)", address(etherSink)));
    vm.expectRevert(bytes("Multicall3: value mismatch"));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.aggregate3Value(calls2);

    // Works if we provide enough value
    Multicall3Permissioned.Call3Value[] memory calls3 = new Multicall3Permissioned.Call3Value[](3);
    calls3[0] = Multicall3Permissioned.Call3Value(address(callee), false, 0, abi.encodeWithSignature("getBlockHash(uint256)", block.number));
    calls3[1] = Multicall3Permissioned.Call3Value(address(callee), true, 0, abi.encodeWithSignature("thisMethodReverts()"));
    calls3[2] = Multicall3Permissioned.Call3Value(address(callee), false, 1, abi.encodeWithSignature("sendBackValue(address)", address(etherSink)));
    // Test calling from authorized address
    vm.prank(authorized);
    multicall.aggregate3Value{value: 1}(calls3);
  }

  function testWhitelistManagement() public {
    MockCallee whitelistedCallee = new MockCallee();
    // Should fail if called from an unauthorized callee
    assertFalse(multicall.hasWhitelist());

    _expectUnauthorizedRevert();
    multicall.addWhitelistAddress(address(whitelistedCallee));

    _expectUnauthorizedRevert();
    multicall.removeWhitelistAddress(address(whitelistedCallee));

    // Should add to whitelist if called from an authorized callee
    vm.startPrank(authorized);
    multicall.addWhitelistAddress(address(whitelistedCallee));
    assertTrue(multicall.hasWhitelist());
    assertTrue(multicall.isAllowed(address(whitelistedCallee)), "Address should be whitelisted");

    // Should check the contract is not whitelisted
    Multicall3Permissioned.Call3Value[] memory calls = new Multicall3Permissioned.Call3Value[](2);
    calls[0] = Multicall3Permissioned.Call3Value(address(whitelistedCallee), true, 1, abi.encodeWithSignature("sendBackValue(address)", address(etherSink)));
    calls[1] = Multicall3Permissioned.Call3Value(address(callee), true, 1, abi.encodeWithSignature("sendBackValue(address)", address(etherSink)));
    vm.expectRevert(
      abi.encodeWithSelector(
        Whitelist.WhitelistNotAllowed.selector,
        address(callee)
      )
    );
    multicall.aggregate3Value(calls);

    // Should remove from whitelist if called from an authorized callee
    multicall.removeWhitelistAddress(address(whitelistedCallee));
    assertFalse(multicall.hasWhitelist());
    assertFalse(multicall.isAllowed(address(whitelistedCallee)), "Address should be whitelisted");

    vm.stopPrank();
  }

  /// >>>>>>>>>>>>>>>>>>>>>>  HELPER TESTS  <<<<<<<<<<<<<<<<<<<<<<< ///

  function testGetBlockHash(uint256 blockNumber) public {
    assertEq(blockhash(blockNumber), multicall.getBlockHash(blockNumber));
  }

  function testGetBlockNumber() public {
    assertEq(block.number, multicall.getBlockNumber());
  }

  function testGetCurrentBlockCoinbase() public {
    assertEq(block.coinbase, multicall.getCurrentBlockCoinbase());
  }

  function testGetCurrentBlockPrevrandao() public {
    assertEq(block.prevrandao, multicall.getCurrentBlockPrevrandao());
  }

  function testGetCurrentBlockGasLimit() public {
    assertEq(block.gaslimit, multicall.getCurrentBlockGasLimit());
  }

  function testGetCurrentBlockTimestamp() public {
    assertEq(block.timestamp, multicall.getCurrentBlockTimestamp());
  }

  function testGetEthBalance(address addr) public {
    assertEq(addr.balance, multicall.getEthBalance(addr));
  }

  function testGetLastBlockHash() public {
    // Prevent arithmetic underflow on the genesis block
    if (block.number == 0) return;
    assertEq(blockhash(block.number - 1), multicall.getLastBlockHash());
  }

  function testGetBasefee() public {
    assertEq(block.basefee, multicall.getBasefee());
  }

  function testGetChainId() public {
    assertEq(block.chainid, multicall.getChainId());
  }

  function _expectUnauthorizedRevert() internal {
    vm.prank(unauthorized);
    vm.expectRevert(
      abi.encodeWithSelector(
        Ownable.OwnableUnauthorizedAccount.selector,
        unauthorized
      )
    );
  }
}
