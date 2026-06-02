// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BallotRegistry} from "../src/BallotRegistry.sol";

contract BallotRegistryTest is Test {
    BallotRegistry reg;
    address operator = address(0xA11CE);
    address stranger = address(0xBEEF);

    function setUp() public {
        vm.prank(operator);
        reg = new BallotRegistry(operator);
    }

    function _labels() internal pure returns (string[] memory l) {
        l = new string[](3);
        l[0] = "Cats"; l[1] = "Dogs"; l[2] = "Both";
    }

    function test_createRound_storesMetadata() public {
        vm.prank(operator);
        reg.createRound(7, "Cats or dogs?", _labels(), bytes32(uint256(0x1b49)), uint64(block.timestamp + 1 days));
        BallotRegistry.Round memory r = reg.getRound(7);
        assertEq(r.question, "Cats or dogs?");
        assertEq(r.optionLabels.length, 3);
        assertEq(r.optionLabels[2], "Both");
        assertEq(r.enrollmentRoot, bytes32(uint256(0x1b49)));
        assertEq(r.numOptions, 3);
        assertTrue(r.exists);
    }

    function test_createRound_onlyOperator() public {
        vm.prank(stranger);
        vm.expectRevert(BallotRegistry.NotOperator.selector);
        reg.createRound(7, "q", _labels(), bytes32(0), uint64(block.timestamp + 1));
    }

    function test_createRound_rejectsDuplicateE3Id() public {
        vm.startPrank(operator);
        reg.createRound(7, "q", _labels(), bytes32(0), uint64(block.timestamp + 1));
        vm.expectRevert(BallotRegistry.RoundExists.selector);
        reg.createRound(7, "q2", _labels(), bytes32(0), uint64(block.timestamp + 1));
        vm.stopPrank();
    }

    function test_createRound_rejectsLessThanTwoOptions() public {
        string[] memory one = new string[](1); one[0] = "Only";
        vm.prank(operator);
        vm.expectRevert(BallotRegistry.TooFewOptions.selector);
        reg.createRound(7, "q", one, bytes32(0), uint64(block.timestamp + 1));
    }
}
