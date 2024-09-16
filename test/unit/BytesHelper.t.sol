pragma solidity 0.8.25;

import {BytesHelper} from "@src/BytesHelper.sol";

import {Test} from "forge-std/Test.sol";

contract BytesHelperUnitTest is Test {
    using BytesHelper for bytes;

    function testGetFunctionSignatureFailsLt4Bytes() public {
        bytes memory toSlice = new bytes(0);
        vm.expectRevert("No function signature");
        toSlice.getFunctionSignature();

        toSlice = new bytes(1);
        vm.expectRevert("No function signature");
        toSlice.getFunctionSignature();

        toSlice = new bytes(2);
        vm.expectRevert("No function signature");
        toSlice.getFunctionSignature();

        toSlice = new bytes(3);
        vm.expectRevert("No function signature");
        toSlice.getFunctionSignature();
    }

    function testGetFirstWordFailsLt32Bytes() public {
        bytes memory toSlice = new bytes(0);
        vm.expectRevert("Length less than 32 bytes");
        toSlice.getFirstWord();

        toSlice = new bytes(31);
        vm.expectRevert("Length less than 32 bytes");
        toSlice.getFirstWord();
    }

    function testSliceBytesFailsStartGtLength() public {
        bytes memory toSlice = new bytes(10);
        vm.expectRevert(
            "Start index is greater than the length of the byte string"
        );
        toSlice.sliceBytes(11, 0);
    }

    function testSliceBytesFailsEndGtLength() public {
        bytes memory toSlice = new bytes(10);
        vm.expectRevert(
            "End index is greater than the length of the byte string"
        );
        toSlice.sliceBytes(0, 11);
    }

    function testSliceBytesSucceedsEqEndLength() public pure {
        bytes memory toSlice = new bytes(10);
        toSlice.sliceBytes(0, 10);
    }

    function testSliceBytesFailsStartGtEnd() public {
        bytes memory toSlice = new bytes(10);
        vm.expectRevert("Start index not less than end index");
        toSlice.sliceBytes(6, 5);
    }

    function testSliceBytesFailsStartEqEnd() public {
        bytes memory toSlice = new bytes(10);
        vm.expectRevert("Start index not less than end index");
        toSlice.sliceBytes(6, 6);
    }
}
