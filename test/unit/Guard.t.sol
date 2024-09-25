pragma solidity ^0.8.13;

import {Enum} from "@safe/common/Enum.sol";

import {console} from "forge-std/Test.sol";

import {Guard} from "src/Guard.sol";
import {CallHelper} from "test/utils/CallHelper.t.sol";

contract GuardUnitTest is CallHelper {
    Guard public guard;

    address public timelock;

    address[] public owners;

    /// @notice storage slot for the guard
    uint256 internal constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @notice storage slot for the fallback handler
    /// keccak256("fallback_manager.handler.address")
    uint256 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    function setUp() public {
        guard = new Guard();
        vm.etch(timelock, hex"FF");
        owners = new address[](0);
    }

    function testCheckTransaction() public view {
        guard.checkTransaction(
            address(0),
            0,
            "",
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(9)),
            "",
            address(0)
        );

        /// transaction is fine within the allowed time range
        guard.checkTransaction(
            address(0),
            0,
            "",
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(9)),
            "",
            address(0)
        );
    }

    function testTransactionDelegateCallFails() public {
        vm.expectRevert("Guard: delegate call disallowed");
        guard.checkTransaction(
            address(this),
            0,
            "",
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(9)),
            "",
            address(0)
        );
    }

    function testTransactionToSelfFailsValue() public {
        vm.expectRevert("Guard: no self calls");
        guard.checkTransaction(
            address(this),
            1,
            "",
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(9)),
            "",
            address(0)
        );
    }

    function testTransactionToSelfFailsData() public {
        vm.expectRevert("Guard: no self calls");
        guard.checkTransaction(
            address(this),
            0,
            hex"FF",
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(9)),
            "",
            address(0)
        );
    }

    function testCheckAfterExecutionNoOp() public view {
        guard.checkAfterExecution(bytes32(0), false);
    }

    function getStorageAt(uint256 offset, uint256 length)
        public
        view
        returns (bytes memory)
    {
        bytes memory result = new bytes(length * 32);
        for (uint256 index = 0; index < length; index++) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                let word := sload(add(offset, index))
                mstore(add(add(result, 0x20), mul(index, 0x20)), word)
            }
        }
        return result;
    }
}
