// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Enum} from "@safe/common/Enum.sol";

import {console} from "forge-std/Test.sol";

import {CallHelper} from "test/utils/CallHelper.t.sol";
import {TimeRestricted} from "src/TimeRestricted.sol";

contract TimeRestrictedUnitTest is CallHelper {
    TimeRestricted public restricted;
    address public timelock;

    address[] public owners;

    address[] public modules0;

    address[] public modules1;

    /// @notice storage slot for the guard
    uint256 internal constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @notice storage slot for the fallback handler
    /// keccak256("fallback_manager.handler.address")
    uint256 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    function setUp() public {
        restricted = new TimeRestricted();
        vm.etch(timelock, hex"FF");
        owners = new address[](0);

        for (uint256 i = 0; i < 10; i++) {
            modules0.push(address(uint160(uint256(i + 100))));
        }

        for (uint256 i = 0; i < 5; i++) {
            modules1.push(address(uint160(uint256(i + 110))));
        }
    }

    function testEnableSafe() public {
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](1);
        allowedDays[0] = 3;

        _initializeConfiguration({
            caller: address(this),
            timeRestricted: address(restricted),
            timelock: timelock,
            timeRanges: ranges,
            allowedDays: allowedDays
        });

        assertEq(
            restricted.numDaysEnabled(address(this)),
            1,
            "incorrect days, should be 1"
        );
        assertEq(
            restricted.authorizedTimelock(address(this)),
            timelock,
            "timelock not set correctly"
        );
    }

    function testInitializeFailsAlreadyConfigured() public {
        testEnableSafe();
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](1);
        allowedDays[0] = 3;

        vm.expectRevert("TimeRestricted: already initialized");
        restricted.initializeConfiguration(timelock, ranges, allowedDays);
    }

    function testInitializeFailsTimelockSet() public {
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](1);
        allowedDays[0] = 3;

        bytes32 slot = keccak256(abi.encode(address(this), 1));
        vm.store(address(restricted), slot, bytes32(type(uint256).max));
        assertEq(
            restricted.authorizedTimelock(address(this)),
            address(type(uint160).max),
            "timelock not set"
        );

        vm.expectRevert("TimeRestricted: timelock already set");
        restricted.initializeConfiguration(timelock, ranges, allowedDays);
    }

    function testInitializeFailsArityMismatch() public {
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](2);
        allowedDays[0] = 3;

        vm.expectRevert("TimeRestricted: arity mismatch");
        restricted.initializeConfiguration(timelock, ranges, allowedDays);
    }

    function testInitializeFailsTimelockEqSafe() public {
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](1);
        allowedDays[0] = 3;

        vm.expectRevert("TimeRestricted: safe cannot equal timelock");
        restricted.initializeConfiguration(address(this), ranges, allowedDays);
    }

    function testInitializeFailsTimelockNoBytecode() public {
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](1);
        allowedDays[0] = 3;

        vm.expectRevert("TimeRestricted: invalid timelock");
        restricted.initializeConfiguration(
            address(100000000), ranges, allowedDays
        );
    }

    function testInitializeFailsSafeNoBytecode() public {
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](1);
        allowedDays[0] = 3;

        vm.prank(address(100000000));
        vm.expectRevert("TimeRestricted: invalid safe");
        restricted.initializeConfiguration(timelock, ranges, allowedDays);
    }

    function testInitializeFailsSafeHasFallbackHandler() public {
        TimeRestricted.TimeRange[] memory ranges =
            new TimeRestricted.TimeRange[](1);
        ranges[0] = TimeRestricted.TimeRange(10, 11);

        /// tx's only allowed on Wednesday
        uint8[] memory allowedDays = new uint8[](1);
        allowedDays[0] = 3;

        uint256 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        assembly {
            sstore(slot, 1)
        }

        vm.expectRevert(
            "TimeRestricted: cannot initialize with fallback handler"
        );
        restricted.initializeConfiguration(timelock, ranges, allowedDays);
    }

    function testSafeCannotModifySchedule() public {
        testEnableSafe();

        vm.expectRevert("TimeRestricted: only timelock");
        restricted.editTimeRange(address(this), 1, 1, 23);
    }

    function testSafeCannotAddToSchedule() public {
        testEnableSafe();

        vm.expectRevert("TimeRestricted: only timelock");
        restricted.addTimeRange(address(this), 1, 1, 23);
    }

    function testSafeCannotDisableGuard() public {
        testEnableSafe();

        vm.expectRevert("TimeRestricted: only timelock");
        restricted.disableGuard(address(this));
    }

    function testSafeCannotRemoveAllowedDay() public {
        testEnableSafe();

        vm.expectRevert("TimeRestricted: only timelock");
        restricted.removeAllowedDay(address(this), 3);
    }

    function testSetup() public view {
        assertFalse(restricted.safeEnabled(address(this)), "safe not enabled");
        assertTrue(
            restricted.transactionAllowed(address(this), 10000),
            "transaction should be allowed"
        );
    }

    function testTransactionsAlwaysAllowedEnabled(uint256 timestamp)
        public
        view
    {
        assertFalse(restricted.safeEnabled(address(this)), "safe not enabled");
        assertTrue(
            restricted.transactionAllowed(address(this), timestamp),
            "transaction should be allowed"
        );
    }

    function testEnableSafeValidDaysHoursSuccess() public {
        testEnableSafe();

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });

        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        (uint8 startHour, uint8 endHour) =
            restricted.dayTimeRanges(address(this), 1);

        assertEq(startHour, 0, "start hour");
        assertEq(endHour, 1, "end hour");
        assertTrue(
            restricted.transactionAllowed(address(this), 1712537758),
            "transaction should be allowed"
        );
    }

    function testEnableSafeInvalidDayFails() public {
        testEnableSafe();

        /// 0 is an invalid day of the week
        vm.expectRevert("invalid day of week");
        vm.prank(timelock);
        restricted.addTimeRange(address(this), 0, 0, 1);

        /// 8 is an invalid day of the week
        vm.expectRevert("invalid day of week");
        vm.prank(timelock);
        restricted.addTimeRange(address(this), 8, 0, 1);
    }

    function testEnableSafeInvalidHoursFails() public {
        testEnableSafe();

        /// 24 is an invalid hour
        vm.expectRevert("invalid end hour");
        vm.prank(timelock);
        restricted.addTimeRange(address(this), 1, 1, 24);

        /// 24 is an invalid hour
        vm.expectRevert("invalid time range");
        vm.prank(timelock);
        restricted.addTimeRange(address(this), 1, 2, 1);

        /// hours are the same, invalid
        vm.expectRevert("invalid time range");
        vm.prank(timelock);
        restricted.addTimeRange(address(this), 1, 2, 2);
    }

    function testEnableAlreadyEnabledDaySucceeds() public {
        testEnableSafe();

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        vm.prank(timelock);
        vm.expectRevert("day already allowed");
        restricted.addTimeRange(address(this), 1, 0, 1);
    }

    function testEditTimeRangeExistingDaySucceeds() public {
        testEnableSafe();

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        _editTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 1,
            endHour: 2
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        (uint8 startHour, uint8 endHour) =
            restricted.dayTimeRanges(address(this), 1);

        assertEq(startHour, 1, "start hour");
        assertEq(endHour, 2, "end hour");
    }

    function testEditTimeRangeNotAllowed() public {
        testEnableSafe();

        vm.prank(timelock);
        vm.expectRevert("day not allowed");
        restricted.editTimeRange(address(this), 1, 1, 23);
    }

    function testEditTimeRangeInvalidHour() public {
        testEnableSafe();

        vm.prank(timelock);
        vm.expectRevert("invalid end hour");
        restricted.editTimeRange(address(this), 1, 1, 24);
    }

    function testEditTimeRangeStartHourLtEndHour() public {
        testEnableSafe();

        vm.prank(timelock);
        vm.expectRevert("invalid time range");
        restricted.editTimeRange(address(this), 1, 23, 23);

        vm.prank(timelock);
        vm.expectRevert("invalid time range");
        restricted.editTimeRange(address(this), 1, 23, 22);
    }

    function testEditTimeRangeInvalidWeekday() public {
        testEnableSafe();

        vm.prank(timelock);
        vm.expectRevert("invalid day of week");
        restricted.editTimeRange(address(this), 8, 22, 23);

        vm.prank(timelock);
        vm.expectRevert("invalid day of week");
        restricted.editTimeRange(address(this), 0, 22, 23);
    }

    function testRemoveAllowedDay() public {
        testEnableSafe();

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 2,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        vm.prank(timelock);
        _removeAllowedDay({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1
        });

        {
            (uint8 startHour, uint8 endHour) =
                restricted.dayTimeRanges(address(this), 1);

            assertEq(startHour, 0, "start hour");
            assertEq(endHour, 0, "end hour");
        }

        {
            (uint8 startHour, uint8 endHour) =
                restricted.dayTimeRanges(address(this), 2);

            assertEq(startHour, 0, "start hour");
            assertEq(endHour, 1, "end hour");
        }
    }

    function testRemoveAllowedDayInvalidDay() public {
        testEnableSafe();

        vm.prank(timelock);
        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(address(this), 0);

        vm.prank(timelock);
        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(address(this), 8);

        vm.prank(timelock);
        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(address(this), 9);

        vm.prank(timelock);
        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(address(this), 255);
    }

    function testRemoveAllowedDayNotAlreadyAllowed() public {
        testEnableSafe();

        vm.prank(timelock);
        vm.expectRevert("day not allowed");
        restricted.removeAllowedDay(address(this), 1);
    }

    function testCannotRemoveFinalDay() public {
        testEnableSafe();

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");
        assertEq(
            restricted.numDaysEnabled(address(this)),
            2,
            "incorrect days, should be 2"
        );

        _removeAllowedDay({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1
        });

        assertEq(
            restricted.numDaysEnabled(address(this)),
            1,
            "incorrect days, should be 1"
        );

        uint8 activeDay = uint8(restricted.safeDaysEnabled(address(this))[0]);

        assertEq(activeDay, 3, "incorrect active day, should be Wednesday");

        vm.prank(timelock);
        vm.expectRevert("day not allowed");
        restricted.removeAllowedDay(address(this), 1);

        vm.prank(timelock);
        vm.expectRevert();
        restricted.removeAllowedDay(address(this), activeDay);
    }

    function testDisableGuardSucceeds() public {
        testEnableSafe();

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        _disableGaurd({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this)
        });

        assertFalse(restricted.safeEnabled(address(this)), "safe not disabled");

        (uint8 startHour, uint8 endHour) =
            restricted.dayTimeRanges(address(this), 1);

        assertEq(startHour, 0, "start hour");
        assertEq(endHour, 0, "end hour");
    }

    function testCheckTransaction() public {
        testEnableSafe();

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");
        assertTrue(
            restricted.transactionAllowed(address(this), 1712537758),
            "transaction should be allowed"
        );

        vm.warp(1712537758);

        /// transaction is fine within the allowed time range
        restricted.checkTransaction(
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

        vm.warp(block.timestamp + 1 days);

        vm.expectRevert("TimeRestricted: transaction outside of allowed hours");
        restricted.checkTransaction(
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
        vm.expectRevert("TimeRestricted: delegate call disallowed");
        restricted.checkTransaction(
            address(0),
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

    function testTransactionToSelfFails() public {
        vm.expectRevert("TimeRestricted: no self calls");
        restricted.checkTransaction(
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

    function testCheckAfterExecutionNoOpFailure() public {
        restricted.checkAfterExecution(bytes32(0), false);
    }

    function testCheckAfterExecutionNoFailure() public {
        testEnableSafe();

        address guard = address(restricted);
        // for checkAfterExecution guard check
        assembly {
            sstore(GUARD_STORAGE_SLOT, guard)
        }

        _addTimeRange({
            caller: timelock,
            timeRestricted: address(restricted),
            safe: address(this),
            dayOfWeek: 1,
            startHour: 0,
            endHour: 1
        });
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        assertTrue(
            restricted.transactionAllowed(address(this), 1712537758),
            "transaction should be allowed"
        );

        vm.warp(1712537758);

        owners = new address[](1);
        owners[0] = address(100000000);

        restricted.checkTransaction(
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

        restricted.checkAfterExecution(bytes32(0), true);
    }

    /// mocks to allow tests to pass

    function getOwners() public view returns (address[] memory) {
        return owners;
    }

    function getStorageAt(uint256 offset, uint256 length)
        public
        view
        returns (bytes memory)
    {
        bytes memory result = new bytes(length * 32);
        for (uint256 index = 0; index < length; index++) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                let word := sload(add(offset, index))
                mstore(add(add(result, 0x20), mul(index, 0x20)), word)
            }
        }
        return result;
    }
}
