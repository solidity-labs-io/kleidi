// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Enum} from "@safe/common/Enum.sol";

import {Test, console} from "forge-std/Test.sol";

import {TimeRestricted} from "src/TimeRestricted.sol";

contract TimeRestrictedUnitTest is Test {
    TimeRestricted public restricted;

    function setUp() public {
        restricted = new TimeRestricted();
    }

    function testSetup() public view {
        assertFalse(restricted.safeEnabled(address(this)), "safe not enabled");
        assertTrue(
            restricted.transactionAllowed(address(this), 10000),
            "transaction should be allowed"
        );
    }

    function testTransactionsAlwaysAllowedEnabled(
        uint256 timestamp
    ) public view {
        assertFalse(restricted.safeEnabled(address(this)), "safe not enabled");
        assertTrue(
            restricted.transactionAllowed(address(this), timestamp),
            "transaction should be allowed"
        );
    }

    function testEnableSafeValidDaysHoursSuccess() public {
        restricted.addTimeRange(1, 0, 1);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        (uint8 startHour, uint8 endHour) = restricted.dayTimeRanges(
            address(this),
            1
        );

        assertEq(startHour, 0, "start hour");
        assertEq(endHour, 1, "end hour");
        assertTrue(
            restricted.transactionAllowed(address(this), 1712537758),
            "transaction should be allowed"
        );
    }

    function testEnableSafeInvalidDayFails() public {
        /// 0 is an invalid day of the week
        vm.expectRevert("invalid day of week");
        restricted.addTimeRange(0, 0, 1);

        /// 8 is an invalid day of the week
        vm.expectRevert("invalid day of week");
        restricted.addTimeRange(8, 0, 1);
    }

    function testEnableSafeInvalidHoursFails() public {
        /// 24 is an invalid hour
        vm.expectRevert("invalid end hour");
        restricted.addTimeRange(1, 1, 24);

        /// 24 is an invalid hour
        vm.expectRevert("invalid time range");
        restricted.addTimeRange(1, 2, 1);

        /// hours are the same, invalid
        vm.expectRevert("invalid time range");
        restricted.addTimeRange(1, 2, 2);
    }

    function testEnableAlreadyEnabledDaySucceeds() public {
        restricted.addTimeRange(1, 0, 1);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        vm.expectRevert("day already allowed");
        restricted.addTimeRange(1, 0, 1);
    }

    function testEditTimeRangeExistingDaySucceeds() public {
        restricted.addTimeRange(1, 0, 1);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        restricted.editTimeRange(1, 1, 2);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        (uint8 startHour, uint8 endHour) = restricted.dayTimeRanges(
            address(this),
            1
        );

        assertEq(startHour, 1, "start hour");
        assertEq(endHour, 2, "end hour");
    }

    function testEditTimeRangeNotAllowed() public {
        vm.expectRevert("day not allowed");
        restricted.editTimeRange(1, 1, 23);
    }

    function testEditTimeRangeInvalidHour() public {
        vm.expectRevert("invalid end hour");
        restricted.editTimeRange(1, 1, 24);
    }

    function testEditTimeRangeStartHourLtEndHour() public {
        vm.expectRevert("invalid time range");
        restricted.editTimeRange(1, 23, 23);

        vm.expectRevert("invalid time range");
        restricted.editTimeRange(1, 23, 22);
    }

    function testEditTimeRangeInvalidWeekday() public {
        vm.expectRevert("invalid day of week");
        restricted.editTimeRange(8, 22, 23);

        vm.expectRevert("invalid day of week");
        restricted.editTimeRange(0, 22, 23);
    }

    function testRemoveAllowedDay() public {
        restricted.addTimeRange(1, 0, 1);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        restricted.addTimeRange(2, 0, 1);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        restricted.removeAllowedDay(1);

        {
            (uint8 startHour, uint8 endHour) = restricted.dayTimeRanges(
                address(this),
                1
            );

            assertEq(startHour, 0, "start hour");
            assertEq(endHour, 0, "end hour");
        }

        {
            (uint8 startHour, uint8 endHour) = restricted.dayTimeRanges(
                address(this),
                2
            );

            assertEq(startHour, 0, "start hour");
            assertEq(endHour, 1, "end hour");
        }
    }

    function testRemoveAllowedDayInvalidDay() public {
        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(0);

        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(8);

        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(9);

        vm.expectRevert("invalid day of week");
        restricted.removeAllowedDay(255);
    }

    function testRemoveAllowedDayNotAlreadyAllowed() public {
        vm.expectRevert("day not allowed to be removed");
        restricted.removeAllowedDay(1);
    }

    function testCannotRemoveFinalDay() public {
        restricted.addTimeRange(1, 0, 1);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        vm.expectRevert();
        restricted.removeAllowedDay(1);
    }

    function testDisableGuardSucceeds() public {
        restricted.addTimeRange(1, 0, 1);
        assertTrue(restricted.safeEnabled(address(this)), "safe enabled");

        restricted.disableGuard();
        assertFalse(restricted.safeEnabled(address(this)), "safe not disabled");

        (uint8 startHour, uint8 endHour) = restricted.dayTimeRanges(
            address(this),
            1
        );

        assertEq(startHour, 0, "start hour");
        assertEq(endHour, 0, "end hour");
    }

    function testCheckTransaction() public {
        restricted.addTimeRange(1, 0, 1);
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

        vm.expectRevert("transaction outside of allowed hours");
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
}
