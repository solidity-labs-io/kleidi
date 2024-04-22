// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BokkyPooBahsDateTimeLibrary} from "src/calendar/BokkyPooBahsDateTimeLibrary.sol";

contract TimeUnitTest is Test {
    using BokkyPooBahsDateTimeLibrary for *;

    function testHourNeverGt23(uint256 day) public pure {
        assertLt(day.getHour(), 24, "Hour should be less than 24");
    }

    function testDayRange(uint256 day) public pure {
        assertLt(
            day.getDayOfWeek(),
            8,
            "Day of week should be less than or equal to 7"
        );
        assertLt(0, day.getDayOfWeek(), "Day of week should be greater than 0");
    }
}
