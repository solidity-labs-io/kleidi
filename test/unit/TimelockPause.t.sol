pragma solidity 0.8.25;

import "test/utils/TimelockUnitFixture.sol";

contract TimelockPauseUnitTest is TimelockUnitFixture {
    function testSetup() public view {
        assertEq(timelock.pauseGuardian(), guardian, "guardian incorrectly set");
        assertEq(
            timelock.pauseDuration(),
            PAUSE_DURATION,
            "pause duration incorrectly set"
        );
        assertFalse(
            timelock.pauseStartTime() != 0, "pause should not be used yet"
        );
        assertEq(timelock.pauseStartTime(), 0, "pauseStartTime should be 0");
    }

    /// Pause Tests
    /// - test that functions revert when paused:
    ///    - schedule
    ///    - scheduleBatch
    ///    - execute
    ///    - executeBatch

    function testScheduleFailsWhenPaused() public {
        vm.prank(guardian);
        timelock.pause();

        vm.expectRevert("Pausable: paused");
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testScheduleBatchFailsWhenPaused() public {
        vm.prank(guardian);
        timelock.pause();

        vm.expectRevert("Pausable: paused");
        vm.prank(address(safe));
        timelock.scheduleBatch(
            new address[](0),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testExecuteFailsWhenPaused() public {
        vm.prank(guardian);
        timelock.pause();

        vm.expectRevert("Pausable: paused");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );
    }

    function testExecuteBatchFailsWhenPaused() public {
        vm.prank(guardian);
        timelock.pause();

        vm.expectRevert("Pausable: paused");
        timelock.executeBatch(
            new address[](0), new uint256[](0), new bytes[](0), bytes32(0)
        );
    }

    function testSetGuardianSucceedsAsTimelockAndUnpauses() public {
        address newGuardian = address(0x22222);
        vm.prank(guardian);
        timelock.pause();

        assertTrue(timelock.paused(), "not paused");
        assertTrue(timelock.pauseStartTime() != 0, "pause should not be used");
        assertEq(
            timelock.pauseStartTime(),
            block.timestamp,
            "pauseStartTime should be 0"
        );

        vm.prank(address(timelock));
        timelock.setGuardian(newGuardian);

        assertEq(
            timelock.pauseGuardian(),
            newGuardian,
            "new guardian not correctly set"
        );
        assertEq(timelock.pauseStartTime(), 0, "pauseStartTime should be 0");
        assertFalse(timelock.paused(), "timelock should not be paused");
        assertFalse(timelock.pauseStartTime() != 0, "pause should not be used");
    }

    function testGuardianPauseAfterUnpauseFails() public {
        vm.prank(guardian);
        timelock.pause();

        timelock.pauseGuardian();

        assertTrue(timelock.paused(), "not paused");
        assertTrue(timelock.pauseStartTime() != 0, "pause should not be used");
        assertEq(
            timelock.pauseStartTime(),
            block.timestamp,
            "pauseStartTime should be 0"
        );

        vm.warp(block.timestamp + PAUSE_DURATION);

        assertTrue(timelock.paused(), "timelock should be paused");

        vm.expectRevert("Pausable: paused");
        vm.prank(guardian);
        timelock.pause();

        vm.warp(block.timestamp + 1);
        assertFalse(timelock.paused(), "timelock should not be paused");

        timelock.pauseGuardian();

        vm.expectRevert("ConfigurablePauseGuardian: only pause guardian");
        vm.prank(guardian);
        timelock.pause();
    }

    function testUpdatePauseDurationTimelockSucceeds(uint128 newDuration)
        public
    {
        newDuration = uint128(
            _bound(
                newDuration,
                timelock.MIN_PAUSE_DURATION(),
                timelock.MAX_PAUSE_DURATION()
            )
        );

        vm.prank(address(timelock));
        timelock.updatePauseDuration(newDuration);

        assertEq(
            timelock.pauseDuration(), newDuration, "pause duration not updated"
        );
    }

    function testUpdatePauseDurationLessThanMinFails() public {
        uint128 newDuration = uint128(timelock.MIN_PAUSE_DURATION()) - 1;

        vm.expectRevert("ConfigurablePause: pause duration out of bounds");
        vm.prank(address(timelock));
        timelock.updatePauseDuration(newDuration);
    }

    function testUpdatePauseDurationGtMaxFails() public {
        uint128 newDuration = uint128(timelock.MAX_PAUSE_DURATION()) + 1;

        vm.expectRevert("ConfigurablePause: pause duration out of bounds");
        vm.prank(address(timelock));
        timelock.updatePauseDuration(newDuration);
    }
}
