// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";

import {MockLending} from "test/mock/MockLending.sol";
import {MockSafe} from "test/mock/MockSafe.sol";
import {Timelock} from "src/Timelock.sol";

contract TimelockTest is Test {
    /// @notice reference to the Timelock contract
    Timelock private timelock;

    /// @notice reference to the MockSafe contract
    MockSafe private safe;

    /// @notice empty for now, will change once tests progress
    address[] public contractAddresses;

    /// @notice empty for now, will change once tests progress
    bytes4[] public selector;

    /// @notice empty for now, will change once tests progress
    uint16[] public startIndex;

    /// @notice empty for now, will change once tests progress
    uint16[] public endIndex;

    /// @notice empty for now, will change once tests progress
    bytes[] public data;

    /// @notice address of the guardian that can pause and break glass in case of emergency
    address public guardian = address(0x11111);

    /// @notice duration of pause once glass is broken in seconds
    uint128 public constant PAUSE_DURATION = 10 days;

    /// @notice minimum delay for a timelocked transaction in seconds
    uint256 public constant MINIMUM_DELAY = 3 days;

    /// @notice expiration period for a timelocked transaction in seconds
    uint256 public constant EXPIRATION_PERIOD = 5 days;

    function setUp() public {
        // at least start at unix timestamp of 1m so that block timestamp isn't 0
        vm.warp(block.timestamp + 1_000_000);

        safe = new MockSafe();

        // Assume the necessary parameters for the constructor
        timelock = new Timelock(
            address(safe), // _safe
            MINIMUM_DELAY, // _minDelay
            EXPIRATION_PERIOD, // _expirationPeriod
            guardian, // _pauser
            PAUSE_DURATION, // _pauseDuration
            contractAddresses, // contractAddresses
            selector, // selector
            startIndex, // startIndex
            endIndex, // endIndex
            data // data
        );
    }

    function testSetup() public view {
        assertEq(timelock.safe(), address(safe), "safe incorrectly set");
        assertEq(
            timelock.minDelay(),
            MINIMUM_DELAY,
            "minDelay incorrectly set"
        );
        assertEq(
            timelock.pauseGuardian(),
            guardian,
            "guardian incorrectly set"
        );
        assertEq(
            timelock.pauseDuration(),
            PAUSE_DURATION,
            "pause duration incorrectly set"
        );
        assertFalse(timelock.pauseUsed(), "pause should not be used yet");
        assertEq(timelock.pauseStartTime(), 0, "pauseStartTime should be 0");
        assertEq(
            timelock.expirationPeriod(),
            EXPIRATION_PERIOD,
            "expirationPeriod incorrectly set"
        );
        assertEq(timelock.getAllProposals().length, 0, "no proposals yet");
    }

    function testScheduleProposalSafeSucceeds() public returns (bytes32) {
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );

        bytes32 id = timelock.hashOperation(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
            bytes32(0)
        );

        assertTrue(
            timelock.isOperationPending(id),
            "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id),
            "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id),
            "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0],
            id,
            "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length,
            1,
            "proposal length incorrect"
        );

        return id;
    }

    function testScheduleBatchProposalSafeSucceeds()
        public
        returns (bytes32, address[] memory, uint256[] memory, bytes[] memory)
    {
        uint256 newDelay = MINIMUM_DELAY + 3 days;

        address[] memory targets = new address[](1);
        targets[0] = address(timelock);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSelector(
            timelock.updateDelay.selector,
            newDelay
        );

        vm.prank(address(safe));
        timelock.scheduleBatch(
            targets,
            values,
            datas,
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );

        bytes32 id = timelock.hashOperationBatch(
            targets,
            values,
            datas,
            bytes32(0),
            bytes32(0)
        );

        assertTrue(
            timelock.isOperationPending(id),
            "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id),
            "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id),
            "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0],
            id,
            "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length,
            1,
            "proposal length incorrect"
        );

        return (id, targets, values, datas);
    }

    function testExecuteBatchSucceds() public {
        (
            bytes32 id,
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory datas
        ) = testScheduleBatchProposalSafeSucceeds();

        vm.warp(block.timestamp + MINIMUM_DELAY);

        timelock.executeBatch(targets, values, datas, bytes32(0), bytes32(0));

        assertTrue(timelock.isOperationDone(id), "operation should be done");
        assertEq(
            timelock.minDelay(),
            MINIMUM_DELAY + 3 days,
            "minDelay should be updated"
        );
        assertEq(
            timelock.getAllProposals().length,
            0,
            "proposal length incorrect"
        );

        vm.expectRevert("Timelock: proposal does not exist");
        timelock.executeBatch(targets, values, datas, bytes32(0), bytes32(0));
    }

    function testStatePostSchedule() public {
        bytes32 id = testScheduleProposalSafeSucceeds();

        vm.warp(block.timestamp + MINIMUM_DELAY);

        assertTrue(
            timelock.isOperationPending(id),
            "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertTrue(
            timelock.isOperationReady(id),
            "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id),
            "operation should not be done"
        );
    }

    function testScheduleNonSafeFails() public {
        vm.expectRevert("Timelock: caller is not the safe");
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testScheduleBatchNonSafeFails() public {
        vm.expectRevert("Timelock: caller is not the safe");
        timelock.scheduleBatch(
            new address[](0),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testPauseNonGuardianFails() public {
        vm.expectRevert("ConfigurablePauseGuardian: only pause guardian");
        timelock.pause();
    }

    function testPauseRemovesAllScheduledProposals() public {
        bytes32 id = testScheduleProposalSafeSucceeds();

        vm.prank(guardian);
        timelock.pause();

        assertEq(timelock.pauseStartTime(), block.timestamp, "pauseStartTime");
        assertTrue(timelock.pauseUsed(), "pause should be used");
        assertTrue(timelock.paused(), "timelock should be paused");

        assertFalse(
            timelock.isOperationPending(id),
            "operation should not be pending"
        );
        assertFalse(
            timelock.isOperation(id),
            "operation should not be present"
        );
        assertFalse(
            timelock.isOperationReady(id),
            "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id),
            "operation should not be done"
        );

        assertEq(timelock.getAllProposals().length, 0, "no proposals yet");
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
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
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
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
            bytes32(0)
        );
    }

    function testExecuteBatchFailsWhenPaused() public {
        vm.prank(guardian);
        timelock.pause();

        vm.expectRevert("Pausable: paused");
        timelock.executeBatch(
            new address[](0),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            bytes32(0)
        );
    }

    /// ACL Tests
    /// - test that only the timelock can:
    ///     - addCalldataChecks
    ///     - removeCalldataChecks
    ///     - removeAllCalldataChecks
    ///     - updateDelay
    ///     - updateExpirationPeriod
    /// prove this through both positive and negative tests
    /// revert when not timelock, and succeed when timelock

    function testAddCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.addCalldataChecks(
            contractAddresses,
            selector,
            startIndex,
            endIndex,
            data
        );
    }

    function testRemoveCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.removeAllCalldataChecks(address(this), bytes4(0xFFFFFFFF), 0);
    }

    function testRemoveAllCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.removeAllCalldataChecks(contractAddresses, selector);
    }

    function testUpdateDelayFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.updateDelay(0);
    }

    function testUpdateExpirationPeriodFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.updateExpirationPeriod(0);
    }

    function testUpdateDelaySucceedsAsTimelock() public {
        uint256 minDelay = timelock.MIN_DELAY();

        vm.prank(address(timelock));
        timelock.updateDelay(minDelay);

        assertEq(minDelay, timelock.minDelay(), "minDelay should be updated");
    }

    function testUpdateExpirationPeriodSucceedsAsTimelock() public {
        uint256 minDelay = timelock.MIN_DELAY();

        vm.prank(address(timelock));
        timelock.updateExpirationPeriod(minDelay);

        assertEq(
            minDelay,
            timelock.expirationPeriod(),
            "expirationPeriod should be updated"
        );
    }

    function testScheduleCallRevertsIfAlreadyScheduled() public {
        // Prepare the scheduling parameters
        // Call schedule() first time
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );
        // Expect revert on second call with same parameters
        vm.prank(address(safe));
        vm.expectRevert("Timelock: duplicate id");
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testScheduleCallSucceedsUnderNormalConditions() public {
        // Prepare the scheduling parameters
        // Call schedule() with valid parameters
    }

    function testExecuteCallRevertsIfNotReady() public {
        // Prepare and schedule a call
        // Attempt to execute before it's ready
    }

    function testExecuteCallSucceedsWhenReady() public {
        // Prepare and schedule a call
        bytes32 id = testScheduleProposalSafeSucceeds();

        // Simulate time passing
        vm.warp(block.timestamp + MINIMUM_DELAY);

        // Execute the call as anyone, should succeed
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector,
                MINIMUM_DELAY
            ),
            bytes32(0),
            bytes32(0)
        );

        assertEq(
            timelock.minDelay(),
            MINIMUM_DELAY,
            "minDelay should be updated"
        );
        assertTrue(timelock.isOperationDone(id), "operation should be done");
    }

    function testExecuteCallUpdateExpirationPeriodSucceedsWhenReady() public {
        uint256 newExpirationPeriod = 50 days;
        // Prepare and schedule a call
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateExpirationPeriod.selector,
                newExpirationPeriod
            ),
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );

        // Simulate time passing
        vm.warp(block.timestamp + MINIMUM_DELAY);

        // Execute the call as anyone, should succeed
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateExpirationPeriod.selector,
                newExpirationPeriod
            ),
            bytes32(0),
            bytes32(0)
        );

        bytes32 id = timelock.hashOperation(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateExpirationPeriod.selector,
                newExpirationPeriod
            ),
            bytes32(0),
            bytes32(0)
        );

        assertEq(
            timelock.expirationPeriod(),
            newExpirationPeriod,
            "expirationPeriod should be updated"
        );

        assertFalse(
            timelock.isOperationPending(id),
            "operation should not be pending"
        );
        assertTrue(timelock.isOperationDone(id), "operation should be done");
        assertTrue(timelock.isOperation(id), "operation should exist");

        assertEq(
            timelock.expirationPeriod(),
            newExpirationPeriod,
            "expirationPeriod should be updated"
        );
        assertEq(
            timelock.minDelay(),
            MINIMUM_DELAY,
            "minDelay should be updated"
        );
    }

    function testWhitelistingCalldataSucceeds() public {
        address[] memory targets = new address[](1);
        targets[0] = address(timelock);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        MockLending lending = new MockLending();

        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.withdraw.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        /// can only withdraw and deposit to timelock
        bytes[] memory checkedCalldata = new bytes[](2);
        checkedCalldata[0] = abi.encodePacked(address(timelock));
        checkedCalldata[1] = abi.encodePacked(address(timelock));

        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSelector(
            timelock.addCalldataChecks.selector,
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldata
        );

        vm.prank(address(safe));
        timelock.scheduleBatch(
            targets,
            values,
            datas,
            bytes32(0),
            bytes32(0),
            MINIMUM_DELAY
        );

        bytes32 id = timelock.hashOperationBatch(
            targets,
            values,
            datas,
            bytes32(0),
            bytes32(0)
        );

        assertTrue(
            timelock.isOperationPending(id),
            "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id),
            "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id),
            "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0],
            id,
            "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length,
            1,
            "proposal length incorrect"
        );

        vm.warp(block.timestamp + MINIMUM_DELAY);

        vm.prank(address(safe));
        timelock.executeBatch(targets, values, datas, bytes32(0), bytes32(0));

        address[] memory safeSigner = new address[](1);
        safeSigner[0] = address(this);

        safe.setOwners(safeSigner);

        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(
                lending.deposit.selector,
                address(timelock),
                100
            )
        );

        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(
                lending.withdraw.selector,
                address(timelock),
                100
            )
        );
    }

    function testCancelOperationEmitsCancelledEvent() public {
        // Prepare and schedule a call
        // Cancel the operation
        // Check that the Cancelled event is emitted
    }

    function testUpdateDelayRevertsIfCallerNotTimelock() public {
        // Try to update delay without the correct permissions
    }

    function testUpdateDelaySucceedsWithCorrectPermissions() public {
        // Properly update delay through a scheduled operation
    }

    function testPauseContractRevertsIfNotGuardian() public {
        // Attempt to pause the contract without being the guardian
    }

    function testPauseContractPausesAllOperations() public {
        // Pause the contract and verify that all operations are cancelled
    }

    function testExecuteWhitelistedBatchRevertsForInvalidCalldata() public {
        // Prepare whitelisted batch with invalid calldata
        // Expect revert
    }

    function testExecuteWhitelistedBatchSucceedsWithValidCalldata() public {
        // Prepare and execute a whitelisted batch with valid calldata
    }

    function testProposalsAreCleanedUpAfterExecution() public {
        // Schedule, execute and check that proposals are cleaned up
    }

    function testReceiveFunctionAcceptsEther() public {
        // Send Ether to the contract and confirm receipt
    }

    function testMinDelayChangeEmitsEvent() public {
        // Change minDelay and confirm the MinDelayChange event is emitted
    }

    function testExpirationPeriodChangeEmitsEvent() public {
        // Change expirationPeriod and confirm the ExpirationPeriodChange event is emitted
    }

    function testRoleOrOpenRoleModifierAllowsAccess() public {
        // Check that onlyRoleOrOpenRole allows access correctly
    }

    function testOnlySafeModifierRevertsForNonSafeCaller() public {
        // Check that onlySafe modifier reverts when called by non-safe
    }

    function testOnlyTimelockModifierRevertsForNonTimelockCaller() public {
        // Check that onlyTimelock modifier reverts when called by non-timelock
    }

    /// TODO test transferring NFT into the timelock and see that it succeeds
}
