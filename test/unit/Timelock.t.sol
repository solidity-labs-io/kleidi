// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC1155Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {
    IERC165,
    ERC165
} from "@openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";

import {Test, console} from "forge-std/Test.sol";

import {Timelock} from "src/Timelock.sol";
import {MockSafe} from "test/mock/MockSafe.sol";
import {MockLending} from "test/mock/MockLending.sol";
import {MockReentrancyExecutor} from "test/mock/MockReentrancyExecutor.sol";

contract TimelockUnitTest is Test {
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
    uint256 public constant MINIMUM_DELAY = 1 days;

    /// @notice expiration period for a timelocked transaction in seconds
    uint256 public constant EXPIRATION_PERIOD = 5 days;

    /// @notice Emitted when a call is performed as part of operation `id`.
    /// @param id unique identifier for the operation
    /// @param index index of the call within the operation, non zero if not first call in a batch
    /// @param target the address of the contract called
    /// @param value the amount of native asset sent with the call
    /// @param data the calldata sent with the call
    event CallExecuted(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data
    );

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
        assertEq(timelock.minDelay(), MINIMUM_DELAY, "minDelay incorrectly set");
        assertEq(timelock.pauseGuardian(), guardian, "guardian incorrectly set");
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

    function testSupportsInterface() public view {
        assertTrue(
            timelock.supportsInterface(type(IERC1155Receiver).interfaceId),
            "Timelock should support 1155 Receiver interface"
        );
        assertTrue(
            timelock.supportsInterface(type(IERC721Receiver).interfaceId),
            "Timelock should support 721 Receiver interface"
        );
        assertTrue(
            timelock.supportsInterface(type(IERC165).interfaceId),
            "Timelock should support 165 Receiver interface"
        );
    }

    function testConstructionFailures() public {
        vm.expectRevert("Timelock: delay out of bounds");
        new Timelock(
            address(0),
            MINIMUM_DELAY - 1,
            EXPIRATION_PERIOD,
            guardian,
            PAUSE_DURATION,
            contractAddresses,
            selector,
            startIndex,
            endIndex,
            data
        );

        vm.expectRevert("Timelock: expiry period too short");
        new Timelock(
            address(0),
            MINIMUM_DELAY,
            MINIMUM_DELAY - 1,
            guardian,
            PAUSE_DURATION,
            contractAddresses,
            selector,
            startIndex,
            endIndex,
            data
        );
    }

    function testScheduleProposalSafeSucceeds() public returns (bytes32) {
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0),
            MINIMUM_DELAY
        );

        bytes32 id = timelock.hashOperation(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );

        assertTrue(
            timelock.isOperationPending(id), "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0], id, "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length, 1, "proposal length incorrect"
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
        datas[0] =
            abi.encodeWithSelector(timelock.updateDelay.selector, newDelay);

        vm.prank(address(safe));
        timelock.scheduleBatch(
            targets, values, datas, bytes32(0), MINIMUM_DELAY
        );

        bytes32 id =
            timelock.hashOperationBatch(targets, values, datas, bytes32(0));

        assertTrue(
            timelock.isOperationPending(id), "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0], id, "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length, 1, "proposal length incorrect"
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

        timelock.executeBatch(targets, values, datas, bytes32(0));

        assertTrue(timelock.isOperationDone(id), "operation should be done");
        assertEq(
            timelock.minDelay(),
            MINIMUM_DELAY + 3 days,
            "minDelay should be updated"
        );
        assertEq(
            timelock.getAllProposals().length, 0, "proposal length incorrect"
        );

        vm.expectRevert("Timelock: proposal does not exist");
        timelock.executeBatch(targets, values, datas, bytes32(0));
    }

    function testStatePostSchedule() public {
        bytes32 id = testScheduleProposalSafeSucceeds();

        vm.warp(block.timestamp + MINIMUM_DELAY);

        assertTrue(
            timelock.isOperationPending(id), "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertTrue(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );
    }

    function testScheduleNonSafeFails() public {
        vm.expectRevert("Timelock: caller is not the safe");
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
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
            timelock.isOperationPending(id), "operation should not be pending"
        );
        assertFalse(timelock.isOperation(id), "operation should not be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
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

    /// ACL Tests
    /// - test that only the timelock can:
    ///     - setGuardian
    ///     - addCalldataCheck
    ///     - addCalldataChecks
    ///     - removeCalldataChecks
    ///     - removeAllCalldataChecks
    ///     - updateDelay
    ///     - updateExpirationPeriod
    /// prove this through both positive and negative tests
    /// revert when not timelock, and succeed when timelock

    function testSetGuardianFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.setGuardian(address(0));
    }

    function testAddCalldataCheckFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.addCalldataCheck(address(0), bytes4(0xFFFFFFFF), 0, 1, "");
    }

    function testAddCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.addCalldataChecks(
            contractAddresses, selector, startIndex, endIndex, data
        );
    }

    function testRemoveCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.removeCalldataChecks(address(this), bytes4(0xFFFFFFFF), 0);
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

    function testSetGuardianSucceedsAsTimelock(address newGuardian) public {
        vm.prank(address(timelock));
        timelock.setGuardian(newGuardian);

        assertEq(
            timelock.pauseGuardian(),
            newGuardian,
            "new guardian not correctly set"
        );
        assertEq(timelock.pauseStartTime(), 0, "pauseStartTime should be 0");
        assertFalse(timelock.paused(), "timelock should not be paused");
        assertFalse(timelock.pauseUsed(), "pause should not be used");
    }

    function testSetGuardianSucceedsAsTimelockAndUnpauses(address newGuardian)
        public
    {
        vm.prank(guardian);
        timelock.pause();

        assertTrue(timelock.paused(), "not paused");
        assertTrue(timelock.pauseUsed(), "pause should not be used");
        assertEq(
            timelock.pauseStartTime(),
            block.timestamp,
            "pauseStartTime should be 0"
        );

        testSetGuardianSucceedsAsTimelock(newGuardian);
    }

    function testUpdateDelaySucceedsAsTimelock() public {
        uint256 minDelay = timelock.MIN_DELAY();

        vm.prank(address(timelock));
        timelock.updateDelay(minDelay);

        assertEq(minDelay, timelock.minDelay(), "minDelay should be updated");
    }

    function testUpdateDelayFailsDelayTooLong() public {
        uint256 delay = timelock.MAX_DELAY() + 1;

        vm.prank(address(timelock));
        vm.expectRevert("Timelock: delay out of bounds");
        timelock.updateDelay(delay);
    }

    function testUpdateDelayFailsDelayTooShort() public {
        uint256 delay = timelock.MIN_DELAY() - 1;

        vm.prank(address(timelock));
        vm.expectRevert("Timelock: delay out of bounds");
        timelock.updateDelay(delay);
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

    function testUpdateExpirationPeriodFailsAsTimelockDelayTooShort() public {
        uint256 delay = timelock.MIN_DELAY() - 1;

        vm.prank(address(timelock));
        vm.expectRevert("Timelock: delay out of bounds");
        timelock.updateExpirationPeriod(delay);
    }

    function testScheduleCallRevertsIfAlreadyScheduled() public {
        // Prepare the scheduling parameters
        // Call schedule() first time
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0),
            MINIMUM_DELAY
        );
        // Expect revert on second call with same parameters
        vm.prank(address(safe));
        vm.expectRevert("Timelock: duplicate id");
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testScheduleCallRevertsDelayLtMinDelay() public {
        // Prepare the scheduling parameters
        // Call schedule() first time
        vm.prank(address(safe));
        vm.expectRevert("Timelock: insufficient delay");
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0),
            MINIMUM_DELAY - 1
        );
    }

    function testScheduleBatchCallRevertsIfAlreadyScheduled() public {
        vm.prank(address(safe));
        timelock.scheduleBatch(
            new address[](0),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            MINIMUM_DELAY
        );

        // Expect revert on second call with same parameters
        vm.prank(address(safe));
        vm.expectRevert("Timelock: duplicate id");
        timelock.scheduleBatch(
            new address[](0),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testScheduleBatchCallRevertsArityMismatch() public {
        vm.expectRevert("Timelock: length mismatch");
        vm.prank(address(safe));
        timelock.scheduleBatch(
            new address[](1),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            MINIMUM_DELAY
        );

        vm.expectRevert("Timelock: length mismatch");
        vm.prank(address(safe));
        timelock.scheduleBatch(
            new address[](1),
            new uint256[](1),
            new bytes[](0),
            bytes32(0),
            MINIMUM_DELAY
        );
    }

    function testExecuteBatchCallRevertsArityMismatch() public {
        vm.expectRevert("Timelock: length mismatch");
        vm.prank(address(safe));
        timelock.executeBatch(
            new address[](1), new uint256[](0), new bytes[](0), bytes32(0)
        );

        vm.expectRevert("Timelock: length mismatch");
        vm.prank(address(safe));
        timelock.executeBatch(
            new address[](1), new uint256[](1), new bytes[](0), bytes32(0)
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
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );

        assertEq(
            timelock.minDelay(), MINIMUM_DELAY, "minDelay should be updated"
        );
        assertTrue(timelock.isOperationDone(id), "operation should be done");
    }

    function testExecuteTwiceFails() public {
        testExecuteCallSucceedsWhenReady();

        vm.expectRevert("Timelock: proposal does not exist");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );
    }

    function testExecuteCallUpdateExpirationPeriodSucceedsWhenReady() public {
        uint256 newExpirationPeriod = 50 days;
        // Prepare and schedule a call
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateExpirationPeriod.selector, newExpirationPeriod
            ),
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
                timelock.updateExpirationPeriod.selector, newExpirationPeriod
            ),
            bytes32(0)
        );

        bytes32 id = timelock.hashOperation(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateExpirationPeriod.selector, newExpirationPeriod
            ),
            bytes32(0)
        );

        assertEq(
            timelock.expirationPeriod(),
            newExpirationPeriod,
            "expirationPeriod should be updated"
        );

        assertFalse(
            timelock.isOperationPending(id), "operation should not be pending"
        );
        assertTrue(timelock.isOperationDone(id), "operation should be done");
        assertTrue(timelock.isOperation(id), "operation should exist");

        assertEq(
            timelock.expirationPeriod(),
            newExpirationPeriod,
            "expirationPeriod should be updated"
        );
        assertEq(
            timelock.minDelay(), MINIMUM_DELAY, "minDelay should be updated"
        );
    }

    function testWhitelistingCalldataSucceeds() public returns (address) {
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
            targets, values, datas, bytes32(0), MINIMUM_DELAY
        );

        bytes32 id =
            timelock.hashOperationBatch(targets, values, datas, bytes32(0));

        assertTrue(
            timelock.isOperationPending(id), "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0], id, "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length, 1, "proposal length incorrect"
        );

        vm.warp(block.timestamp + MINIMUM_DELAY);

        vm.prank(address(safe));
        timelock.executeBatch(targets, values, datas, bytes32(0));

        address[] memory safeSigner = new address[](1);
        safeSigner[0] = address(this);

        safe.setOwners(safeSigner);

        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(
                lending.deposit.selector, address(timelock), 100
            )
        );

        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(
                lending.withdraw.selector, address(timelock), 100
            )
        );

        vm.expectRevert("CalldataList: Value exceeds maximum");
        timelock.checkCalldata(
            address(lending),
            1,
            abi.encodeWithSelector(
                lending.withdraw.selector, address(timelock), 100
            )
        );

        /// cannot withdraw funds to the safe
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(lending.deposit.selector, address(safe), 100)
        );

        Timelock.Index[] memory calldataDepositChecks = timelock
            .getCalldataChecks(address(lending), MockLending.deposit.selector);

        assertEq(
            calldataDepositChecks.length, 1, "calldata checks should be added"
        );
        assertEq(
            calldataDepositChecks[0].startIndex, 16, "startIndex should be 16"
        );
        assertEq(
            calldataDepositChecks[0].endIndex, 36, "startIndex should be 16"
        );
        assertEq(
            calldataDepositChecks[0].data,
            abi.encodePacked(address(timelock)),
            "data should be correct"
        );

        Timelock.Index[] memory calldataWithdrawChecks = timelock
            .getCalldataChecks(address(lending), MockLending.withdraw.selector);

        assertEq(
            calldataWithdrawChecks.length, 1, "calldata checks should be added"
        );
        assertEq(
            calldataWithdrawChecks[0].startIndex, 16, "startIndex should be 16"
        );
        assertEq(
            calldataWithdrawChecks[0].endIndex, 36, "startIndex should be 16"
        );
        assertEq(
            calldataWithdrawChecks[0].data,
            abi.encodePacked(address(timelock)),
            "data should be correct"
        );

        return address(lending);
    }

    function testWhitelistingBatchCalldataSucceeds() public returns (address) {
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
            targets, values, datas, bytes32(0), MINIMUM_DELAY
        );

        bytes32 id =
            timelock.hashOperationBatch(targets, values, datas, bytes32(0));

        assertTrue(
            timelock.isOperationPending(id), "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0], id, "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length, 1, "proposal length incorrect"
        );

        vm.warp(block.timestamp + MINIMUM_DELAY);

        vm.prank(address(safe));
        timelock.executeBatch(targets, values, datas, bytes32(0));

        address[] memory safeSigner = new address[](1);
        safeSigner[0] = address(this);

        safe.setOwners(safeSigner);

        address[] memory lendingAddresses = new address[](2);
        lendingAddresses[0] = address(lending);
        lendingAddresses[1] = address(lending);

        bytes[] memory lendingPayloads = new bytes[](2);
        lendingPayloads[0] = abi.encodeWithSelector(
            lending.deposit.selector, address(timelock), 100
        );
        lendingPayloads[1] = abi.encodeWithSelector(
            lending.withdraw.selector, address(timelock), 100
        );

        vm.expectEmit(true, true, true, true, address(timelock));
        emit CallExecuted(
            bytes32(0), 0, address(lending), 0, lendingPayloads[0]
        );

        vm.expectEmit(true, true, true, true, address(timelock));
        emit CallExecuted(
            bytes32(0), 1, address(lending), 0, lendingPayloads[1]
        );

        timelock.executeWhitelistedBatch(
            lendingAddresses, new uint256[](2), lendingPayloads
        );

        Timelock.Index[] memory calldataChecks = timelock.getCalldataChecks(
            address(lending), MockLending.deposit.selector
        );

        assertEq(calldataChecks.length, 1, "calldata checks should exist");
        assertEq(calldataChecks[0].startIndex, 16, "startIndex should be 16");
        assertEq(calldataChecks[0].endIndex, 36, "startIndex should be 16");
        assertEq(
            calldataChecks[0].data,
            abi.encodePacked(address(timelock)),
            "data should be correct"
        );

        return address(lending);
    }

    function testExecuteWhitelistedNonSafeOwnerFails() public {
        vm.expectRevert("Timelock: caller is not the safe owner");
        timelock.executeWhitelisted(address(this), 0, "");
    }

    function testExecuteWhitelistedBatchNonSafeOwnerFails() public {
        vm.expectRevert("Timelock: caller is not the safe owner");
        timelock.executeWhitelistedBatch(
            new address[](0), new uint256[](0), new bytes[](0)
        );
    }

    function testExecuteWhitelistedBatchArityMismatchFails() public {
        address[] memory safeSigner = new address[](1);
        safeSigner[0] = address(this);

        safe.setOwners(safeSigner);
        vm.expectRevert("Timelock: length mismatch");
        timelock.executeWhitelistedBatch(
            new address[](1), new uint256[](0), new bytes[](0)
        );

        vm.expectRevert("Timelock: length mismatch");
        timelock.executeWhitelistedBatch(
            new address[](1), new uint256[](1), new bytes[](0)
        );
    }

    function testRemoveAllCalldataChecksArityMismatchFails() public {
        vm.expectRevert("Timelock: arity mismatch");
        vm.prank(address(timelock));
        timelock.removeAllCalldataChecks(new address[](2), new bytes4[](0));
    }

    function testRemoveCalldataChecksNonExistentChecksFails() public {
        address lending = testWhitelistingCalldataSucceeds();

        vm.expectRevert("CalldataList: Calldata index out of bounds");
        vm.prank(address(timelock));
        timelock.removeCalldataChecks(address(lending), bytes4(0xFFFFFFFF), 0);
    }

    function testRemoveCalldataChecksWithChecksSucceeds() public {
        address lending = testWhitelistingCalldataSucceeds();

        vm.prank(address(timelock));
        timelock.removeCalldataChecks(
            address(lending), MockLending.deposit.selector, 0
        );

        Timelock.Index[] memory calldataChecks = timelock.getCalldataChecks(
            address(lending), MockLending.deposit.selector
        );

        assertEq(calldataChecks.length, 0, "calldata checks should be removed");
    }

    function testRemoveAllCalldataChecksTimelockSucceeds()
        public
        returns (address lending)
    {
        lending = testWhitelistingCalldataSucceeds();

        address[] memory targets = new address[](2);
        targets[0] = address(lending);
        targets[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.withdraw.selector;

        vm.prank(address(timelock));
        timelock.removeAllCalldataChecks(targets, selectors);

        {
            Timelock.Index[] memory calldataChecks = timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            );

            assertEq(
                calldataChecks.length, 0, "calldata checks should be removed"
            );
        }
        {
            Timelock.Index[] memory calldataChecks = timelock.getCalldataChecks(
                address(lending), MockLending.withdraw.selector
            );

            assertEq(
                calldataChecks.length, 0, "calldata checks should be removed"
            );
        }

        vm.expectRevert("CalldataList: No calldata checks found");
        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(
                MockLending.deposit.selector, address(timelock), 100
            )
        );

        vm.expectRevert("CalldataList: No calldata checks found");
        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(
                MockLending.withdraw.selector, address(timelock), 100
            )
        );
    }

    function testRemoveAllCalldataChecksTimelockFailsNoChecks() public {
        address lending = testRemoveAllCalldataChecksTimelockSucceeds();

        address[] memory targets = new address[](2);
        targets[0] = address(lending);
        targets[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.withdraw.selector;

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: No calldata checks to remove");
        timelock.removeAllCalldataChecks(targets, selectors);
    }

    function testExecuteBeforeTimelockFinishesFails() public {
        testScheduleProposalSafeSucceeds();

        vm.expectRevert("Timelock: operation is not ready");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );

        vm.warp(block.timestamp + MINIMUM_DELAY - 1);

        vm.expectRevert("Timelock: operation is not ready");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );
    }

    /// test a timelock execution call that fails due to reentrancy check in _afterCall

    function testReentrantExecuteFails() public {
        MockReentrancyExecutor executor = new MockReentrancyExecutor();

        vm.prank(address(safe));
        timelock.schedule(address(executor), 0, "", bytes32(0), MINIMUM_DELAY);

        vm.warp(block.timestamp + MINIMUM_DELAY);

        vm.expectRevert("Timelock: underlying transaction reverted");
        timelock.execute(address(executor), 0, "", bytes32(0));
    }

    function testReentrantExecuteBatchFails() public {
        MockReentrancyExecutor executor = new MockReentrancyExecutor();
        executor.setExecuteBatch(true);

        address[] memory targets = new address[](1);
        targets[0] = address(executor);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory datas = new bytes[](1);
        datas[0] = "";

        vm.prank(address(safe));
        timelock.scheduleBatch(
            targets, values, datas, bytes32(0), MINIMUM_DELAY
        );

        vm.warp(block.timestamp + MINIMUM_DELAY);

        vm.expectRevert("Timelock: underlying transaction reverted");
        timelock.executeBatch(targets, values, datas, bytes32(0));
    }

    function testCallBubblesUpRevert() public {
        vm.prank(address(safe));
        timelock.schedule(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY - 1
            ),
            bytes32(0),
            MINIMUM_DELAY
        );

        bytes32 id = timelock.hashOperation(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY - 1
            ),
            bytes32(0)
        );

        assertTrue(
            timelock.isOperationPending(id), "operation should be pending"
        );
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );

        assertEq(
            timelock.getAllProposals()[0], id, "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length, 1, "proposal length incorrect"
        );

        vm.warp(block.timestamp + MINIMUM_DELAY);

        vm.expectRevert("Timelock: underlying transaction reverted");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY - 1
            ),
            bytes32(0)
        );
    }

    function testNoopReceiveNoRevert() public {
        timelock.onERC1155Received(address(0), address(0), 0, 0, "");
        timelock.onERC1155BatchReceived(
            address(0), address(0), new uint256[](0), new uint256[](0), ""
        );
        timelock.onERC721Received(address(0), address(0), 0, "");

        vm.deal(address(this), 1);
        (bool success,) = address(timelock).call{value: 1}("");
        assertTrue(success, "payable call failed");
    }
}
