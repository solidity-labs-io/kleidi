pragma solidity 0.8.25;

import "test/utils/TimelockUnitFixture.sol";

contract TimelockUnitTest is TimelockUnitFixture {
    function testSetup() public view {
        assertEq(timelock.safe(), address(safe), "safe incorrectly set");
        assertEq(timelock.minDelay(), MINIMUM_DELAY, "minDelay incorrectly set");
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
        assertEq(
            timelock.expirationPeriod(),
            EXPIRATION_PERIOD,
            "expirationPeriod incorrectly set"
        );
        assertEq(timelock.getAllProposals().length, 0, "no proposals yet");
        assertTrue(timelock.initialized(), "timelock not initialized");
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

    function testCannotReInitializeTimelock() public {
        assertTrue(timelock.initialized(), "timelock not initialized");

        vm.expectRevert("Timelock: already initialized");
        timelock.initialize(
            new address[](0),
            new bytes4[](0),
            new uint16[](0),
            new uint16[](0),
            new bytes[][](0)
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
            new address[](0)
        );

        vm.expectRevert("Timelock: expiration period too short");
        new Timelock(
            address(0),
            MINIMUM_DELAY,
            86399,
            guardian,
            PAUSE_DURATION,
            new address[](0)
        );
    }

    function testScheduleProposalSafeSucceeds() public returns (bytes32) {
        _schedule({
            caller: address(safe),
            timelock: address(timelock),
            target: address(timelock),
            value: 0,
            data: abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY
            ),
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });

        bytes32 id = timelock.hashOperation(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );
        assertGt(timelock.timestamps(id), 1, "operation should be pending");
        assertTrue(timelock.isOperation(id), "operation should be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );
        assertFalse(
            timelock.isOperationExpired(id), "operation should not be expired"
        );

        assertEq(
            timelock.getAllProposals()[0], id, "proposal should be in proposals"
        );
        assertEq(
            timelock.getAllProposals().length, 1, "proposal length incorrect"
        );
        assertEq(
            timelock.positionOf(id),
            1,
            "incorrect position of the proposal in live proposal set"
        );
        assertEq(timelock.atIndex(0), id, "incorrect proposal at index 0");

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

        _scheduleBatch({
            caller: address(safe),
            timelock: address(timelock),
            targets: targets,
            values: values,
            payloads: datas,
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });

        bytes32 id =
            timelock.hashOperationBatch(targets, values, datas, bytes32(0));

        assertGt(timelock.timestamps(id), 1, "operation should be pending");
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

        _executeBatch({
            caller: address(this),
            timelock: address(timelock),
            targets: targets,
            values: values,
            payloads: datas,
            salt: bytes32(0)
        });

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

        assertGt(timelock.timestamps(id), 1, "operation should be pending");
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
        assertTrue(timelock.pauseStartTime() != 0, "pause should be used");
        assertTrue(timelock.paused(), "timelock should be paused");

        assertEq(timelock.timestamps(id), 0, "operation should be pending");
        assertFalse(timelock.isOperation(id), "operation should not be present");
        assertFalse(
            timelock.isOperationReady(id), "operation should not be ready"
        );
        assertFalse(
            timelock.isOperationDone(id), "operation should not be done"
        );

        assertEq(timelock.getAllProposals().length, 0, "no proposals yet");
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

    function testRevokeHotSignerFailsNotSafe() public {
        vm.expectRevert("Timelock: caller is not the safe");
        timelock.revokeHotSigner(address(this));
    }

    function testRevokeRoleNotAdminFails() public {
        bytes32 role = timelock.HOT_SIGNER_ROLE();
        vm.expectRevert();
        timelock.revokeRole(role, address(this));
    }

    function testRenounceRoleFails() public {
        bytes32 role = timelock.HOT_SIGNER_ROLE();
        vm.expectRevert();
        timelock.renounceRole(role, address(1));
    }

    function testGrantHotSignerRoleFails() public {
        bytes32 role = timelock.HOT_SIGNER_ROLE();
        vm.expectRevert();
        timelock.grantRole(role, address(1));
    }

    function testGrantNewRoleAsHotSignerFails() public {
        bytes32 role = keccak256("testing123");
        vm.prank(hotSigners[0]);
        vm.expectRevert();
        timelock.grantRole(role, address(1));
    }

    function testAddHotSignerFailsNotTimelock() public {
        bytes32 hotSignerRole = timelock.HOT_SIGNER_ROLE();
        vm.expectRevert(
            abi.encodePacked(
                bytes16(
                    bytes4(
                        keccak256(
                            "AccessControlUnauthorizedAccount(address,bytes32)"
                        )
                    )
                ),
                address(this),
                bytes32(0)
            )
        );

        timelock.grantRole(hotSignerRole, address(this));
    }

    function testGrantAdminRoleFails() public {
        bytes32 adminRole = timelock.DEFAULT_ADMIN_ROLE();
        vm.expectRevert("Timelock: cannot grant admin role");
        timelock.grantRole(adminRole, address(this));
    }

    function testRevokeAdminRoleFails() public {
        bytes32 adminRole = timelock.DEFAULT_ADMIN_ROLE();
        vm.expectRevert("Timelock: cannot revoke admin role");
        timelock.revokeRole(adminRole, address(this));
    }

    function testRenounceAdminRoleFails() public {
        bytes32 adminRole = timelock.DEFAULT_ADMIN_ROLE();
        vm.expectRevert("Timelock: cannot renounce admin role");
        timelock.renounceRole(adminRole, address(this));
    }

    function testSetGuardianFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.setGuardian(address(0));
    }

    function testRemoveCalldataCheckFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.removeCalldataCheckDatahash(
            address(0), bytes4(0), 0, bytes32(0)
        );
    }

    function testAddCalldataCheckFailsNonTimelock() public {
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodePacked(timelock);

        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.addCalldataCheck(address(0), bytes4(0xFFFFFFFF), 0, 1, datas);
    }

    function testAddCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.addCalldataChecks(
            new address[](0),
            new bytes4[](0),
            new uint16[](0),
            new uint16[](0),
            new bytes[][](0)
        );
    }

    function testRemoveCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.removeCalldataCheck(address(this), bytes4(0xFFFFFFFF), 0);
    }

    function testRemoveAllCalldataChecksFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.removeAllCalldataChecks(new address[](0), new bytes4[](0));
    }

    function testUpdateDelayFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.updateDelay(0);
    }

    function testUpdateExpirationPeriodFailsNonTimelock() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.updateExpirationPeriod(0);
    }

    function testUpdatePauseDurationNonTimelockFails() public {
        vm.expectRevert("Timelock: caller is not the timelock");
        timelock.updatePauseDuration(1);
    }

    function testAddCalldataChecksFailsLengthMismatch() public {
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"1234";

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Data length mismatch");
        timelock.addCalldataCheck(
            address(10000), timelock.addCalldataCheck.selector, 10, 13, datas
        );

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Data length mismatch");
        timelock.addCalldataCheck(
            address(10000), timelock.addCalldataCheck.selector, 9, 28, datas
        );
    }

    function testAddCalldataCheckEmptyCalldataFails() public {
        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Data empty");
        timelock.addCalldataCheck(
            address(10000),
            timelock.addCalldataCheck.selector,
            10,
            30,
            new bytes[](0)
        );
    }

    function testAddCalldataChecksEmptyCalldataFails() public {
        address[] memory targets = new address[](1);
        targets[0] = address(10000);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = timelock.addCalldataCheck.selector;

        uint16[] memory startIndexes = new uint16[](1);
        startIndexes[0] = 20;
        uint16[] memory endIndexes = new uint16[](1);
        endIndexes[0] = 30;

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Data empty");
        timelock.addCalldataChecks(
            targets, selectors, startIndexes, endIndexes, new bytes[][](1)
        );
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
        assertFalse(timelock.pauseStartTime() != 0, "pause should not be used");
    }

    function testSetGuardianSucceedsAsTimelockAndUnpauses(address newGuardian)
        public
    {
        vm.prank(guardian);
        timelock.pause();

        assertTrue(timelock.paused(), "not paused");
        assertTrue(timelock.pauseStartTime() != 0, "pause should not be used");
        assertEq(
            timelock.pauseStartTime(),
            block.timestamp,
            "pauseStartTime should be 0"
        );

        testSetGuardianSucceedsAsTimelock(newGuardian);
    }

    function testUpdateDelaySucceedsAsTimelock() public {
        uint256 minDelay = MIN_DELAY;

        vm.prank(address(timelock));
        timelock.updateDelay(minDelay);

        assertEq(minDelay, timelock.minDelay(), "minDelay should be updated");
    }

    function testUpdateDelayFailsDelayTooLong() public {
        uint256 delay = MAX_DELAY + 1;

        vm.prank(address(timelock));
        vm.expectRevert("Timelock: delay out of bounds");
        timelock.updateDelay(delay);
    }

    function testUpdateDelayFailsDelayTooShort() public {
        uint256 delay = MIN_DELAY - 1;

        vm.prank(address(timelock));
        vm.expectRevert("Timelock: delay out of bounds");
        timelock.updateDelay(delay);
    }

    function testUpdateExpirationPeriodSucceedsAsTimelock() public {
        uint256 minDelay = MIN_DELAY;

        vm.prank(address(timelock));
        timelock.updateExpirationPeriod(minDelay);

        assertEq(
            minDelay,
            timelock.expirationPeriod(),
            "expirationPeriod should be updated"
        );
    }

    function testUpdateExpirationPeriodFailsAsTimelockDelayTooShort() public {
        uint256 delay = MIN_DELAY - 1;

        vm.prank(address(timelock));
        vm.expectRevert("Timelock: delay out of bounds");
        timelock.updateExpirationPeriod(delay);
    }

    function testScheduleCallRevertsIfAlreadyScheduled() public {
        // Prepare the scheduling parameters
        // Call schedule() first time
        _schedule({
            caller: address(safe),
            timelock: address(timelock),
            target: address(timelock),
            value: 0,
            data: abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY
            ),
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });
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

    function testRevokeHotSignerSafeSucceeds() public {
        vm.prank(address(safe));
        timelock.revokeHotSigner(HOT_SIGNER_ONE);

        vm.prank(address(safe));
        timelock.revokeHotSigner(HOT_SIGNER_TWO);

        vm.prank(address(safe));
        timelock.revokeHotSigner(HOT_SIGNER_THREE);

        assertFalse(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_ONE),
            "Hot signer one should have role revoked"
        );
        assertFalse(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_TWO),
            "Hot signer two should have role revoked"
        );
        assertFalse(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_THREE),
            "Hot signer three should have role revoked"
        );
    }

    function testExecuteCallSucceedsWhenReady() public {
        // Prepare and schedule a call
        bytes32 id = testScheduleProposalSafeSucceeds();

        // Simulate time passing
        vm.warp(block.timestamp + MINIMUM_DELAY);

        // Execute the call as anyone, should succeed
        _execute({
            caller: address(this),
            timelock: address(timelock),
            target: address(timelock),
            value: 0,
            payload: abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY
            ),
            salt: bytes32(0)
        });

        vm.expectRevert("Timelock: operation already executed");
        timelock.isOperationExpired(id);

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
        _schedule({
            caller: address(safe),
            timelock: address(timelock),
            target: address(timelock),
            value: 0,
            data: abi.encodeWithSelector(
                timelock.updateExpirationPeriod.selector, newExpirationPeriod
            ),
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });

        // Simulate time passing
        vm.warp(block.timestamp + MINIMUM_DELAY);

        // Execute the call as anyone, should succeed
        _execute({
            caller: address(this),
            timelock: address(timelock),
            target: address(timelock),
            value: 0,
            payload: abi.encodeWithSelector(
                timelock.updateExpirationPeriod.selector, newExpirationPeriod
            ),
            salt: bytes32(0)
        });

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

        assertEq(timelock.timestamps(id), 1, "operation should be pending");
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

        {
            bytes[] memory payloads = new bytes[](1);
            payloads[0] = abi.encodeWithSelector(
                timelock.grantRole.selector,
                timelock.HOT_SIGNER_ROLE(),
                address(this)
            );

            _scheduleBatch({
                caller: address(safe),
                timelock: address(timelock),
                targets: targets,
                values: values,
                payloads: payloads,
                salt: bytes32(0),
                delay: MINIMUM_DELAY
            });

            vm.warp(block.timestamp + MINIMUM_DELAY);

            _executeBatch({
                caller: address(this),
                timelock: address(timelock),
                targets: targets,
                values: values,
                payloads: payloads,
                salt: bytes32(0)
            });
        }

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

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata = new bytes[](1);
        checkedCalldata[0] = abi.encodePacked(timelock);
        checkedCalldatas[0] = checkedCalldata;
        checkedCalldatas[1] = checkedCalldata;

        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSelector(
            timelock.addCalldataChecks.selector,
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        _scheduleBatch({
            caller: address(safe),
            timelock: address(timelock),
            targets: targets,
            values: values,
            payloads: datas,
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });

        bytes32 id =
            timelock.hashOperationBatch(targets, values, datas, bytes32(0));

        assertEq(
            timelock.timestamps(id),
            block.timestamp + MINIMUM_DELAY,
            "operation should be scheduled"
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

        _executeBatch({
            caller: address(this),
            timelock: address(timelock),
            targets: targets,
            values: values,
            payloads: datas,
            salt: bytes32(0)
        });

        timelock.checkCalldata(
            address(lending),
            abi.encodeWithSelector(
                lending.deposit.selector, address(timelock), 100
            )
        );
        timelock.checkCalldata(
            address(lending),
            abi.encodeWithSelector(
                lending.withdraw.selector, address(timelock), 100
            )
        );

        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.checkCalldata(
            address(lending),
            abi.encodeWithSelector(
                lending.withdraw.selector, address(this), 100
            )
        );
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.checkCalldata(
            address(lending),
            abi.encodeWithSelector(lending.deposit.selector, address(this), 100)
        );

        _executeWhiteListed({
            caller: address(this),
            timelock: address(timelock),
            target: address(lending),
            value: 0,
            payload: abi.encodeWithSelector(
                lending.deposit.selector, address(timelock), 100
            )
        });

        _executeWhiteListed({
            caller: address(this),
            timelock: address(timelock),
            target: address(lending),
            value: 0,
            payload: abi.encodeWithSelector(
                lending.withdraw.selector, address(timelock), 100
            )
        });

        /// cannot withdraw funds to the safe
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelisted(
            address(lending),
            0,
            abi.encodeWithSelector(lending.deposit.selector, address(safe), 100)
        );

        Timelock.IndexData[] memory calldataDepositChecks = timelock
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
            calldataDepositChecks[0].dataHashes[0],
            keccak256(abi.encodePacked(address(timelock))),
            "data should be correct"
        );

        Timelock.IndexData[] memory calldataWithdrawChecks = timelock
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
            calldataWithdrawChecks[0].dataHashes[0],
            keccak256(abi.encodePacked(address(timelock))),
            "data hash should match"
        );

        return address(lending);
    }

    function testWhitelistingBatchCalldataSucceeds() public returns (address) {
        address[] memory targets = new address[](1);
        targets[0] = address(timelock);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        {
            bytes[] memory payloads = new bytes[](1);
            payloads[0] = abi.encodeWithSelector(
                timelock.grantRole.selector,
                timelock.HOT_SIGNER_ROLE(),
                address(this)
            );

            _scheduleBatch({
                caller: address(safe),
                timelock: address(timelock),
                targets: targets,
                values: values,
                payloads: payloads,
                salt: bytes32(0),
                delay: MINIMUM_DELAY
            });

            vm.warp(block.timestamp + MINIMUM_DELAY);

            _executeBatch({
                caller: address(this),
                timelock: address(timelock),
                targets: targets,
                values: values,
                payloads: payloads,
                salt: bytes32(0)
            });
        }

        MockLending lending = new MockLending();

        {
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

            bytes[][] memory checkedCalldatas = new bytes[][](2);
            bytes[] memory checkedCalldata = new bytes[](1);
            checkedCalldata[0] = abi.encodePacked(address(timelock));
            checkedCalldatas[0] = checkedCalldata;
            checkedCalldatas[1] = checkedCalldata;

            bytes[] memory datas = new bytes[](1);
            datas[0] = abi.encodeWithSelector(
                timelock.addCalldataChecks.selector,
                targetAddresses,
                selectors,
                startIndexes,
                endIndexes,
                checkedCalldatas
            );

            _scheduleBatch({
                caller: address(safe),
                timelock: address(timelock),
                targets: targets,
                values: values,
                payloads: datas,
                salt: bytes32(0),
                delay: MINIMUM_DELAY
            });

            bytes32 id =
                timelock.hashOperationBatch(targets, values, datas, bytes32(0));

            assertEq(
                timelock.timestamps(id),
                block.timestamp + MINIMUM_DELAY,
                "operation should be scheduled"
            );
            assertTrue(timelock.isOperation(id), "operation should be present");
            assertFalse(
                timelock.isOperationReady(id), "operation should not be ready"
            );
            assertFalse(
                timelock.isOperationDone(id), "operation should not be done"
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

            _executeBatch({
                caller: address(this),
                timelock: address(timelock),
                targets: targets,
                values: values,
                payloads: datas,
                salt: bytes32(0)
            });
        }

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

        _executeWhitelistedBatch({
            caller: address(this),
            timelock: address(timelock),
            targets: lendingAddresses,
            values: new uint256[](2),
            payloads: lendingPayloads
        });

        Timelock.IndexData[] memory calldataChecks = timelock.getCalldataChecks(
            address(lending), MockLending.deposit.selector
        );

        assertEq(calldataChecks.length, 1, "calldata checks should exist");
        assertEq(calldataChecks[0].startIndex, 16, "startIndex should be 16");
        assertEq(calldataChecks[0].endIndex, 36, "startIndex should be 16");
        assertEq(
            calldataChecks[0].dataHashes[0],
            keccak256(abi.encodePacked(address(timelock))),
            "data should be correct"
        );

        return address(lending);
    }

    function testRevokeHotSignerSucceeds() public {
        testWhitelistingBatchCalldataSucceeds();

        bytes32 hotSignerRole = timelock.HOT_SIGNER_ROLE();

        vm.prank(address(timelock));
        timelock.revokeRole(hotSignerRole, address(this));

        assertFalse(
            timelock.hasRole(hotSignerRole, address(this)),
            "hot signer not revoked"
        );
    }

    function testRenounceHotSignerSucceeds() public {
        testWhitelistingBatchCalldataSucceeds();

        bytes32 hotSignerRole = timelock.HOT_SIGNER_ROLE();

        timelock.renounceRole(hotSignerRole, address(this));

        assertFalse(
            timelock.hasRole(hotSignerRole, address(this)),
            "hot signer not renounced"
        );
    }

    function testExecuteWhitelistedNotHotSignerFails() public {
        bytes32 hotSignerRole = timelock.HOT_SIGNER_ROLE();
        vm.expectRevert(
            abi.encodePacked(
                bytes16(
                    bytes4(
                        keccak256(
                            "AccessControlUnauthorizedAccount(address,bytes32)"
                        )
                    )
                ),
                address(this),
                hotSignerRole
            )
        );
        timelock.executeWhitelisted(address(this), 0, "");
    }

    function testExecuteWhitelistedBatchNotHotSignerFails() public {
        bytes32 hotSignerRole = timelock.HOT_SIGNER_ROLE();

        vm.expectRevert(
            abi.encodePacked(
                bytes16(
                    bytes4(
                        keccak256(
                            "AccessControlUnauthorizedAccount(address,bytes32)"
                        )
                    )
                ),
                address(this),
                hotSignerRole
            )
        );
        timelock.executeWhitelistedBatch(
            new address[](0), new uint256[](0), new bytes[](0)
        );
    }

    function testCancelProposalNonSafeOwnerFails() public {
        vm.expectRevert("Timelock: caller is not the safe");
        timelock.cancel(bytes32(0));
    }

    function testCancelActiveProposalSafeSucceeds() public returns (bytes32) {
        bytes32 id = testScheduleProposalSafeSucceeds();

        vm.prank(address(safe));
        timelock.cancel(id);

        assertFalse(
            timelock.isOperation(id), "operation should no longer be present"
        );

        vm.expectRevert("Timelock: operation non-existent");
        timelock.isOperationExpired(id);

        assertEq(
            timelock.getAllProposals().length,
            0,
            "no proposals should be present"
        );

        return id;
    }

    function testCancelCancelledProposalFails() public {
        bytes32 id = testCancelActiveProposalSafeSucceeds();

        vm.prank(address(safe));
        vm.expectRevert("Timelock: operation does not exist");
        timelock.cancel(id);
    }

    function testOperationExpiresNonExecutable() public {
        bytes32 id = testScheduleProposalSafeSucceeds();
        uint256 timestamp = block.timestamp + MIN_DELAY;

        assertFalse(
            timelock.isOperationExpired(id), "operation should not be expired"
        );

        vm.warp(block.timestamp + MINIMUM_DELAY);

        assertFalse(
            timelock.isOperationExpired(id), "operation should not be expired"
        );

        vm.warp(block.timestamp + EXPIRATION_PERIOD - 1);

        assertFalse(
            timelock.isOperationExpired(id), "operation should not be expired"
        );

        vm.warp(block.timestamp + 1);

        assertTrue(
            timelock.isOperationExpired(id), "operation should not be expired"
        );

        vm.expectRevert("Timelock: operation is not ready");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );

        assertEq(
            timelock.getAllProposals().length,
            1,
            "only a single proposal should be present"
        );
        assertEq(
            timelock.timestamps(id),
            timestamp,
            "timestamps pre-cleanup should equal block timestamp"
        );

        timelock.cleanup(id);

        assertEq(
            timelock.getAllProposals().length,
            0,
            "no proposals should be present post cleanup"
        );

        assertEq(
            timelock.timestamps(id),
            timestamp,
            "timestamps post cleanup should equal block timestamp"
        );
    }

    function testCannotCleanupNonExpiredProposal() public {
        bytes32 id = testScheduleProposalSafeSucceeds();

        assertFalse(
            timelock.isOperationExpired(id), "operation should not be expired"
        );

        vm.expectRevert("Timelock: operation not expired");
        timelock.cleanup(id);
    }

    function testExecuteWhitelistedBatchArityMismatchFails() public {
        bytes32 hotSignerRole = timelock.HOT_SIGNER_ROLE();

        vm.prank(address(timelock));
        timelock.grantRole(hotSignerRole, address(this));

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
        timelock.removeCalldataCheck(address(lending), bytes4(0xFFFFFFFF), 0);
    }

    function testRemoveCalldataChecksWithChecksSucceeds() public {
        address lending = testWhitelistingCalldataSucceeds();

        vm.prank(address(timelock));
        timelock.removeCalldataCheck(
            address(lending), MockLending.deposit.selector, 0
        );

        Timelock.IndexData[] memory calldataChecks = timelock.getCalldataChecks(
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
            Timelock.IndexData[] memory calldataChecks = timelock
                .getCalldataChecks(address(lending), MockLending.deposit.selector);

            assertEq(
                calldataChecks.length, 0, "calldata checks should be removed"
            );
        }
        {
            Timelock.IndexData[] memory calldataChecks = timelock
                .getCalldataChecks(address(lending), MockLending.withdraw.selector);

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

    function testExecuteAfterTimelockExpiryFails() public {
        testScheduleProposalSafeSucceeds();

        vm.warp(block.timestamp + MINIMUM_DELAY + EXPIRATION_PERIOD);

        vm.expectRevert("Timelock: operation is not ready");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );

        vm.warp(block.timestamp + MINIMUM_DELAY + EXPIRATION_PERIOD + 1);
        vm.expectRevert("Timelock: operation is not ready");
        timelock.execute(
            address(timelock),
            0,
            abi.encodeWithSelector(timelock.updateDelay.selector, MINIMUM_DELAY),
            bytes32(0)
        );
    }

    function testExecuteBatchAfterTimelockExpiryFails() public {
        (
            ,
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory datas
        ) = testScheduleBatchProposalSafeSucceeds();

        vm.expectRevert("Timelock: operation is not ready");
        timelock.executeBatch(targets, values, datas, bytes32(0));

        vm.warp(block.timestamp + MINIMUM_DELAY - 1);

        vm.expectRevert("Timelock: operation is not ready");
        timelock.executeBatch(targets, values, datas, bytes32(0));

        vm.warp(block.timestamp + 1 + EXPIRATION_PERIOD);
        vm.expectRevert("Timelock: operation is not ready");
        timelock.executeBatch(targets, values, datas, bytes32(0));
    }

    /// test a timelock execution call that fails due to reentrancy check in _afterCall

    function testReentrantExecuteFails() public {
        MockReentrancyExecutor executor = new MockReentrancyExecutor();

        _schedule({
            caller: address(safe),
            timelock: address(timelock),
            target: address(executor),
            value: 0,
            data: "",
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });

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

        _scheduleBatch({
            caller: address(safe),
            timelock: address(timelock),
            targets: targets,
            values: values,
            payloads: datas,
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });

        vm.warp(block.timestamp + MINIMUM_DELAY);

        vm.expectRevert("Timelock: underlying transaction reverted");
        timelock.executeBatch(targets, values, datas, bytes32(0));
    }

    function testCallBubblesUpRevert() public {
        _schedule({
            caller: address(safe),
            timelock: address(timelock),
            target: address(timelock),
            value: 0,
            data: abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY - 1
            ),
            salt: bytes32(0),
            delay: MINIMUM_DELAY
        });

        bytes32 id = timelock.hashOperation(
            address(timelock),
            0,
            abi.encodeWithSelector(
                timelock.updateDelay.selector, MINIMUM_DELAY - 1
            ),
            bytes32(0)
        );

        assertEq(
            timelock.timestamps(id),
            block.timestamp + MINIMUM_DELAY,
            "operation should be scheduled"
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

    function testScheduleBatchCallRevertsIfExpiredAndCleanedUp() public {
        vm.prank(address(safe));
        timelock.scheduleBatch(
            new address[](0),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            MINIMUM_DELAY
        );

        bytes32 id = timelock.hashOperationBatch(
            new address[](0), new uint256[](0), new bytes[](0), bytes32(0)
        );

        vm.warp(
            block.timestamp + timelock.expirationPeriod() + timelock.minDelay()
        );

        timelock.cleanup(id);

        // Expect revert on second call with same parameters
        vm.prank(address(safe));
        vm.expectRevert("Timelock: operation already scheduled");
        timelock.scheduleBatch(
            new address[](0),
            new uint256[](0),
            new bytes[](0),
            bytes32(0),
            MINIMUM_DELAY
        );

        vm.expectRevert("Timelock: proposal does not exist");
        timelock.executeBatch(
            new address[](0), new uint256[](0), new bytes[](0), bytes32(0)
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

    function testTokensReceivedNoOp() public view {
        timelock.tokensReceived(address(0), address(0), address(0), 0, "", "");
    }
}
