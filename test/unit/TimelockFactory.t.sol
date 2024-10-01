pragma solidity 0.8.25;

import "test/utils/TimelockUnitFixture.sol";

contract TimelockFactoryUnitTest is TimelockUnitFixture {
    /// @notice Emitted when a call is scheduled as part of operation `id`.
    /// @param timelock address of the newly created timelock
    /// @param creationTime of the new timelock
    /// @param sender that called the contract to create the timelock
    event TimelockCreated(
        address indexed timelock, uint256 creationTime, address indexed sender
    );

    function testTimelockCreation() public view {
        assertEq(timelock.minDelay(), MIN_DELAY, "Min delay should be set");
        assertEq(
            timelock.expirationPeriod(),
            EXPIRATION_PERIOD,
            "Expiration period should be set"
        );
        assertEq(timelock.pauseGuardian(), guardian, "Guardian should be set");
        assertEq(
            timelock.pauseDuration(),
            PAUSE_DURATION,
            "Pause duration should be set"
        );

        assertFalse(
            timelock.pauseStartTime() != 0, "timelock pause should not be used"
        );
        assertFalse(timelock.paused(), "timelock should not be paused");

        assertTrue(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_ONE),
            "Hot signer one should have role"
        );
        assertTrue(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_TWO),
            "Hot signer two should have role"
        );
        assertTrue(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_THREE),
            "Hot signer three should have role"
        );
    }

    function testCreateTimelockThroughFactory() public {
        DeploymentParams memory params = DeploymentParams({
            minDelay: MINIMUM_DELAY + 1,
            expirationPeriod: EXPIRATION_PERIOD,
            pauser: guardian,
            pauseDuration: PAUSE_DURATION,
            hotSigners: hotSigners,
            contractAddresses: new address[](0),
            selectors: new bytes4[](0),
            startIndexes: new uint16[](0),
            endIndexes: new uint16[](0),
            datas: new bytes[][](0),
            salt: salt
        });

        address newTimelock =
            timelockFactory.createTimelock(address(this), params);

        assertTrue(newTimelock.code.length > 0, "Timelock not created");
    }

    function testCreateTimelockThroughFactoryDifferentSendersSameParams()
        public
    {
        DeploymentParams memory params = DeploymentParams({
            minDelay: MINIMUM_DELAY + 1,
            expirationPeriod: EXPIRATION_PERIOD,
            pauser: guardian,
            pauseDuration: PAUSE_DURATION,
            hotSigners: hotSigners,
            contractAddresses: new address[](0),
            selectors: new bytes4[](0),
            startIndexes: new uint16[](0),
            endIndexes: new uint16[](0),
            datas: new bytes[][](0),
            salt: salt
        });

        vm.prank(address(1000000000));
        address newTimelockSenderOne =
            timelockFactory.createTimelock(address(this), params);

        assertTrue(newTimelockSenderOne.code.length > 0, "Timelock not created");

        vm.prank(address(2000000000));
        address newTimelockSenderTwo =
            timelockFactory.createTimelock(address(this), params);

        assertTrue(newTimelockSenderTwo.code.length > 0, "Timelock not created");

        assertNotEq(
            newTimelockSenderTwo,
            newTimelockSenderOne,
            "Timelocks should be different"
        );
    }

    function testTimelockCreationCode() public view {
        bytes memory timelockCreationCode =
            timelockFactory.timelockCreationCode();
        bytes memory actualTimelockCreationCode = type(Timelock).creationCode;

        assertEq(
            timelockCreationCode,
            actualTimelockCreationCode,
            "Timelock creation code should be empty"
        );
    }

    function testTimelockCreatedEventEmitted() public {
        address safeAddress = address(0x3afe);
        DeploymentParams memory params = DeploymentParams({
            minDelay: MINIMUM_DELAY + 1,
            expirationPeriod: EXPIRATION_PERIOD,
            pauser: guardian,
            pauseDuration: PAUSE_DURATION,
            hotSigners: hotSigners,
            contractAddresses: new address[](0),
            selectors: new bytes4[](0),
            startIndexes: new uint16[](0),
            endIndexes: new uint16[](0),
            datas: new bytes[][](0),
            salt: salt
        });

        Create2Params memory create2Params;
        create2Params.creator = address(timelockFactory);
        create2Params.creationCode = timelockFactory.timelockCreationCode();
        create2Params.constructorParams = abi.encode(
            safeAddress,
            params.minDelay,
            params.expirationPeriod,
            params.pauser,
            params.pauseDuration,
            params.hotSigners
        );
        create2Params.salt =
            keccak256(abi.encodePacked(params.salt, address(this)));

        address newTimelock = calculateCreate2Address(create2Params);

        vm.expectEmit(true, true, true, true, address(timelockFactory));
        emit TimelockCreated(newTimelock, block.timestamp, address(this));

        timelockFactory.createTimelock(safeAddress, params);
    }
}
