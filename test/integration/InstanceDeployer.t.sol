// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "test/utils/SystemIntegrationFixture.sol";

contract InstanceDeployerIntegrationTest is SystemIntegrationFixture {
    using BytesHelper for bytes;

    function testValidateDeployment() public view {
        validate();
    }

    function testCreateSystemInstance(
        uint8 ownersLength,
        uint8 threshold,
        uint8 recoverySpellLength
    ) public {
        ownersLength = uint8(bound(ownersLength, 1, 20));
        threshold = uint8(bound(threshold, 1, ownersLength));
        recoverySpellLength = uint8(bound(recoverySpellLength, 0, 20));

        _createAndValidateSystemInstance(
            ownersLength, threshold, recoverySpellLength, true
        );
    }

    function testCreateSystemDifferentParamsTwice() public {
        uint8 ownersLength = 10;
        uint8 threshold = 5;
        uint8 recoverySpellLength = 7;

        (Timelock newTimelock1, SafeProxy newSafe1) =
        _createAndValidateSystemInstance(
            ownersLength, threshold, recoverySpellLength, true
        );

        vm.expectRevert("Create2 call failed");
        _createAndValidateSystemInstance(
            ownersLength, threshold, recoverySpellLength, false
        );

        (Timelock newTimelock2, SafeProxy newSafe2) =
        _createAndValidateSystemInstance(
            ownersLength + 1, threshold, recoverySpellLength, true
        );

        assertNotEq(
            address(newTimelock1),
            address(newTimelock2),
            "new timelock addresses not correct"
        );
        assertNotEq(
            address(newSafe1),
            address(newSafe2),
            "new safe addresses not correct"
        );
    }

    function _createAndValidateSystemInstance(
        uint8 ownersLength,
        uint8 threshold,
        uint8 recoverySpellLength,
        bool runAssertions
    ) private returns (Timelock newTimelock, SafeProxy newSafe) {
        InstanceDeployer.NewInstance memory instance;

        instance.owners = new address[](ownersLength);
        instance.threshold = threshold;
        instance.recoverySpells = new address[](recoverySpellLength);

        for (uint256 i = 0; i < ownersLength; i++) {
            instance.owners[i] = address(uint160(11 + i));
        }

        for (uint256 i = 0; i < recoverySpellLength; i++) {
            instance.recoverySpells[i] = address(uint160(101 + i));
        }

        instance.timelockParams.minDelay = MIN_DELAY;
        instance.timelockParams.expirationPeriod = EXPIRATION_PERIOD;
        instance.timelockParams.pauser = guardian;
        instance.timelockParams.pauseDuration = PAUSE_DURATION;
        instance.timelockParams.salt = bytes32(uint256(0x3a17));
        instance.timelockParams.contractAddresses = new address[](0);
        instance.timelockParams.selector = new bytes4[](0);
        instance.timelockParams.startIndex = new uint16[](0);
        instance.timelockParams.endIndex = new uint16[](0);
        instance.timelockParams.data = new bytes[](0);

        uint8[] memory allowedDays = new uint8[](5);
        allowedDays[0] = 1;
        allowedDays[1] = 2;
        allowedDays[2] = 3;
        allowedDays[3] = 4;
        allowedDays[4] = 5;

        TimeRestricted.TimeRange[] memory timeRanges =
            new TimeRestricted.TimeRange[](5);

        timeRanges[0] = TimeRestricted.TimeRange(10, 11);
        timeRanges[1] = TimeRestricted.TimeRange(10, 11);
        timeRanges[2] = TimeRestricted.TimeRange(12, 13);
        timeRanges[3] = TimeRestricted.TimeRange(10, 14);
        timeRanges[4] = TimeRestricted.TimeRange(11, 13);

        instance.timeRanges = timeRanges;
        instance.allowedDays = allowedDays;

        (newTimelock, newSafe) = deployer.createSystemInstance(instance);

        if (runAssertions) {
            /// safe validations

            for (uint256 i = 0; i < ownersLength; i++) {
                assertTrue(
                    Safe(payable(newSafe)).isOwner(instance.owners[i]),
                    "owner incorrect"
                );
            }

            for (uint256 i = 0; i < recoverySpellLength; i++) {
                assertTrue(
                    Safe(payable(newSafe)).isModuleEnabled(
                        instance.recoverySpells[i]
                    ),
                    "module incorrect"
                );
            }
            assertEq(
                Safe(payable(newSafe)).getOwners().length,
                ownersLength,
                "owner length incorrect"
            );

            (address[] memory array,) =
                Safe(payable(newSafe)).getModulesPaginated(address(1), 25);

            assertEq(
                array.length, 1 + recoverySpellLength, "module length incorrect"
            );

            uint256[] memory daysEnabled =
                restricted.safeDaysEnabled(address(newSafe));

            assertEq(
                restricted.numDaysEnabled(address(newSafe)),
                5,
                "incorrect days enabled length"
            );
            assertEq(daysEnabled.length, 5, "incorrect days enabled length");
            assertEq(daysEnabled[0], 1, "incorrect day 1");
            assertEq(daysEnabled[1], 2, "incorrect day 2");
            assertEq(daysEnabled[2], 3, "incorrect day 3");
            assertEq(daysEnabled[3], 4, "incorrect day 4");
            assertEq(daysEnabled[4], 5, "incorrect day 5");

            {
                (uint8 startHour, uint8 endHour) =
                    restricted.dayTimeRanges(address(newSafe), 1);
                assertEq(startHour, 10, "incorrect start hour");
                assertEq(endHour, 11, "incorrect end hour");
            }

            {
                (uint8 startHour, uint8 endHour) =
                    restricted.dayTimeRanges(address(newSafe), 2);
                assertEq(startHour, 10, "incorrect start hour");
                assertEq(endHour, 11, "incorrect end hour");
            }
            {
                (uint8 startHour, uint8 endHour) =
                    restricted.dayTimeRanges(address(newSafe), 3);
                assertEq(startHour, 12, "incorrect start hour");
                assertEq(endHour, 13, "incorrect end hour");
            }
            {
                (uint8 startHour, uint8 endHour) =
                    restricted.dayTimeRanges(address(newSafe), 4);
                assertEq(startHour, 10, "incorrect start hour");
                assertEq(endHour, 14, "incorrect end hour");
            }
            {
                (uint8 startHour, uint8 endHour) =
                    restricted.dayTimeRanges(address(newSafe), 5);
                assertEq(startHour, 11, "incorrect start hour");
                assertEq(endHour, 13, "incorrect end hour");
            }

            /// timelock validations

            assertEq(
                newTimelock.safe(),
                address(newSafe),
                "timelock not owned by safe"
            );
            assertEq(
                newTimelock.minDelay(),
                instance.timelockParams.minDelay,
                "timelock minDelay"
            );
            assertEq(
                newTimelock.expirationPeriod(),
                instance.timelockParams.expirationPeriod,
                "timelock expiration period"
            );
            assertEq(
                newTimelock.getAllProposals().length, 0, "proposal length 0"
            );
            assertFalse(newTimelock.pauseUsed(), "pause should not be used yet");
            assertEq(
                newTimelock.pauseStartTime(), 0, "pauseStartTime should be 0"
            );
            assertEq(
                newTimelock.pauseGuardian(),
                guardian,
                "guardian incorrectly set"
            );
            assertEq(
                newTimelock.pauseDuration(),
                instance.timelockParams.pauseDuration,
                "pause duration incorrectly set"
            );
            assertTrue(
                timelockFactory.factoryCreated(address(newTimelock)),
                "timelock incorrectly registered in factory"
            );
        }
    }

    /// recovery spell bytecode check

    /// timelock deploy failed

    /// safe deploy failed

    function testSafeExecTransactionFails() public {}

    /// safe exec transaction fails
}
