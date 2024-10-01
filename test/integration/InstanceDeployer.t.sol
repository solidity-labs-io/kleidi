pragma solidity 0.8.25;

import "test/utils/SystemIntegrationFixture.sol";

contract InstanceDeployerIntegrationTest is SystemIntegrationFixture {
    using BytesHelper for bytes;

    function testValidateDeployment() public view {
        validate();
    }

    function testNonHotSignerCannotDeploy() public {
        uint8 recoverySpellLength = 7;
        uint8 ownersLength = 3;

        NewInstance memory instance;

        instance.owners = new address[](ownersLength);
        instance.threshold = 2;
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
        instance.timelockParams.hotSigners = new address[](0);

        vm.prank(HOT_SIGNER_ONE);
        vm.expectRevert("InstanceDeployer: sender must be hot signer");
        deployer.createSystemInstance(instance);
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

    function testFrontRunningOnlySafeCreationAllowsSetupContinuation() public {
        uint8 ownersLength = 10;
        uint8 threshold = 5;
        uint8 recoverySpellLength = 7;

        NewInstance memory instance;

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
        instance.timelockParams.hotSigners = new address[](1);
        instance.timelockParams.hotSigners[0] = HOT_SIGNER_ONE;

        uint256 creationSalt = uint256(
            keccak256(
                abi.encode(
                    instance.owners,
                    instance.threshold,
                    instance.timelockParams.minDelay,
                    instance.timelockParams.expirationPeriod,
                    instance.timelockParams.pauser,
                    instance.timelockParams.pauseDuration,
                    instance.timelockParams.hotSigners
                )
            )
        );

        address[] memory factoryOwner = new address[](1);
        factoryOwner[0] = address(deployer);

        bytes memory safeInitData = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            factoryOwner,
            1,
            /// no to address because there are no external actions on
            /// initialization
            address(0),
            /// no data because there are no external actions on initialization
            "",
            /// no fallback handler allowed by Guard
            address(0),
            /// no payment token
            address(0),
            /// no payment amount
            0,
            /// no payment receiver because no payment amount
            address(0)
        );

        SafeProxy proxy = factory.createProxyWithNonce(
            deployer.safeProxyLogic(), safeInitData, creationSalt
        );

        (Timelock newTimelock, SafeProxy newSafe) =
        _createAndValidateSystemInstance(
            ownersLength, threshold, recoverySpellLength, true
        );

        assertEq(
            address(proxy),
            address(newSafe),
            "safe address incorrectly calculated"
        );

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

        /// timelock validations

        assertEq(
            newTimelock.safe(), address(newSafe), "timelock not owned by safe"
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
        assertEq(newTimelock.getAllProposals().length, 0, "proposal length 0");
        assertFalse(
            newTimelock.pauseStartTime() != 0, "pause should not be used yet"
        );
        assertEq(newTimelock.pauseStartTime(), 0, "pauseStartTime should be 0");
        assertEq(
            newTimelock.pauseGuardian(), guardian, "guardian incorrectly set"
        );
        assertEq(
            newTimelock.pauseDuration(),
            instance.timelockParams.pauseDuration,
            "pause duration incorrectly set"
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

        vm.expectRevert(stdError.assertionError);
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
        NewInstance memory instance;

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
        instance.timelockParams.hotSigners = new address[](1);
        instance.timelockParams.hotSigners[0] = HOT_SIGNER_ONE;

        vm.prank(HOT_SIGNER_ONE);
        SystemInstance memory wallet = deployer.createSystemInstance(instance);

        newTimelock = wallet.timelock;
        newSafe = wallet.safe;

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
            assertFalse(
                newTimelock.pauseStartTime() != 0,
                "pause should not be used yet"
            );
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
        }
    }

    /// timelock deploy failed

    /// safe deploy failed

    function testSafeDeployFrontrunStillAllowsDeployment() public {
        uint256 newQuorum = 3;
        NewInstance memory instance = NewInstance(
            owners,
            newQuorum,
            /// no recovery spells for now
            new address[](0),
            DeploymentParams(
                MINIMUM_DELAY,
                EXPIRATION_PERIOD,
                guardian,
                PAUSE_DURATION,
                hotSigners,
                new address[](0),
                new bytes4[](0),
                new uint16[](0),
                new uint16[](0),
                new bytes[][](0),
                bytes32(0)
            )
        );

        address[] memory factoryOwner = new address[](1);
        factoryOwner[0] = address(deployer);

        bytes memory safeInitdata = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            factoryOwner,
            1,
            /// no to address because there are no external actions on
            /// initialization
            address(0),
            /// no data because there are no external actions on initialization
            "",
            /// no fallback handler allowed by Guard
            address(0),
            /// no payment token
            address(0),
            /// no payment amount
            0,
            /// no payment receiver because no payment amount
            address(0)
        );

        uint256 creationSalt = uint256(
            keccak256(
                abi.encode(
                    instance.owners,
                    instance.threshold,
                    instance.timelockParams.minDelay,
                    instance.timelockParams.expirationPeriod,
                    instance.timelockParams.pauser,
                    instance.timelockParams.pauseDuration,
                    instance.timelockParams.hotSigners
                )
            )
        );

        SafeProxy safeProxy = SafeProxyFactory(deployer.safeProxyFactory())
            .createProxyWithNonce(
            deployer.safeProxyLogic(), safeInitdata, creationSalt
        );

        vm.expectEmit(true, true, true, true, address(deployer));
        emit SafeCreationFailed(
            HOT_SIGNER_ONE,
            block.timestamp,
            address(safeProxy),
            safeInitdata,
            creationSalt
        );

        vm.prank(HOT_SIGNER_ONE);
        SystemInstance memory walletInstance =
            deployer.createSystemInstance(instance);

        assertEq(
            address(walletInstance.safe),
            address(safeProxy),
            "safe proxy address incorrect"
        );
    }
}
