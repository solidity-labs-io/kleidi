// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "test/utils/SystemIntegrationFixture.sol";

contract AddressCalculationIntegrationTest is SystemIntegrationFixture {
    function testSetup() public view {
        assertEq(
            addressCalculation.instanceDeployer(),
            address(deployer),
            "Instance deployer should match"
        );
    }

    function testCalculateAddressMatchesCreatedAddresses() public {
        address[] memory recoverySpell = new address[](1);
        recoverySpell[0] = recoverySpellAddress;

        /// 2 / 3 multisig
        uint256 threshold = 2;

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
            datas: new bytes[](0),
            isSelfAddressCheck: new bool[](0),
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        SystemInstance memory expectedContracts =
            addressCalculation.calculateAddress(instance);

        vm.prank(HOT_SIGNER_ONE);
        SystemInstance memory actualContracts =
            deployer.createSystemInstance(instance);

        assertEq(
            address(expectedContracts.safe),
            address(actualContracts.safe),
            "Safe address should match"
        );
        assertEq(
            address(expectedContracts.timelock),
            address(actualContracts.timelock),
            "Timelock address should match"
        );
    }

    function testRecoverySpellAddressesNotCalculated() public {
        address[] memory recoverySpell = new address[](1);
        recoverySpell[0] = recoverySpellAddress;

        /// 2 / 3 multisig
        uint256 threshold = 2;

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
            datas: new bytes[](0),
            isSelfAddressCheck: new bool[](0),
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        SystemInstance memory expectedContracts =
            addressCalculation.calculateAddress(instance);

        /// remove recovery spell
        instance.recoverySpells = new address[](0);

        vm.prank(HOT_SIGNER_ONE);
        SystemInstance memory actualContracts =
            deployer.createSystemInstance(instance);

        assertEq(
            address(expectedContracts.safe),
            address(actualContracts.safe),
            "Safe address should match"
        );
        assertEq(
            address(expectedContracts.timelock),
            address(actualContracts.timelock),
            "Timelock address should match"
        );
    }

    function testCalculateAddressSafeFailsSafeAlreadyDeployed() public {
        address[] memory recoverySpell = new address[](1);
        recoverySpell[0] = recoverySpellAddress;

        /// 2 / 3 multisig
        uint256 threshold = 2;

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
            datas: new bytes[](0),
            isSelfAddressCheck: new bool[](0),
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        /// remove recovery spell
        instance.recoverySpells = new address[](0);

        vm.prank(HOT_SIGNER_ONE);
        deployer.createSystemInstance(instance);

        vm.expectRevert("InstanceDeployer: safe already created");
        addressCalculation.calculateAddress(instance);
    }

    function testCalculateAddressTimelockFailsTimelockAlreadyDeployed()
        public
    {
        address[] memory recoverySpell = new address[](1);
        recoverySpell[0] = recoverySpellAddress;

        /// 2 / 3 multisig
        uint256 threshold = 2;

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
            datas: new bytes[](0),
            isSelfAddressCheck: new bool[](0),
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        /// remove recovery spell
        instance.recoverySpells = new address[](0);

        SystemInstance memory expectedContracts =
            addressCalculation.calculateAddress(instance);

        vm.etch(address(expectedContracts.timelock), hex"3afe");

        vm.expectRevert("InstanceDeployer: timelock already created");
        addressCalculation.calculateAddress(instance);
    }

    function testTimelockBytecodeUnsetFactorySet() public {
        address[] memory recoverySpell = new address[](1);
        recoverySpell[0] = recoverySpellAddress;

        /// 2 / 3 multisig
        uint256 threshold = 2;

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
            datas: new bytes[](0),
            isSelfAddressCheck: new bool[](0),
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        /// remove recovery spell
        instance.recoverySpells = new address[](0);

        vm.prank(HOT_SIGNER_ONE);
        SystemInstance memory contracts =
            deployer.createSystemInstance(instance);

        /// remove timelock and safe bytecode
        vm.etch(address(contracts.safe), "");
        vm.etch(address(contracts.timelock), "");

        vm.expectRevert("InstanceDeployer: timelock already created");
        addressCalculation.calculateAddress(instance);
    }

    function testCalculateAddressBytecodeRecoverySpellFails() public {
        address[] memory recoverySpell = new address[](1);
        recoverySpell[0] = recoverySpellAddress;

        /// 2 / 3 multisig
        uint256 threshold = 2;

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
            datas: new bytes[](0),
            isSelfAddressCheck: new bool[](0),
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        vm.etch(recoverySpellAddress, hex"3afe");

        vm.expectRevert("InstanceDeployer: recovery spell has bytecode");
        addressCalculation.calculateAddress(instance);
    }

    function testCalculateAddressUnsafe() public {
        address[] memory recoverySpell = new address[](1);
        recoverySpell[0] = recoverySpellAddress;

        /// 2 / 3 multisig
        uint256 threshold = 2;

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
            datas: new bytes[](0),
            isSelfAddressCheck: new bool[](0),
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        SystemInstance memory expectedContracts =
            addressCalculation.calculateAddressUnsafe(instance);

        vm.prank(HOT_SIGNER_ONE);
        SystemInstance memory actualContracts =
            deployer.createSystemInstance(instance);

        assertEq(
            address(expectedContracts.safe),
            address(actualContracts.safe),
            "Safe address should match"
        );
        assertEq(
            address(expectedContracts.timelock),
            address(actualContracts.timelock),
            "Timelock address should match"
        );
    }
}
