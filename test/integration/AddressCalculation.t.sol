// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "test/utils/SystemIntegrationFixture.sol";

contract AddressCalculationIntegrationTest is SystemIntegrationFixture {
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
            contractAddresses: contractAddresses,
            selector: selector,
            startIndex: startIndex,
            endIndex: endIndex,
            data: data,
            salt: salt
        });

        NewInstance memory instance = NewInstance({
            owners: owners,
            threshold: threshold,
            recoverySpells: recoverySpell,
            timelockParams: params
        });

        SystemInstance memory expectedContracts =
            deployer.calculateAddress(instance);
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
