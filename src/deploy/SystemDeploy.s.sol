pragma solidity 0.8.25;

import {
    MultisigProposal
} from "@forge-proposal-simulator/src/proposals/MultisigProposal.sol";
import {Addresses} from "@forge-proposal-simulator/addresses/Addresses.sol";

import {Guard} from "src/Guard.sol";
import {Timelock} from "src/Timelock.sol";
import {BytesHelper} from "src/BytesHelper.sol";
import {TimelockFactory} from "src/TimelockFactory.sol";
import {InstanceDeployer} from "src/InstanceDeployer.sol";
import {AddressCalculation} from "src/views/AddressCalculation.sol";
import {RecoverySpellFactory} from "src/RecoverySpellFactory.sol";

function matchPattern(bytes memory data, bytes4 pattern)
    pure
    returns (uint256)
{
    require(data.length >= 4, "Data length is less than pattern length");

    for (uint256 i = 0; i <= data.length - 4; i++) {
        bool isMatch = true;
        for (uint256 j = 0; j < 4; j++) {
            if (data[i + j] != pattern[j]) {
                isMatch = false;
                break;
            }
        }
        if (isMatch) {
            return i + 1;
        }
    }
    return 0;
}

/// @notice system deployment contract
/// all contracts are permissionless
/// DO_PRINT=false DO_BUILD=false DO_RUN=false DO_DEPLOY=true DO_VALIDATE=true forge script src/deploy/SystemDeploy.s.sol:SystemDeploy --fork-url base -vvvvv
contract SystemDeploy is MultisigProposal {
    using BytesHelper for bytes;

    bytes32 public salt =
        0x0000000000000000000000000000000000000000000000000000000000003afe;
    bytes4 public pattern = 0xa2646970;

    constructor() {
        uint256[] memory chainIds = new uint256[](5);
        chainIds[0] = 1;
        chainIds[1] = 8453;
        chainIds[2] = 84532;
        chainIds[3] = 11155420;
        chainIds[4] = 10;
        addresses = new Addresses("./addresses", chainIds);
    }

    function name() public pure override returns (string memory) {
        return "SYS_DEPLOY";
    }

    function description() public pure override returns (string memory) {
        return "Deploy Factories, Instance Deployer, Guard and View contracts";
    }

    function deploy() public override {
        if (!addresses.isAddressSet("TIMELOCK_FACTORY")) {
            TimelockFactory factory = new TimelockFactory{salt: salt}();
            addresses.addAddress("TIMELOCK_FACTORY", address(factory), true);
        }
        if (!addresses.isAddressSet("RECOVERY_SPELL_FACTORY")) {
            RecoverySpellFactory recoveryFactory =
                new RecoverySpellFactory{salt: salt}();
            addresses.addAddress(
                "RECOVERY_SPELL_FACTORY", address(recoveryFactory), true
            );
        }
        if (!addresses.isAddressSet("GUARD")) {
            Guard guard = new Guard{salt: salt}();
            addresses.addAddress("GUARD", address(guard), true);
        }
        if (!addresses.isAddressSet("INSTANCE_DEPLOYER")) {
            InstanceDeployer deployer = new InstanceDeployer{
                salt: salt
            }(
                addresses.getAddress("SAFE_FACTORY"),
                addresses.getAddress("SAFE_LOGIC"),
                addresses.getAddress("TIMELOCK_FACTORY"),
                addresses.getAddress("GUARD"),
                addresses.getAddress("MULTICALL3")
            );

            addresses.addAddress("INSTANCE_DEPLOYER", address(deployer), true);
        }
        if (!addresses.isAddressSet("ADDRESS_CALCULATION")) {
            AddressCalculation addressCalculation = new AddressCalculation{
                salt: salt
            }(addresses.getAddress("INSTANCE_DEPLOYER"));

            addresses.addAddress(
                "ADDRESS_CALCULATION", address(addressCalculation), true
            );
        }
    }

    function validate() public view override {
        if (addresses.isAddressSet("TIMELOCK_FACTORY")) {
            address factory = addresses.getAddress("TIMELOCK_FACTORY");
            uint256 endIndex = matchPattern(factory.code, pattern);
            endIndex = endIndex == 0 ? factory.code.length - 1 : endIndex - 1;
            assertEq(
                keccak256(factory.code.sliceBytes(0, endIndex)),
                keccak256(
                    type(TimelockFactory).runtimeCode.sliceBytes(0, endIndex)
                ),
                "Incorrect TimelockFactory Bytecode"
            );

            address guard = addresses.getAddress("GUARD");
            endIndex = matchPattern(guard.code, pattern);
            endIndex = endIndex == 0 ? guard.code.length - 1 : endIndex - 1;
            assertEq(
                keccak256(guard.code.sliceBytes(0, endIndex)),
                keccak256(type(Guard).runtimeCode.sliceBytes(0, endIndex)),
                "Incorrect Guard Bytecode"
            );

            address recoverySpellFactory =
                addresses.getAddress("RECOVERY_SPELL_FACTORY");
            endIndex = matchPattern(recoverySpellFactory.code, pattern);
            endIndex = endIndex == 0
                ? recoverySpellFactory.code.length - 1
                : endIndex - 1;
            assertEq(
                keccak256(recoverySpellFactory.code.sliceBytes(0, endIndex)),
                keccak256(
                    type(RecoverySpellFactory).runtimeCode
                        .sliceBytes(0, endIndex)
                ),
                "Incorrect RecoverySpellFactory Bytecode"
            );

            /// cannot check bytecode, following error is thrown when trying:
            ///  `"runtimeCode" is not available for contracts containing
            ///   immutable variables.`
            InstanceDeployer deployer =
                InstanceDeployer(addresses.getAddress("INSTANCE_DEPLOYER"));

            assertEq(
                deployer.safeProxyFactory(),
                addresses.getAddress("SAFE_FACTORY"),
                "incorrect safe proxy factory"
            );
            assertEq(
                deployer.safeProxyLogic(),
                addresses.getAddress("SAFE_LOGIC"),
                "incorrect safe logic contract"
            );
            assertEq(
                deployer.timelockFactory(),
                addresses.getAddress("TIMELOCK_FACTORY"),
                "incorrect timelock factory"
            );
            assertEq(
                deployer.guard(),
                addresses.getAddress("GUARD"),
                "incorrect GUARD"
            );
            assertEq(
                deployer.multicall3(),
                addresses.getAddress("MULTICALL3"),
                "incorrect MULTICALL3"
            );
        }
    }
}
