pragma solidity 0.8.25;

import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";

import {Timelock} from "src/Timelock.sol";
import {TimelockFactory, DeploymentParams} from "src/TimelockFactory.sol";
import {
    calculateCreate2Address, Create2Params
} from "src/utils/Create2Helper.sol";
import {
    InstanceDeployer,
    NewInstance,
    SystemInstance
} from "src/InstanceDeployer.sol";

contract AddressCalculation {
    /// @notice instance deployer
    address public immutable instanceDeployer;

    constructor(address _instanceDeployer) {
        instanceDeployer = _instanceDeployer;
    }

    /// @notice calculate address with safety checks, ensuring the address has
    /// not already been created by the respective safe and timelock factories
    /// @param instance configuration information
    function calculateAddress(NewInstance memory instance)
        external
        view
        returns (SystemInstance memory walletInstance)
    {
        /// important check:
        ///   - recovery spells should have no bytecode
        ///   - this is a duplicate check, however there is no harm in being safe
        for (uint256 i = 0; i < instance.recoverySpells.length; i++) {
            require(
                instance.recoverySpells[i].code.length == 0,
                "InstanceDeployer: recovery spell has bytecode"
            );
        }

        walletInstance = calculateAddressUnsafe(instance);

        /// if the safe does not exist, then there should be no need to check
        /// recovery spell addresses because they will not be able to be
        /// created from the recovery spell factory if the safe does not exist.
        require(
            address(walletInstance.safe).code.length == 0,
            "InstanceDeployer: safe already created"
        );
        require(
            address(walletInstance.timelock).code.length == 0,
            "InstanceDeployer: timelock already created"
        );
    }

    /// @notice calculate address without safety checks
    /// WARNING: only use this if you know what you are doing and are an
    /// advanced user.
    /// @param instance configuration information
    function calculateAddressUnsafe(NewInstance memory instance)
        public
        view
        returns (SystemInstance memory walletInstance)
    {
        address[] memory factoryOwner = new address[](1);
        factoryOwner[0] = instanceDeployer;

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

        {
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

            /// timelock salt is the result of the all params, so no one can
            /// front-run creation of the timelock with the same address on other
            /// chains
            instance.timelockParams.salt = bytes32(creationSalt);

            bytes32 salt = keccak256(
                abi.encodePacked(keccak256(safeInitdata), creationSalt)
            );
            address safeProxyFactory =
                InstanceDeployer(instanceDeployer).safeProxyFactory();

            walletInstance.safe = SafeProxy(
                payable(
                    calculateCreate2Address(
                        safeProxyFactory,
                        SafeProxyFactory(safeProxyFactory).proxyCreationCode(),
                        abi.encodePacked(
                            uint256(
                                uint160(
                                    InstanceDeployer(instanceDeployer)
                                        .safeProxyLogic()
                                )
                            )
                        ),
                        salt
                    )
                )
            );
        }
        address timelockFactory =
            InstanceDeployer(instanceDeployer).timelockFactory();

        Create2Params memory params;
        params.creator = timelockFactory;
        params.creationCode =
            TimelockFactory(timelockFactory).timelockCreationCode();

        params.constructorParams = abi.encode(
            walletInstance.safe,
            instance.timelockParams.minDelay,
            instance.timelockParams.expirationPeriod,
            instance.timelockParams.pauser,
            instance.timelockParams.pauseDuration,
            instance.timelockParams.hotSigners
        );
        params.salt = keccak256(
            abi.encodePacked(instance.timelockParams.salt, instanceDeployer)
        );

        walletInstance.timelock =
            Timelock(payable(calculateCreate2Address(params)));
    }
}
