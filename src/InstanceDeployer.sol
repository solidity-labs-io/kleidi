pragma solidity 0.8.25;

import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {ModuleManager} from "@safe/base/ModuleManager.sol";
import {GuardManager} from "@safe/base/GuardManager.sol";
import {IMulticall3} from "@interface/IMulticall3.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";

import {Timelock} from "src/Timelock.sol";
import {TimeRestricted} from "src/TimeRestricted.sol";
import {TimelockFactory, DeploymentParams} from "src/TimelockFactory.sol";

/// @notice deploy a completely set up instance of a contract
/// system for a user.

/// @notice the deployment process is as follows:
///
///    1. deploy the safe proxy with this contract as the owner from the proxy
///    factory
///    2. deploy the timelock contract with the new safe as the owner
///
///    All of the following actions are batched into a single action
///  through multicall. The actions are as follows:
///
///    3. call the time restricted contract to initialize the configuration
///    4. add the timelock as a module to the safe
///    5. add the time restricted contract as a guard to the safe
///    6. add all recovery spells as modules to the safe
///    7. rotate this contract as the safe owner off the safe and add the supplied
/// owners to the safe. Update the proposal threshold on the final call
/// performing these swaps.
contract InstanceDeployer {
    /// @notice safe proxy creation code
    address public immutable safeProxyFactory;

    /// @notice safe proxy creation code
    address public immutable safeProxyLogic;

    /// @notice timelock factory address
    address public immutable timelockFactory;

    /// @notice TimeRestricted address
    address public immutable timeRestricted;

    /// @notice MULTICALL3 address
    address public immutable multicall3;

    /// @notice salt for the timelock
    bytes32 public constant TIMELOCK_SALT = bytes32(uint256(0x3afe));

    /// @notice emitted when a new system instance is created
    /// @param safe address of the safe
    /// @param timelock address of the timelock
    /// @param creator address that created the system instance
    /// @param creationTime time the system instance was created in unix time
    event SystemInstanceCreated(
        address indexed safe,
        address indexed timelock,
        address indexed creator,
        uint256 creationTime
    );

    constructor(
        address _safeProxyFactory,
        address _safeProxyLogic,
        address _timelockFactory,
        address _timeRestricted,
        address _multicall3
    ) {
        safeProxyFactory = _safeProxyFactory;
        safeProxyLogic = _safeProxyLogic;
        timelockFactory = _timelockFactory;
        timeRestricted = _timeRestricted;
        multicall3 = _multicall3;
    }

    struct NewInstance {
        /// safe information
        address[] owners;
        uint256 threshold;
        address[] recoverySpells;
        uint256 safeNonceSalt;
        /// timelock information
        DeploymentParams timelockParams;
        /// time restriction information
        TimeRestricted.TimeRange[] timeRanges;
        uint8[] allowedDays;
    }

    function createSystemInstance(NewInstance calldata instance)
        external
        returns (Timelock timelock, SafeProxy safe)
    {
        /// important check:
        ///   recovery spells should have no bytecode
        for (uint256 i = 0; i < instance.recoverySpells.length; i++) {
            require(
                instance.recoverySpells[i].code.length == 0,
                "InstanceDeployer: recovery spell has bytecode"
            );
        }

        safe = SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
            safeProxyLogic, "", instance.safeNonceSalt
        );

        timelock = Timelock(
            payable(
                TimelockFactory(timelockFactory).createTimelock(
                    address(safe), instance.timelockParams
                )
            )
        );

        IMulticall3.Call3[] memory calls3 =
            new IMulticall3.Call3[](3 + instance.recoverySpells.length);

        calls3[0].target = timeRestricted;
        calls3[0].allowFailure = false;

        calls3[0].callData = abi.encodeWithSelector(
            TimeRestricted.initializeConfiguration.selector,
            address(timelock),
            instance.timeRanges,
            instance.allowedDays
        );

        for (uint256 i = 1; i < calls3.length; i++) {
            calls3[i].target = address(safe);
            calls3[i].allowFailure = false;
        }

        calls3[1].callData = abi.encodeWithSelector(
            GuardManager.setGuard.selector, timeRestricted
        );

        calls3[2].callData = abi.encodeWithSelector(
            ModuleManager.enableModule.selector, address(timelock)
        );

        /// enable all recovery spells
        for (uint256 i = 0; i < instance.recoverySpells.length; i++) {
            calls3[i + 3].callData = abi.encodeWithSelector(
                ModuleManager.enableModule.selector, instance.recoverySpells[i]
            );
        }

        bytes memory initdata = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            instance.owners,
            instance.threshold,
            /// no to address because there are no external actions on
            /// initialization
            multicall3,
            /// no data because there are no external actions on initialization
            abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls3),
            /// no fallback handler allowed by TimeRestricted
            address(0),
            /// no payment token
            address(0),
            /// no payment amount
            0,
            /// no payment receiver because no payment amount
            address(0)
        );

        {
            (bool success,) = address(safe).call{value: 0}(initdata);

            require(success, "InstanceDeployer: safe initialization failed");
        }

        /// check contracts are deployed
        require(
            address(timelock).code.length != 0,
            "InstanceDeployer: timelock failed to deploy"
        );
        require(
            address(safe).code.length != 0,
            "InstanceDeployer: safe failed to deploy"
        );

        emit SystemInstanceCreated(
            address(safe), address(timelock), msg.sender, block.timestamp
        );
    }
}
