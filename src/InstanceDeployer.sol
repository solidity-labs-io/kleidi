pragma solidity 0.8.25;

import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {ModuleManager} from "@safe/base/ModuleManager.sol";
import {OwnerManager} from "@safe/base/OwnerManager.sol";
import {GuardManager} from "@safe/base/GuardManager.sol";
import {IMulticall3} from "@interface/IMulticall3.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

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
    /// @notice safe proxy creation factory
    address public immutable safeProxyFactory;

    /// @notice safe proxy logic contract
    address public immutable safeProxyLogic;

    /// @notice timelock factory address
    address public immutable timelockFactory;

    /// @notice TimeRestricted address
    address public immutable timeRestricted;

    /// @notice MULTICALL3 address
    address public immutable multicall3;

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
        /// timelock information
        DeploymentParams timelockParams;
        /// time restriction information
        TimeRestricted.TimeRange[] timeRanges;
        uint8[] allowedDays;
    }

    /// @notice function to create a system instance that has the following
    /// contracts and configurations:
    /// 1. new safe created with specified owners and threshold
    /// 2. new timelock created owned by the safe
    /// 3. timelock is a module in the safe
    /// 4. time restricted is configured as a guard on the safe
    /// 5. all recovery spells are added as modules on the safe
    /// 6. this contract is no longer an owner and threshold is updated to
    /// the threshold parameter passed
    /// A key system property is that deployments are deterministic across
    /// all chains. The same calldata on any EVM equivalent chain will generate
    /// the same safe and timelock address.
    /// @param instance configuration parameters
    function createSystemInstance(NewInstance memory instance)
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

        address[] memory factoryOwner = new address[](1);
        factoryOwner[0] = address(this);

        bytes memory safeInitdata = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            factoryOwner,
            1,
            /// no to address because there are no external actions on
            /// initialization
            address(0),
            /// no data because there are no external actions on initialization
            "",
            /// no fallback handler allowed by TimeRestricted
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
                    instance.recoverySpells,
                    instance.timelockParams,
                    instance.timeRanges,
                    instance.allowedDays
                )
            )
        );

        /// timelock salt is the result of the all params, so no one can
        /// front-run creation of the timelock with the same address on other
        /// chains
        instance.timelockParams.salt = bytes32(creationSalt);

        safe = SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
            safeProxyLogic, safeInitdata, creationSalt
        );

        require(
            Safe(payable(safe)).isOwner(address(this)) == true,
            "owner not set correctly"
        );
        require(
            Safe(payable(safe)).getOwners().length == 1,
            "owners not set correctly"
        );

        timelock = Timelock(
            payable(
                TimelockFactory(timelockFactory).createTimelock(
                    address(safe), instance.timelockParams
                )
            )
        );

        /// check contracts are deployed
        require(
            address(timelock).code.length != 0,
            "InstanceDeployer: timelock failed to deploy"
        );
        require(
            address(safe).code.length != 0,
            "InstanceDeployer: safe failed to deploy"
        );

        IMulticall3.Call3[] memory calls3 = new IMulticall3.Call3[](
            3 + instance.recoverySpells.length + instance.owners.length
        );
        uint256 index = 0;

        calls3[0].target = timeRestricted;
        calls3[0].allowFailure = false;

        calls3[index++].callData = abi.encodeWithSelector(
            TimeRestricted.initializeConfiguration.selector,
            address(timelock),
            instance.timeRanges,
            instance.allowedDays
        );

        for (uint256 i = 1; i < calls3.length; i++) {
            calls3[i].target = address(safe);
            calls3[i].allowFailure = false;
        }

        calls3[index++].callData = abi.encodeWithSelector(
            GuardManager.setGuard.selector, timeRestricted
        );

        calls3[index++].callData = abi.encodeWithSelector(
            ModuleManager.enableModule.selector, address(timelock)
        );

        /// enable all recovery spells
        for (uint256 i = 0; i < instance.recoverySpells.length; i++) {
            calls3[index++].callData = abi.encodeWithSelector(
                ModuleManager.enableModule.selector, instance.recoverySpells[i]
            );
        }

        calls3[index++].callData = abi.encodeWithSelector(
            OwnerManager.swapOwner.selector,
            address(1),
            address(this),
            instance.owners[0]
        );

        /// only cover indexes 1 through newOwners.length - 1
        for (uint256 i = 1; i < instance.owners.length - 1; i++) {
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.addOwnerWithThreshold.selector,
                instance.owners[i],
                1
            );
        }

        if (instance.owners.length > 1) {
            /// add final owner with the updated threshold
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.addOwnerWithThreshold.selector,
                instance.owners[instance.owners.length - 1],
                instance.threshold
            );
        }

        assert(calls3.length == index);

        bytes memory signature;
        {
            bytes32 r = bytes32(uint256(uint160(address(this))));
            uint8 v = 1;

            assembly {
                /// Load free memory location
                let ptr := mload(0x40)

                /// We allocate memory for the return data by setting the free memory location to
                /// current free memory location + data size + 32 bytes for data size value
                mstore(0x40, add(ptr, 97))

                /// Store the size of the signature:
                /// 65 (r + s + v)
                mstore(ptr, 65)

                /// Store the data

                /// store r
                mstore(add(ptr, 0x20), r)

                /// no need to store s

                /// store v
                mstore8(add(ptr, 0x60), v)

                /// Point the signature data to the correct memory location
                signature := ptr
            }
        }

        require(
            Safe(payable(safe)).execTransaction(
                multicall3,
                0,
                abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls3),
                Enum.Operation.DelegateCall,
                0,
                0,
                0,
                address(0),
                payable(0),
                signature
            ),
            "InstanceDeployer: Safe delegate call failed"
        );

        emit SystemInstanceCreated(
            address(safe), address(timelock), msg.sender, block.timestamp
        );
    }
}
