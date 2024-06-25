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
import {calculateCreate2Address} from "src/utils/Create2Helper.sol";
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

    /// @param sender address that attempted to create the safe
    /// @param timestamp time the safe creation failed
    /// @param safeInitdata initialization data for the safe
    /// @param creationSalt salt used to create the safe
    event SafeCreationFailed(
        address indexed sender,
        uint256 indexed timestamp,
        bytes safeInitdata,
        uint256 creationSalt
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

        /// safe guard against front-running safe creation with the same
        /// address, init data and creation salt on other chains
        try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
            safeProxyLogic, safeInitdata, creationSalt
        ) returns (SafeProxy safeProxy) {
            safe = safeProxy;
        } catch {
            emit SafeCreationFailed(
                msg.sender, block.timestamp, safeInitdata, creationSalt
            );
        }

        /// if front-running occurred, there should be no way for the safe to
        /// be created without the exact same address, which means init data
        /// set the owner of the safe to be this factory address.
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

        /// add the timelock as a module to the safe
        /// this enables the timelock to execute calls + delegate calls through
        /// the safe
        calls3[index++].callData = abi.encodeWithSelector(
            ModuleManager.enableModule.selector, address(timelock)
        );

        /// enable all recovery spells in the safe by adding them as modules
        for (uint256 i = 0; i < instance.recoverySpells.length; i++) {
            /// all recovery spells should be private at the time of safe
            /// creation, however we cannot enforce this except by excluding
            /// recovery spells that are not private.

            /// We cannot have a check here that recovery spells are private
            /// because if we did, and a recovery spell got activated, and it
            /// was activated on another chain where the system instance was
            /// deployed, and then the system instance was not deployed on this
            /// chain, then a malicious user could deploy the recovery spell
            /// before the system instance to block the instance from ever
            /// being deployed to this chain.
            calls3[index++].callData = abi.encodeWithSelector(
                ModuleManager.enableModule.selector, instance.recoverySpells[i]
            );
        }

        calls3[index++].callData = abi.encodeWithSelector(
            OwnerManager.swapOwner.selector,
            /// previous owner
            address(1),
            /// old owner (this address)
            address(this),
            /// new owner, the first owner the caller wants to add
            instance.owners[0]
        );

        /// - add owners with threshold of 1
        /// - only cover indexes 1 through newOwners.length - 1
        /// - leave the last index for the final owner which will adjust the
        /// threshold
        for (uint256 i = 1; i < instance.owners.length - 1; i++) {
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.addOwnerWithThreshold.selector,
                instance.owners[i],
                1
            );
        }

        /// if there are more than one owner, add the final owner with the
        /// updated threshold
        if (instance.owners.length > 1) {
            /// add final owner with the updated threshold
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.addOwnerWithThreshold.selector,
                instance.owners[instance.owners.length - 1],
                instance.threshold
            );
        }

        /// ensure that the number of calls is equal to the index
        /// this is a safety check and should never be false
        assert(calls3.length == index);

        bytes memory signature;
        /// craft the signature singing off on all of the multicall
        /// operations
        {
            bytes32 r = bytes32(uint256(uint160(address(this))));
            uint8 v = 1;

            assembly {
                /// Load free memory location
                let ptr := mload(0x40)

                /// We allocate memory for the return data by setting the free memory location to
                /// current free memory location + data size + 32 bytes for data size value

                ///         4 -> 82
                mstore(0x40, add(ptr, 97))
                ///         4 -> 179

                /// Store the size of the signature in the first 32 bytes:
                /// 65 (r + s + v)
                mstore(ptr, 65)

                ///
                ///                              Data Offsets
                ///
                ///                 --------------------------------------
                ///  bytes length   |      32     |   32  |  32   |   1  |
                ///                 --------------------------------------
                ///      bytes      |     0-31    | 32-63 | 64-95 |  96  |
                ///                 --------------------------------------
                ///      data       | length = 65 |   r   |   s   |   v  |
                ///                 --------------------------------------
                ///

                /// store r at offset 32 to 64 in the allocated pointer
                mstore(add(ptr, 0x20), r)

                /// no need to store s

                /// store v at offset 96 to 97 in the allocated pointer
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

    /// @notice calculate address with safety checks, ensuring the address has
    /// not already been created by the respective safe and timelock factories
    /// @param instance configuration information
    function calculateAddress(NewInstance memory instance)
        external
        view
        returns (address timelock, address safe)
    {
        (timelock, safe) = calculateAddressUnsafe(instance);

        require(safe.code.length == 0, "InstanceDeployer: safe already created");

        /// timelock created in factory implies that it has bytecode
        require(
            !TimelockFactory(timelockFactory).factoryCreated(timelock),
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
        returns (address timelock, address safe)
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

        {
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

            bytes32 salt = keccak256(
                abi.encodePacked(keccak256(safeInitdata), creationSalt)
            );

            safe = calculateCreate2Address(
                safeProxyFactory,
                SafeProxyFactory(safeProxyFactory).proxyCreationCode(),
                abi.encodePacked(uint256(uint160(safeProxyLogic))),
                salt
            );

            require(
                safe.code.length == 0, "InstanceDeployer: safe already created"
            );
        }

        timelock = TimelockFactory(timelockFactory).calculateAddress(
            safe, instance.timelockParams
        );

        require(
            !TimelockFactory(timelockFactory).factoryCreated(timelock),
            "InstanceDeployer: timelock already created"
        );
    }
}
