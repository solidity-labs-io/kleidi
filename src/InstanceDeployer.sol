pragma solidity 0.8.25;

import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {ModuleManager} from "@safe/base/ModuleManager.sol";
import {OwnerManager} from "@safe/base/OwnerManager.sol";
import {GuardManager} from "@safe/base/GuardManager.sol";
import {IMulticall3} from "@interface/IMulticall3.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

import {Guard} from "src/Guard.sol";
import {Timelock} from "src/Timelock.sol";
import {TimelockFactory, DeploymentParams} from "src/TimelockFactory.sol";
import {
    calculateCreate2Address, Create2Params
} from "src/utils/Create2Helper.sol";

/// @notice deploy a completely set up instance of a contract
/// system for a user.

/// Relies on both the SafeProxyFactory and TimelockFactory to be deployed
/// before this contract.
/// Then calls into the SafeProxyFactory and TimelockFactory to create the
/// Safe and Timelock.

/// @notice the deployment process is as follows:
///
///    1. deploy the safe proxy with this contract as the owner from the proxy
///    factory
///      - if the safe has already been deployed the proxy factory will continue
///      deploying the system instance, this is to prevent front-running attacks
///      where a malicious user could deploy the safe before the system
///      instance to block the instance from ever being deployed to this chain
///    2. deploy the timelock contract with the new safe as the owner
///      - it should be impossible for the timelock to be deployed at the
///      correct address without being deployed by the timelock factory because
///      the factory uses the msg.sender for creating its salt, which would be
///      the instance deployer.
///
///    All of the following actions are batched into a single action
///  through multicall. The actions are as follows:
///
///    3. add the timelock as a module to the safe
///    4. add the guard to the safe
///    5. add all recovery spells as modules to the safe
///    6. rotate this contract as the safe owner off the safe and add the supplied
///    owners to the safe.
///    7. Update the proposal threshold on the final call performing the rotation.

struct NewInstance {
    /// safe information
    address[] owners;
    uint256 threshold;
    /// recovery spells are not part of the creation salt as that would create
    /// a circular dependency
    address[] recoverySpells;
    /// timelock information
    DeploymentParams timelockParams;
}

struct SystemInstance {
    SafeProxy safe;
    Timelock timelock;
}

contract InstanceDeployer {
    /// @notice safe proxy creation factory, address is the same across all chains
    address public immutable safeProxyFactory;

    /// @notice safe proxy logic contract, address is the same across all chains
    address public immutable safeProxyLogic;

    /// @notice timelock factory address, address is the same across all chains
    address public immutable timelockFactory;

    /// @notice Guard address, address is the same across all chains
    address public immutable guard;

    /// @notice MULTICALL3 address, address is the same across all chains
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
        address indexed safe,
        bytes safeInitdata,
        uint256 creationSalt
    );

    /// @notice initialize with all immutable variables
    constructor(
        address _safeProxyFactory,
        address _safeProxyLogic,
        address _timelockFactory,
        address _guard,
        address _multicall3
    ) {
        safeProxyFactory = _safeProxyFactory;
        safeProxyLogic = _safeProxyLogic;
        timelockFactory = _timelockFactory;
        guard = _guard;
        multicall3 = _multicall3;
    }

    /// callable only by the hot signer of the timelock
    /// this prevents a malicious user from deploying a system instance with
    /// calldata that was not intended to be whitelisted.

    /// @notice function to create a system instance that has the following
    /// contracts and configurations:
    /// 1. new safe created with specified owners and threshold
    /// 2. new timelock created owned by the safe
    /// 3. timelock is a module in the safe
    /// 4. the guard is configured on the safe as a guard
    /// 5. all recovery spells are added as modules on the safe
    /// 6. this contract is no longer an owner and threshold is updated to
    /// the threshold parameter passed
    /// A key system property is that deployments are deterministic across
    /// all chains. The same calldata on any EVM equivalent chain will generate
    /// the same safe and timelock address.
    /// @param instance configuration parameters
    function createSystemInstance(NewInstance memory instance)
        external
        returns (SystemInstance memory walletInstance)
    {
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

        /// timelock salt is the result of the all params, so no one can
        /// front-run creation of the timelock with the same address on other
        /// chains
        instance.timelockParams.salt = bytes32(creationSalt);

        /// safe guard against front-running safe creation with the same
        /// address, init data and creation salt on other chains
        try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
            safeProxyLogic, safeInitdata, creationSalt
        ) returns (SafeProxy safeProxy) {
            walletInstance.safe = safeProxy;
        } catch {
            /// calculate salt just like the safe proxy factory does
            bytes32 salt = keccak256(
                abi.encodePacked(keccak256(safeInitdata), creationSalt)
            );
            walletInstance.safe = SafeProxy(
                payable(
                    calculateCreate2Address(
                        safeProxyFactory,
                        SafeProxyFactory(safeProxyFactory).proxyCreationCode(),
                        abi.encode(safeProxyLogic),
                        salt
                    )
                )
            );

            emit SafeCreationFailed(
                msg.sender,
                block.timestamp,
                address(walletInstance.safe),
                safeInitdata,
                creationSalt
            );
        }

        /// if front-running occurred, there should be no way for the safe to
        /// be created without the exact same address, which means init data
        /// set the owner of the safe to be this factory address.
        assert(Safe(payable(walletInstance.safe)).isOwner(address(this)));
        assert(Safe(payable(walletInstance.safe)).getOwners().length == 1);

        /// the factory uses the msg.sender for creating its salt, so there is
        /// no way to front-run the timelock creation
        walletInstance.timelock = Timelock(
            payable(
                TimelockFactory(timelockFactory).createTimelock(
                    address(walletInstance.safe), instance.timelockParams
                )
            )
        );

        require(
            walletInstance.timelock.hasRole(
                walletInstance.timelock.HOT_SIGNER_ROLE(), msg.sender
            ),
            "InstanceDeployer: sender must be hot signer"
        );

        walletInstance.timelock.initialize(
            instance.timelockParams.contractAddresses,
            instance.timelockParams.selectors,
            instance.timelockParams.startIndexes,
            instance.timelockParams.endIndexes,
            instance.timelockParams.datas
        );

        /// checks that contracts successfully deployed
        assert(address(walletInstance.timelock).code.length != 0);
        assert(address(walletInstance.safe).code.length != 0);

        /// 1. setGuard
        /// 2. enable timelock as a module in the safe
        IMulticall3.Call3[] memory calls3 = new IMulticall3.Call3[](
            2 + instance.recoverySpells.length + instance.owners.length
        );
        {
            uint256 index = 0;

            for (uint256 i = 0; i < calls3.length; i++) {
                calls3[i].target = address(walletInstance.safe);
                calls3[i].allowFailure = false;
            }

            calls3[index++].callData =
                abi.encodeWithSelector(GuardManager.setGuard.selector, guard);

            /// add the timelock as a module to the safe
            /// this enables the timelock to execute calls + delegate calls through
            /// the safe
            calls3[index++].callData = abi.encodeWithSelector(
                ModuleManager.enableModule.selector,
                address(walletInstance.timelock)
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
                    ModuleManager.enableModule.selector,
                    instance.recoverySpells[i]
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

            /// if there is only one owner, the threshold is set to 1
            /// if there are more than one owner, add the final owner with the
            /// updated threshold
            if (instance.owners.length > 1) {
                /// add final owner with the updated threshold
                /// if threshold is greater than the number of owners, that
                /// will be caught in the addOwnerWithThreshold function with
                /// error "GS201"
                calls3[index++].callData = abi.encodeWithSelector(
                    OwnerManager.addOwnerWithThreshold.selector,
                    instance.owners[instance.owners.length - 1],
                    instance.threshold
                );
            }

            /// ensure that the number of calls is equal to the index
            /// this is a safety check and should never be false
            assert(calls3.length == index);
        }

        bytes memory signature;
        /// craft the signature singing off on all of the multicall
        /// operations
        {
            bytes32 r = bytes32(uint256(uint160(address(this))));
            uint8 v = 1;

            assembly ("memory-safe") {
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

                /// no need to store s, this should be 0 bytes

                /// store v at offset 96 to 97 in the allocated pointer
                mstore8(add(ptr, 0x60), v)

                /// Point the signature data to the correct memory location
                signature := ptr
            }
        }

        require(
            Safe(payable(walletInstance.safe)).execTransaction(
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
            address(walletInstance.safe),
            address(walletInstance.timelock),
            msg.sender,
            block.timestamp
        );
    }
}
