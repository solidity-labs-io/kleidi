pragma solidity 0.8.25;

import {IERC1155Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {IERC721Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {
    IERC165,
    ERC165
} from "@openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {FallbackManager} from "@safe/base/FallbackManager.sol";
import {ModuleManager} from "@safe/base/ModuleManager.sol";
import {GuardManager} from "@safe/base/GuardManager.sol";
import {OwnerManager} from "@safe/base/OwnerManager.sol";
import {IMulticall3} from "@interface/IMulticall3.sol";
import {Addresses} from "@forge-proposal-simulator/addresses/Addresses.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {SafeL2} from "@safe/SafeL2.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";
import {
    IMorpho,
    Position,
    IMorphoBase,
    MarketParams
} from "src/interface/IMorpho.sol";

import {Test, stdError, console} from "forge-std/Test.sol";

import "src/utils/Constants.sol";

import {Guard} from "src/Guard.sol";
import {Timelock} from "src/Timelock.sol";
import {BytesHelper} from "src/BytesHelper.sol";
import {SigHelper} from "test/utils/SigHelper.sol";
import {RecoverySpell} from "src/RecoverySpell.sol";
import {SystemDeploy} from "src/deploy/SystemDeploy.s.sol";
import {RecoverySpellFactory} from "src/RecoverySpellFactory.sol";
import {AddressCalculation} from "src/views/AddressCalculation.sol";
import {TimelockFactory, DeploymentParams} from "src/TimelockFactory.sol";
import {
    InstanceDeployer,
    NewInstance,
    SystemInstance
} from "src/InstanceDeployer.sol";

contract SystemIntegrationFixture is Test, SigHelper, SystemDeploy {
    using BytesHelper for bytes;

    /// @notice reference to the Timelock contract
    Timelock public timelock;

    /// @notice reference to the deployed Safe contract
    SafeL2 public safe;

    /// @notice reference to the Guard contract
    Guard public guard;

    /// @notice reference to the instance deployer
    InstanceDeployer public deployer;

    /// @notice reference to the AddressCalculation contract
    AddressCalculation public addressCalculation;

    /// @notice reference to the RecoverySpellFactory contract
    RecoverySpellFactory public recoveryFactory;

    /// @notice reference to the TimelockFactory contract
    TimelockFactory public timelockFactory;

    /// @notice the 3 hot signers that can execute whitelisted actions
    address[] public hotSigners;

    /// @notice address of the guardian that can pause in case of emergency
    address public guardian = address(0x11111);

    /// @notice duration of pause
    uint128 public constant PAUSE_DURATION = 10 days;

    /// @notice minimum delay for a timelocked transaction in seconds
    uint256 public constant MINIMUM_DELAY = 2 days;

    /// @notice expiration period for a timelocked transaction in seconds
    uint256 public constant EXPIRATION_PERIOD = 5 days;

    /// @notice number of signatures required on the gnosis safe
    uint256 public constant QUORUM = 2;

    /// @notice first public key
    uint256 public constant pk1 = 4;

    /// @notice second public key
    uint256 public constant pk2 = 2;

    /// @notice third public key
    uint256 public constant pk3 = 3;

    /// @notice address of the factory contract
    SafeProxyFactory public factory;

    /// @notice liquidation loan to value ratio
    uint256 public constant lltv = 915000000000000000;

    /// @notice storage slot for the guard
    /// keccak256("guard_manager.guard.address")
    uint256 public constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @notice current owners
    address[] public owners;

    /// @notice 5 backup owners for the safe
    uint256[] public recoveryPrivateKeys;

    /// @notice 5 backup owners for the safe
    address[] public recoveryOwners;

    /// @notice backup threshold
    uint256 public constant recoveryThreshold = 3;

    /// @notice recovery delay time
    uint256 public constant recoveryDelay = 1 days;

    /// @notice salt for the recovery spell
    bytes32 public recoverySalt =
        0x00000000000000001234567890abcdef00000000000000001234567890abcdef;

    /// @notice address of the recovery spell contract
    address public recoverySpellAddress;

    /// @notice address of the morpho blue contract
    address public morphoBlue;

    /// @notice logic contract for the safe
    address public logic;

    /// @notice ethena USD contract
    address public ethenaUsd;

    /// @notice DAI contract
    address public dai;

    /// @notice WBTC contract
    address public wbtc;

    /// @notice WETH contract
    address public weth;

    /// @notice cDAI contract
    address public cDai;

    /// @notice cEther contract
    address public cEther;

    /// @notice morpho blue irm contract
    address public irm;

    /// @notice morpho blue oracle contract USDe Dai
    address public oracleEusdDai;

    /// @notice morpho blue oracle contract WBTC WETH
    address public oracleWbtcdWeth;

    /// @notice the multicall contract
    address public multicall;

    /// @notice time the test started
    uint256 public startTimestamp;

    /// @notice 2 owners need to sign to recover the safe
    uint256 public constant RECOVERY_THRESHOLD_OWNERS = 2;

    /// @notice the length of the market params in bytes
    uint256 constant MARKET_PARAMS_BYTES_LENGTH = 5 * 32;

    /// @notice addresses of the hot signers
    address public constant HOT_SIGNER_ONE = address(0x11111);
    address public constant HOT_SIGNER_TWO = address(0x22222);
    address public constant HOT_SIGNER_THREE = address(0x33333);

    /// @notice event emitted when the recovery is executed
    /// @param time the time the recovery was executed
    event SafeRecovered(uint256 indexed time);

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

    function setUp() public {
        hotSigners.push(HOT_SIGNER_ONE);
        hotSigners.push(HOT_SIGNER_TWO);
        hotSigners.push(HOT_SIGNER_THREE);

        startTimestamp = block.timestamp;

        /// set addresses object in msig proposal
        uint256[] memory chainIds = new uint256[](3);
        chainIds[0] = 1;
        chainIds[1] = 8453;
        chainIds[2] = 84532;
        addresses = new Addresses("./addresses", chainIds);

        deploy();

        factory = SafeProxyFactory(addresses.getAddress("SAFE_FACTORY"));
        morphoBlue = addresses.getAddress("MORPHO_BLUE");
        logic = addresses.getAddress("SAFE_LOGIC");
        ethenaUsd = addresses.getAddress("ETHENA_USD");
        dai = addresses.getAddress("DAI");
        wbtc = addresses.getAddress("WBTC");
        weth = addresses.getAddress("WETH");
        irm = addresses.getAddress("MORPHO_BLUE_IRM");
        oracleEusdDai = addresses.getAddress("MORPHO_BLUE_EUSD_DAI_ORACLE");
        oracleWbtcdWeth = addresses.getAddress("MORPHO_BLUE_WBTC_WETH_ORACLE");
        multicall = addresses.getAddress("MULTICALL3");
        cDai = addresses.getAddress("C_DAI");
        cEther = addresses.getAddress("C_ETHER");

        owners.push(vm.addr(pk1));
        owners.push(vm.addr(pk2));
        owners.push(vm.addr(pk3));

        vm.label(owners[0], "Owner 1");
        vm.label(owners[1], "Owner 2");
        vm.label(owners[2], "Owner 3");

        recoveryPrivateKeys.push(10);
        recoveryPrivateKeys.push(11);
        recoveryPrivateKeys.push(12);
        recoveryPrivateKeys.push(13);
        recoveryPrivateKeys.push(14);

        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            recoveryOwners.push(vm.addr(recoveryPrivateKeys[i]));
        }

        guard = Guard(addresses.getAddress("GUARD"));
        recoveryFactory =
            RecoverySpellFactory(addresses.getAddress("RECOVERY_SPELL_FACTORY"));
        deployer = InstanceDeployer(addresses.getAddress("INSTANCE_DEPLOYER"));
        timelockFactory =
            TimelockFactory(addresses.getAddress("TIMELOCK_FACTORY"));
        addressCalculation =
            AddressCalculation(addresses.getAddress("ADDRESS_CALCULATION"));

        NewInstance memory instance = NewInstance(
            owners,
            QUORUM,
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

        SystemInstance memory calculatedInstance =
            addressCalculation.calculateAddress(instance);

        recoverySpellAddress = recoveryFactory.calculateAddress(
            recoverySalt,
            recoveryOwners,
            address(calculatedInstance.safe),
            recoveryThreshold,
            RECOVERY_THRESHOLD_OWNERS,
            recoveryDelay
        );

        address[] memory recoverySpells = new address[](1);
        recoverySpells[0] = recoverySpellAddress;
        instance.recoverySpells = recoverySpells;

        vm.prank(HOT_SIGNER_ONE);
        SystemInstance memory walletInstance =
            deployer.createSystemInstance(instance);

        safe = SafeL2(payable(walletInstance.safe));
        timelock = Timelock(payable(walletInstance.timelock));

        vm.label(address(timelock), "Timelock");
        vm.label(address(safe), "Safe");
    }

    /// MORPHO Helper function

    /// @notice Returns the id of the market `marketParams`.
    function id(MarketParams memory marketParams)
        internal
        pure
        returns (bytes32 marketParamsId)
    {
        assembly ("memory-safe") {
            marketParamsId :=
                keccak256(marketParams, MARKET_PARAMS_BYTES_LENGTH)
        }
    }
}
