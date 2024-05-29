// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

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
import {SafeL2} from "@safe/SafeL2.sol";
import {Enum} from "@safe/common/Enum.sol";
import {
    IMorpho,
    Position,
    IMorphoBase,
    MarketParams
} from "src/interface/IMorpho.sol";

import {Test, stdError} from "forge-std/Test.sol";

import {Timelock} from "src/Timelock.sol";
import {SigHelper} from "test/utils/SigHelper.sol";
import {BytesHelper} from "src/BytesHelper.sol";
import {RecoverySpell} from "src/RecoverySpell.sol";
import {TimeRestricted} from "src/TimeRestricted.sol";
import {RecoverySpellFactory} from "src/RecoverySpellFactory.sol";

contract SystemIntegrationFixture is Test, SigHelper {
    using BytesHelper for bytes;

    /// @notice addresses object
    Addresses public addresses;

    /// @notice reference to the Timelock contract
    Timelock public timelock;

    /// @notice reference to the deployed Safe contract
    SafeL2 public safe;

    /// @notice reference to the TimeRestricted contract
    TimeRestricted public restricted;

    /// @notice reference to the RecoverySpellFactory contract
    RecoverySpellFactory public recoveryFactory;

    /// @notice empty for now, will change once tests progress
    address[] public contractAddresses;

    /// @notice empty for now, will change once tests progress
    bytes4[] public selector;

    /// @notice empty for now, will change once tests progress
    uint16[] public startIndex;

    /// @notice empty for now, will change once tests progress
    uint16[] public endIndex;

    /// @notice empty for now, will change once tests progress
    bytes[] public data;

    /// @notice address of the guardian that can pause and break glass in case of emergency
    address public guardian = address(0x11111);

    /// @notice duration of pause once glass is broken in seconds
    uint128 public constant PAUSE_DURATION = 10 days;

    /// @notice minimum delay for a timelocked transaction in seconds
    uint256 public constant MINIMUM_DELAY = 2 days;

    /// @notice expiration period for a timelocked transaction in seconds
    uint256 public constant EXPIRATION_PERIOD = 5 days;

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

    /// @notice morpho blue irm contract
    address public irm;

    /// @notice morpho blue oracle contract
    address public oracle;

    /// @notice the multicall contract
    address public multicall;

    /// @notice time the test started
    uint256 public startTimestamp;

    /// @notice no owners need to sign to recover the safe
    uint256 public constant RECOVERY_THRESHOLD_OWNERS = 0;

    /// @notice the length of the market params in bytes
    uint256 constant MARKET_PARAMS_BYTES_LENGTH = 5 * 32;

    /// @notice event emitted when the recovery is executed
    /// @param time the time the recovery was executed
    event SafeRecovered(uint256 indexed time);

    function setUp() public {
        startTimestamp = block.timestamp;
        addresses = new Addresses("./Addresses.json");
        factory = SafeProxyFactory(addresses.getAddress("SAFE_FACTORY"));
        morphoBlue = addresses.getAddress("MORPHO_BLUE");
        logic = addresses.getAddress("SAFE_LOGIC");
        ethenaUsd = addresses.getAddress("ETHENA_USD");
        dai = addresses.getAddress("DAI");
        irm = addresses.getAddress("MORPHO_BLUE_IRM");
        oracle = addresses.getAddress("MORPHO_BLUE_ORACLE");
        multicall = addresses.getAddress("MULTICALL3");

        owners.push(vm.addr(pk1));
        owners.push(vm.addr(pk2));
        owners.push(vm.addr(pk3));

        recoveryPrivateKeys.push(10);
        recoveryPrivateKeys.push(11);
        recoveryPrivateKeys.push(12);
        recoveryPrivateKeys.push(13);
        recoveryPrivateKeys.push(14);

        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            recoveryOwners.push(vm.addr(recoveryPrivateKeys[i]));
        }

        restricted = new TimeRestricted();
        recoveryFactory = new RecoverySpellFactory();

        bytes memory initdata = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            2,
            address(0),
            "",
            address(0),
            address(0),
            0,
            address(0)
        );

        safe = SafeL2(
            payable(address(factory.createProxyWithNonce(logic, initdata, 0)))
        );

        recoverySpellAddress = recoveryFactory.calculateAddress(
            recoverySalt,
            recoveryOwners,
            address(safe),
            recoveryThreshold,
            RECOVERY_THRESHOLD_OWNERS,
            recoveryDelay
        );

        // Assume the necessary parameters for the constructor
        timelock = new Timelock(
            address(safe), // _safe
            MINIMUM_DELAY, // _minDelay
            EXPIRATION_PERIOD, // _expirationPeriod
            guardian, // _pauser
            PAUSE_DURATION, // _pauseDuration
            contractAddresses, // contractAddresses
            selector, // selector
            startIndex, // startIndex
            endIndex, // endIndex
            data // data
        );
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
