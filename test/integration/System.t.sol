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

import {ModuleManager} from "@safe/base/ModuleManager.sol";
import {GuardManager} from "@safe/base/GuardManager.sol";
import {SafeL2} from "@safe/SafeL2.sol";

import {Test, console} from "forge-std/Test.sol";

import {Enum} from "@safe/common/Enum.sol";
import {Timelock} from "src/Timelock.sol";
import {BytesHelper} from "src/BytesHelper.sol";
import {TimeRestricted} from "src/TimeRestricted.sol";

interface call3 {
    struct Call3 {
        // Target contract to call.
        address target;
        // If false, the entire call will revert if the call fails.
        bool allowFailure;
        // Data to call on the target contract.
        bytes callData;
    }

    struct Result {
        // True if the call succeeded, false otherwise.
        bool success;
        // Return data if the call succeeded, or revert data if the call reverted.
        bytes returnData;
    }

    /// @notice Aggregate calls, ensuring each returns success if required
    /// @param calls An array of Call3 structs
    /// @return returnData An array of Result structs
    function aggregate3(Call3[] calldata calls)
        external
        payable
        returns (Result[] memory returnData);
}

contract SystemIntegrationTest is Test {
    using BytesHelper for bytes;

    /// @notice reference to the Timelock contract
    Timelock private timelock;

    /// @notice reference to the deployed Safe contract
    SafeL2 private safe;

    /// @notice reference to the TimeRestricted contract
    TimeRestricted public restricted;

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
    uint256 public constant MINIMUM_DELAY = 1 days;

    /// @notice expiration period for a timelocked transaction in seconds
    uint256 public constant EXPIRATION_PERIOD = 5 days;

    /// @notice first private key
    uint256 public constant pk1 = 4;

    /// @notice second private key
    uint256 public constant pk2 = 2;

    /// @notice third private key
    uint256 public constant pk3 = 3;

    /// @notice address of the factory contract
    SafeProxyFactory public constant factory =
        SafeProxyFactory(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);

    /// @notice address of the logic contract
    address public logic = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;

    /// @notice address of the multicall contract
    address public multicall = 0xcA11bde05977b3631167028862bE2a173976CA11;

    /// @notice storage slot for the guard
    /// keccak256("guard_manager.guard.address")
    uint256 private constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    function setUp() public {
        // at least start at unix timestamp of 1m so that block timestamp isn't 0
        vm.warp(block.timestamp + 1_000_000);

        restricted = new TimeRestricted();

        address[] memory owners = new address[](3);
        owners[0] = vm.addr(pk1);
        owners[1] = vm.addr(pk2);
        owners[2] = vm.addr(pk3);

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

    function testSafeSetup() public view {
        (address[] memory modules,) = safe.getModulesPaginated(address(1), 10);
        assertEq(
            modules.length, 0, "incorrect modules length, none should exist"
        );

        address[] memory owners = safe.getOwners();
        assertEq(owners.length, 3, "incorrect owners length");

        assertEq(owners[0], vm.addr(pk1), "incorrect owner 1");
        assertEq(owners[1], vm.addr(pk2), "incorrect owner 2");
        assertEq(owners[2], vm.addr(pk3), "incorrect owner 3");

        assertTrue(safe.isOwner(vm.addr(pk1)), "pk1 is not an owner");
        assertTrue(safe.isOwner(vm.addr(pk2)), "pk2 is not an owner");
        assertTrue(safe.isOwner(vm.addr(pk3)), "pk3 is not an owner");

        assertEq(safe.getThreshold(), 2, "incorrect threshold");

        bytes32 fallbackHandler = vm.load(
            address(safe),
            0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5
        );
        assertEq(fallbackHandler, bytes32(0), "fallback handler is not 0");

        bytes32 guard = vm.load(
            address(safe),
            0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8
        );
        assertEq(guard, bytes32(0), "guard is not 0");

        assertEq(safe.nonce(), 0, "incorrect nonce");
    }

    function testTimelockSetup() public view {
        assertEq(timelock.safe(), address(safe), "incorrect safe address");
        assertEq(timelock.minDelay(), MINIMUM_DELAY, "incorrect min delay");
        assertEq(
            timelock.expirationPeriod(),
            EXPIRATION_PERIOD,
            "incorrect expiration period"
        );
        assertEq(timelock.pauseGuardian(), guardian, "incorrect pauser");
        assertEq(
            timelock.pauseDuration(), PAUSE_DURATION, "incorrect pause duration"
        );
    }

    ///
    /// 2. Queue and execute a transaction in the Gnosis Safe to perform the following actions:
    ///  - initialize configuration with the timelock address, and allowed time ranges and their corresponding allowed days
    ///  - add the guard to the Safe
    ///  - add the Timelock as a Safe module

    ///
    /// construction of initial setup call in this system:
    ///  1. call to SafeRestriction contract to initialize configuration
    ///  with the timelock address, and allowed time ranges and their
    ///  corresponding allowed days.
    /// 2. call to `setGuard` with the address of the time-restriction contract on the safe
    /// 3. call `enableModule` with the address of the timelock on the safe
    ///
    /// Notes:
    ///   This should be wrapped in a single call to the Safe contract.
    ///   Use multicall to execute the calls in a single transaction.
    ///
    ///
    /// construction of all calls within this system outside of setup:
    ///    safe calls timelock, timelock calls external contracts
    ///    encoding:
    ///       1. gather array of addresses, values and bytes for the calls
    ///       2. encode the array of calls to call the scheduleBatch function on the timelock
    ///       3. encode this data to call the Safe contract
    ///
    ///
    function testStepTwoInitializeContract() public {
        address[] memory calls = new address[](3);
        calls[0] = address(restricted);
        calls[1] = address(safe);
        calls[2] = address(safe);

        /// 0 values
        uint256[] memory values = new uint256[](3);

        bytes[] memory calldatas = new bytes[](3);

        {
            uint8[] memory allowedDays = new uint8[](5);
            allowedDays[0] = 1;
            allowedDays[1] = 2;
            allowedDays[2] = 3;
            allowedDays[3] = 4;
            allowedDays[4] = 5;

            TimeRestricted.TimeRange[] memory ranges =
                new TimeRestricted.TimeRange[](5);

            ranges[0] = TimeRestricted.TimeRange(10, 11);
            ranges[1] = TimeRestricted.TimeRange(10, 11);
            ranges[2] = TimeRestricted.TimeRange(12, 13);
            ranges[3] = TimeRestricted.TimeRange(10, 14);
            ranges[4] = TimeRestricted.TimeRange(11, 13);

            calldatas[0] = abi.encodeWithSelector(
                restricted.initializeConfiguration.selector,
                address(timelock),
                ranges,
                allowedDays
            );
        }

        calldatas[1] = abi.encodeWithSelector(
            GuardManager.setGuard.selector, address(restricted)
        );

        calldatas[2] = abi.encodeWithSelector(
            ModuleManager.enableModule.selector, address(timelock)
        );

        call3.Call3[] memory calls3 = new call3.Call3[](3);

        calls3[0].target = calls[0];
        calls3[0].allowFailure = false;
        calls3[0].callData = calldatas[0];

        calls3[1].target = calls[1];
        calls3[1].allowFailure = false;
        calls3[1].callData = calldatas[1];

        calls3[2].target = calls[2];
        calls3[2].allowFailure = false;
        calls3[2].callData = calldatas[2];

        bytes memory safeData =
            abi.encodeWithSelector(call3.aggregate3.selector, calls3);

        bytes memory encodedDate = safe.encodeTransactionData(
            multicall,
            0,
            safeData,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        bytes32 transactionHash = safe.getTransactionHash(
            multicall,
            0,
            safeData,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        bytes memory collatedSignatures;
        {
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, transactionHash);
            (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pk2, transactionHash);
            (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(pk3, transactionHash);

            bytes memory sig1 = abi.encodePacked(r1, s1, v1);
            bytes memory sig2 = abi.encodePacked(r2, s2, v2);
            bytes memory sig3 = abi.encodePacked(r3, s3, v3);

            collatedSignatures = abi.encodePacked(sig1, sig2, sig3);
        }

        safe.checkNSignatures(transactionHash, safeData, collatedSignatures, 3);

        safe.execTransaction(
            multicall,
            0,
            safeData,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        bytes memory guardBytes =
            SafeL2(payable(safe)).getStorageAt(GUARD_STORAGE_SLOT, 1);

        address guard = address(uint160(uint256(guardBytes.getFirstWord())));

        assertEq(guard, address(restricted), "guard is not restricted");
        assertTrue(
            safe.isModuleEnabled(address(timelock)), "timelock not a module"
        );

        assertEq(
            restricted.authorizedTimelock(address(safe)),
            address(timelock),
            "timelock not set correctly"
        );
        assertTrue(restricted.safeEnabled(address(safe)), "safe not enabled");

        uint256[] memory daysEnabled = restricted.safeDaysEnabled(address(safe));

        assertEq(
            restricted.numDaysEnabled(address(safe)),
            5,
            "incorrect days enabled length"
        );
        assertEq(daysEnabled.length, 5, "incorrect days enabled length");
        assertEq(daysEnabled[0], 1, "incorrect day 1");
        assertEq(daysEnabled[1], 2, "incorrect day 2");
        assertEq(daysEnabled[2], 3, "incorrect day 3");
        assertEq(daysEnabled[3], 4, "incorrect day 4");
        assertEq(daysEnabled[4], 5, "incorrect day 5");

        {
            (uint8 startHour, uint8 endHour) =
                restricted.dayTimeRanges(address(safe), 1);
            assertEq(startHour, 10, "incorrect start hour");
            assertEq(endHour, 11, "incorrect end hour");
        }

        {
            (uint8 startHour, uint8 endHour) =
                restricted.dayTimeRanges(address(safe), 2);
            assertEq(startHour, 10, "incorrect start hour");
            assertEq(endHour, 11, "incorrect end hour");
        }
        {
            (uint8 startHour, uint8 endHour) =
                restricted.dayTimeRanges(address(safe), 3);
            assertEq(startHour, 12, "incorrect start hour");
            assertEq(endHour, 13, "incorrect end hour");
        }
        {
            (uint8 startHour, uint8 endHour) =
                restricted.dayTimeRanges(address(safe), 4);
            assertEq(startHour, 10, "incorrect start hour");
            assertEq(endHour, 14, "incorrect end hour");
        }
        {
            (uint8 startHour, uint8 endHour) =
                restricted.dayTimeRanges(address(safe), 5);
            assertEq(startHour, 11, "incorrect start hour");
            assertEq(endHour, 13, "incorrect end hour");
        }
    }
}
