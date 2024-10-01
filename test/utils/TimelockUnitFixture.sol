pragma solidity 0.8.25;

import {IERC1155Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {
    IERC165,
    ERC165
} from "@openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";

import {Test, console} from "forge-std/Test.sol";

import {Timelock} from "src/Timelock.sol";
import {MockSafe} from "test/mock/MockSafe.sol";
import {CallHelper} from "test/utils/CallHelper.t.sol";
import {MockLending} from "test/mock/MockLending.sol";
import {MockReentrancyExecutor} from "test/mock/MockReentrancyExecutor.sol";
import {TimelockFactory, DeploymentParams} from "src/TimelockFactory.sol";
import {
    calculateCreate2Address, Create2Params
} from "src/utils/Create2Helper.sol";
import {
    InstanceDeployer,
    NewInstance,
    SystemInstance
} from "src/InstanceDeployer.sol";
import {
    _DONE_TIMESTAMP,
    MIN_DELAY,
    MIN_DELAY as MINIMUM_DELAY,
    MAX_DELAY
} from "src/utils/Constants.sol";

contract TimelockUnitFixture is CallHelper {
    /// @notice reference to the Timelock contract
    Timelock public timelock;

    /// @notice timelock factory
    TimelockFactory public timelockFactory;

    /// @notice reference to the MockSafe contract
    MockSafe public safe;

    /// @notice the 3 hot signers that can execute whitelisted actions
    address[] public hotSigners;

    /// @notice address of the guardian that can pause in case of emergency
    address public guardian = address(0x11111);

    /// @notice duration of pause
    uint128 public constant PAUSE_DURATION = 10 days;

    /// @notice expiration period for a timelocked transaction in seconds
    uint256 public constant EXPIRATION_PERIOD = 5 days;

    /// @notice salt for timelock creation through the factory
    bytes32 public constant salt = keccak256(hex"3afe");

    /// @notice addresses of the hot signers
    address public constant HOT_SIGNER_ONE = address(0x11111);
    address public constant HOT_SIGNER_TWO = address(0x22222);
    address public constant HOT_SIGNER_THREE = address(0x33333);

    function setUp() public {
        hotSigners.push(HOT_SIGNER_ONE);
        hotSigners.push(HOT_SIGNER_TWO);
        hotSigners.push(HOT_SIGNER_THREE);

        // at least start at unix timestamp of 1m so that block timestamp isn't 0
        vm.warp(block.timestamp + 1_000_000 + EXPIRATION_PERIOD);

        safe = new MockSafe();

        timelockFactory = new TimelockFactory();

        // Assume the necessary parameters for the constructor
        timelock = Timelock(
            payable(
                timelockFactory.createTimelock(
                    address(safe), // _safe
                    DeploymentParams(
                        MINIMUM_DELAY, // _minDelay
                        EXPIRATION_PERIOD, // _expirationPeriod
                        guardian, // _pauser
                        PAUSE_DURATION, // _pauseDuration
                        hotSigners,
                        new address[](0),
                        new bytes4[](0),
                        new uint16[](0),
                        new uint16[](0),
                        new bytes[][](0),
                        salt
                    )
                )
            )
        );

        timelock.initialize(
            new address[](0),
            new bytes4[](0),
            new uint16[](0),
            new uint16[](0),
            new bytes[][](0)
        );
    }
}
