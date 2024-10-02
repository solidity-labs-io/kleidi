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
import {MockERC721} from "test/mock/MockERC721.sol";
import {MockERC1155} from "test/mock/MockERC1155.sol";
import {MIN_DELAY as MINIMUM_DELAY} from "src/utils/Constants.sol";

contract TimelockReceivingUnitTest is Test {
    /// @notice reference to the Timelock contract
    Timelock private timelock;

    /// @notice reference to the MockSafe contract
    MockSafe private safe;

    /// @notice reference to the MockERC1155 contract
    MockERC1155 private erc1155;

    /// @notice reference to the MockERC721 contract
    MockERC721 private erc721;

    /// @notice address of the guardian that can pause in case of emergency
    address public guardian = address(0x11111);

    /// @notice duration of pause
    uint128 public constant PAUSE_DURATION = 10 days;

    /// @notice expiration period for a timelocked transaction in seconds
    uint256 public constant EXPIRATION_PERIOD = 5 days;

    function setUp() public {
        // at least start at unix timestamp of 1m so that block timestamp isn't 0
        vm.warp(block.timestamp + 1_000_000);

        safe = new MockSafe();

        erc1155 = new MockERC1155();
        erc721 = new MockERC721();

        // Assume the necessary parameters for the constructor
        timelock = new Timelock(
            address(safe), // _safe
            MINIMUM_DELAY, // _minDelay
            EXPIRATION_PERIOD, // _expirationPeriod
            guardian, // _pauser
            PAUSE_DURATION, // _pauseDuration
            new address[](0) // hotSigners
        );

        timelock.initialize(
            new address[](0), // targets
            new bytes4[](0), // selectors
            new uint16[](0), // startIndexes
            new uint16[](0), // endIndexes
            new bytes[][](0) // datas
        );
    }

    function testReceive1155Mint() public {
        erc1155.mint(address(timelock), 2, 1);

        assertEq(
            erc1155.balanceOf(address(timelock), 2),
            1,
            "id does not have correct balance"
        );
    }

    function testReceive1155BatchMint() public {
        uint256[] memory ids = new uint256[](4);
        uint256[] memory values = new uint256[](4);
        ids[0] = 0;
        ids[1] = 1;
        ids[2] = 2;
        ids[3] = 3;

        values[0] = 100_000;
        values[1] = 100_000_000;
        values[2] = 100_000_000_000;
        values[3] = 100_000_000_000_000;

        erc1155.mintBatch(address(timelock), ids, values);

        for (uint256 i = 0; i < ids.length; i++) {
            assertEq(
                erc1155.balanceOf(address(timelock), ids[i]),
                values[i],
                "id does not have correct balance"
            );
        }
    }

    function testReceive721() public {
        erc721.mint(address(timelock), 1);

        assertEq(
            erc721.ownerOf(1),
            address(timelock),
            "id does not have correct owner"
        );
    }

    function testReceive721Safe() public {
        erc721.safeMint(address(timelock), 1);

        assertEq(
            erc721.ownerOf(1),
            address(timelock),
            "id does not have correct owner"
        );
    }

    function testReceiveEth() public {
        uint256 amount = 1 ether;
        vm.deal(address(this), amount);

        address payable timelockPayable = payable(address(timelock));
        timelockPayable.transfer(amount);

        assertEq(
            address(timelock).balance,
            amount,
            "timelock does not have correct balance"
        );
    }
}
