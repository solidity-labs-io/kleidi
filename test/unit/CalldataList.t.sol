// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

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
import {MockLending} from "test/mock/MockLending.sol";

contract CalldataListUnitTest is Test {
    /// @notice reference to the Timelock contract
    Timelock private timelock;

    /// @notice reference to the MockSafe contract
    MockSafe private safe;

    /// @notice reference to the MockLending contract
    MockLending private lending;

    /// @notice the 3 hot signers that can execute whitelisted actions
    address[] public hotSigners;

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

    /// @notice addresses of the hot signers
    address public constant HOT_SIGNER_ONE = address(0x11111);
    address public constant HOT_SIGNER_TWO = address(0x22222);
    address public constant HOT_SIGNER_THREE = address(0x33333);

    function setUp() public {
        hotSigners.push(HOT_SIGNER_ONE);
        hotSigners.push(HOT_SIGNER_TWO);
        hotSigners.push(HOT_SIGNER_THREE);

        // at least start at unix timestamp of 1m so that block timestamp isn't 0
        vm.warp(block.timestamp + 1_000_000);

        safe = new MockSafe();

        lending = new MockLending();

        // Assume the necessary parameters for the constructor
        timelock = new Timelock(
            address(safe), // _safe
            MINIMUM_DELAY, // _minDelay
            EXPIRATION_PERIOD, // _expirationPeriod
            guardian, // _pauser
            PAUSE_DURATION, // _pauseDuration
            hotSigners
        );

        timelock.initialize(
            new address[](0),
            new bytes4[](0),
            new uint16[](0),
            new uint16[](0),
            new bytes[][](0),
            new bool[][](0)
        );
    }

    function testAddCalldataCheckAndRemoveCalldataCheckSucceeds() public {
        address[] memory targets = new address[](1);
        targets[0] = address(timelock);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 12;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 32;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata = new bytes[](1);
        checkedCalldata[0] = "";
        checkedCalldatas[0] = checkedCalldata;
        checkedCalldatas[1] = checkedCalldata;

        bool[][] memory isSelfAddressChecks = new bool[][](2);
        bool[] memory isSelfAddressCheck = new bool[](1);
        isSelfAddressCheck[0] = true;
        isSelfAddressChecks[0] = isSelfAddressCheck;
        isSelfAddressChecks[1] = isSelfAddressCheck;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas,
            isSelfAddressChecks
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            2,
            "calldata checks not added"
        );

        vm.prank(address(timelock));
        timelock.removeCalldataCheck(
            address(lending), MockLending.deposit.selector, 0
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            1,
            "calldata check not removed"
        );
        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].startIndex,
            16,
            "calldata check not removed"
        );
        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].endIndex,
            36,
            "calldata check not removed"
        );

        vm.prank(address(timelock));
        timelock.removeCalldataCheck(
            address(lending), MockLending.deposit.selector, 0
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            0,
            "calldata check not removed"
        );
    }

    function testArityMismatchAddCalldataChecks() public {
        address[] memory targets = new address[](1);
        targets[0] = address(timelock);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.withdraw.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](1);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = "";
        checkedCalldatas[0] = checkedCalldata1;

        bool[][] memory isSelfAddressChecks = new bool[][](2);
        bool[] memory isSelfAddressCheck1 = new bool[](1);
        bool[] memory isSelfAddressCheck2 = new bool[](2);
        isSelfAddressCheck1[0] = true;
        isSelfAddressCheck2[0] = true;
        isSelfAddressCheck2[1] = false;
        isSelfAddressChecks[0] = isSelfAddressCheck1;
        isSelfAddressChecks[1] = isSelfAddressCheck2;

        vm.expectRevert("CalldataList: Array lengths must be equal");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas,
            isSelfAddressChecks
        );

        checkedCalldatas = new bytes[][](2);
        checkedCalldatas[0] = checkedCalldata1;
        checkedCalldatas[1] = checkedCalldata1;

        vm.expectRevert("CalldataList: Array lengths must be equal");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas,
            isSelfAddressChecks
        );

        bytes[] memory checkedCalldata2 = new bytes[](2);
        checkedCalldata2[0] = "";
        checkedCalldata2[1] = abi.encodePacked(address(lending));
        checkedCalldatas[1] = checkedCalldata2;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas,
            isSelfAddressChecks
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            1,
            "calldata check for deposit not added"
        );
        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.withdraw.selector
            ).length,
            1,
            "calldata check for withdraw not added"
        );
    }

    function testAddCalldataCheckFailsStartIndexLt4() public {
        bytes[] memory datas = new bytes[](1);
        bool[] memory selfAddressChecks = new bool[](1);
        datas[0] = "";
        selfAddressChecks[0] = true;

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Start index must be greater than 3");
        timelock.addCalldataCheck(
            address(lending),
            MockLending.deposit.selector,
            3,
            4,
            datas,
            selfAddressChecks
        );
    }

    function testAddCalldataCheckFailsStartIndexEqEndIndexAlreadyExistingCheck()
        public
    {
        bytes[] memory datas = new bytes[](1);
        bool[] memory selfAddressChecks = new bool[](1);
        datas[0] = hex"12";
        selfAddressChecks[0] = false;

        vm.prank(address(timelock));
        timelock.addCalldataCheck(
            address(lending),
            MockLending.deposit.selector,
            4,
            5,
            datas,
            selfAddressChecks
        );

        datas[0] = "";

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Add wildcard only if no existing check");
        timelock.addCalldataCheck(
            address(lending),
            MockLending.deposit.selector,
            4,
            4,
            datas,
            selfAddressChecks
        );
    }

    function testAddCalldataCheckFailsStartIndexGtEndIndex() public {
        bytes[] memory datas = new bytes[](1);
        bool[] memory selfAddressChecks = new bool[](1);
        datas[0] = "";
        selfAddressChecks[0] = true;

        vm.prank(address(timelock));
        vm.expectRevert(
            "CalldataList: End index must be greater than start index"
        );
        timelock.addCalldataCheck(
            address(lending),
            MockLending.deposit.selector,
            4,
            3,
            datas,
            selfAddressChecks
        );
    }

    function testAddCalldataCheckFailsWhitelistedCalldataTimelock() public {
        bytes[] memory datas = new bytes[](1);
        bool[] memory selfAddressChecks = new bool[](1);
        datas[0] = "";
        selfAddressChecks[0] = true;

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Address cannot be this");
        timelock.addCalldataCheck(
            address(timelock),
            Timelock.schedule.selector,
            4,
            5,
            datas,
            selfAddressChecks
        );
    }

    function testAddCalldataCheckFailsWhitelistedCalldataSafe() public {
        bytes[] memory datas = new bytes[](1);
        bool[] memory selfAddressChecks = new bool[](1);
        datas[0] = "";
        selfAddressChecks[0] = true;

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Address cannot be safe");
        timelock.addCalldataCheck(
            address(safe),
            Timelock.schedule.selector,
            4,
            5,
            datas,
            selfAddressChecks
        );
    }

    function testAddCalldataCheckFailsStartIndexEqEndIndexNotEq4() public {
        bytes[] memory datas = new bytes[](1);
        bool[] memory selfAddressChecks = new bool[](1);
        datas[0] = "";
        selfAddressChecks[0] = false;

        vm.prank(address(timelock));
        vm.expectRevert(
            "CalldataList: End index eqauls start index only when 4"
        );
        timelock.addCalldataCheck(
            address(lending),
            MockLending.deposit.selector,
            5,
            5,
            datas,
            selfAddressChecks
        );
    }

    function testAddCalldataCheckFailsWildcardAlreadyAdded() public {
        bytes[] memory datas = new bytes[](1);
        bool[] memory selfAddressChecks = new bool[](1);
        datas[0] = "";
        selfAddressChecks[0] = false;

        vm.prank(address(timelock));
        timelock.addCalldataCheck(
            address(lending),
            MockLending.deposit.selector,
            4,
            4,
            datas,
            selfAddressChecks
        );

        datas[0] = hex"12";

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Cannot add check with wildcard");
        timelock.addCalldataCheck(
            address(lending),
            MockLending.deposit.selector,
            4,
            5,
            datas,
            selfAddressChecks
        );
    }
}
