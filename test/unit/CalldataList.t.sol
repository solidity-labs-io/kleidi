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
import {MockLending} from "test/mock/MockLending.sol";

contract CalldataListUnitTest is Test {
    struct CheckData {
        address[] targets;
        bytes4[] selectors;
        uint16[] startIndexes;
        uint16[] endIndexes;
        bytes[][] calldatas;
    }

    /// @notice struct used to fuzz values for testAddAndRemoveCalldataFuzzy
    /// target: the contract address to be whitelisted
    /// selector: the function signature to be whitelisted on target contract
    /// calldataLength: length of calldata for all the checks for target and selector
    /// seedCalldata: seed calldata used to generate multiple calldatas for different AND and OR checks
    struct CheckDataFuzzParams {
        address target;
        bytes4 selector;
        uint16 calldataLength;
        bytes seedCalldata;
    }

    /// @notice reference to the Timelock contract
    Timelock private timelock;

    /// @notice reference to the MockSafe contract
    MockSafe private safe;

    /// @notice reference to the MockLending contract
    MockLending private lending;

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

    /// @notice addresses of the hot signers
    address public constant HOT_SIGNER_ONE = address(0x11111);
    address public constant HOT_SIGNER_TWO = address(0x22222);
    address public constant HOT_SIGNER_THREE = address(0x33333);

    /// @notice nonce for generating random numbers
    uint256 internal _nonce = 0;

    /// @notice mapping used in testAddAndRemoveCalldataFuzzy to store
    /// total number of AND checks for a contract selector pair
    mapping(address target => mapping(bytes4 selector => uint256 count)) private
        totalChecks;

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
            new bytes[][](0)
        );
    }

    function testSetup() public view {
        for (uint256 i = 0; i < hotSigners.length; i++) {
            assertTrue(
                timelock.hasRole(timelock.HOT_SIGNER_ROLE(), hotSigners[i]),
                "hot signer not assigned"
            );
        }
    }

    function testAddCalldataCheckAndRemoveCalldataCheckSucceeds() public {
        address[] memory targetAddresses = new address[](3);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);
        targetAddresses[2] = address(lending);

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;
        selectors[2] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](3);
        startIndexes[0] = 16;
        startIndexes[1] = 16;
        startIndexes[2] = 40;

        uint16[] memory endIndexes = new uint16[](3);
        endIndexes[0] = 36;
        endIndexes[1] = 36;
        endIndexes[2] = 60;

        bytes[][] memory checkedCalldatas = new bytes[][](3);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        bytes[] memory checkedCalldata3 = new bytes[](1);
        checkedCalldata3[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[2] = checkedCalldata3;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            2,
            "calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].dataHashes.length,
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

    function testAddCalldataCheckAndRemoveCalldataCheckDatahashSucceeds()
        public
    {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            1,
            "calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].dataHashes.length,
            2,
            "calldata checks not added"
        );

        vm.prank(address(timelock));
        timelock.removeCalldataCheckDatahash(
            address(lending),
            MockLending.deposit.selector,
            0,
            keccak256(checkedCalldata1[0])
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            1,
            "calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].dataHashes.length,
            1,
            "calldata checks not added"
        );

        vm.prank(address(timelock));
        timelock.removeCalldataCheckDatahash(
            address(lending),
            MockLending.deposit.selector,
            0,
            keccak256(checkedCalldata2[0])
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            0,
            "calldata check not removed"
        );
    }

    function testAddCalldataCheckAndRemoveCalldataCheckDatahashMultipleIndecesSucceeds(
    ) public {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 37;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 57;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            2,
            "calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].dataHashes.length,
            1,
            "first calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[1].dataHashes.length,
            1,
            "second calldata checks not added"
        );

        vm.prank(address(timelock));
        timelock.removeCalldataCheckDatahash(
            address(lending),
            MockLending.deposit.selector,
            0,
            keccak256(checkedCalldata1[0])
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            1,
            "calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].dataHashes.length,
            1,
            "calldata checks not added"
        );

        vm.prank(address(timelock));
        timelock.removeCalldataCheckDatahash(
            address(lending),
            MockLending.deposit.selector,
            0,
            keccak256(checkedCalldata2[0])
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            0,
            "calldata check not removed"
        );
    }

    function testAddCalldataCheckFailsWhenOverlap() public {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 20;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 40;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        vm.expectRevert("CalldataList: Partial check overlap");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );
    }

    function testAddCalldataCheckFailsWithDuplicateData() public {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(this));
        checkedCalldatas[1] = checkedCalldata2;

        vm.expectRevert("CalldataList: Duplicate data");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );
    }

    function testAddCalldataCheckFailsWhenTargetZeroAddress() public {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(0);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        vm.expectRevert("CalldataList: Address cannot be zero");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );
    }

    function testAddCalldataCheckFailsWhenTargetSelectorZero() public {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = "";
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        vm.expectRevert("CalldataList: Selector cannot be empty");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );
    }

    function testRemoveCalldataCheckDatahashFailsForOutOfBoundIndex() public {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            1,
            "calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].dataHashes.length,
            2,
            "calldata checks not added"
        );

        vm.expectRevert("CalldataList: Calldata index out of bounds");
        vm.prank(address(timelock));
        timelock.removeCalldataCheckDatahash(
            address(lending),
            MockLending.deposit.selector,
            1,
            keccak256(checkedCalldata1[0])
        );
    }

    function testRemoveCalldataCheckDatahashFailsWhenDataHashNotExist()
        public
    {
        address[] memory targetAddresses = new address[](2);
        targetAddresses[0] = address(lending);
        targetAddresses[1] = address(lending);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockLending.deposit.selector;
        selectors[1] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](2);
        startIndexes[0] = 16;
        startIndexes[1] = 16;

        uint16[] memory endIndexes = new uint16[](2);
        endIndexes[0] = 36;
        endIndexes[1] = 36;

        bytes[][] memory checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata1 = new bytes[](1);
        checkedCalldata1[0] = abi.encodePacked(address(this));
        checkedCalldatas[0] = checkedCalldata1;

        bytes[] memory checkedCalldata2 = new bytes[](1);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldatas[1] = checkedCalldata2;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            ).length,
            1,
            "calldata checks not added"
        );

        assertEq(
            timelock.getCalldataChecks(
                address(lending), MockLending.deposit.selector
            )[0].dataHashes.length,
            2,
            "calldata checks not added"
        );

        vm.expectRevert("CalldataList: DataHash does not exist");
        vm.prank(address(timelock));
        timelock.removeCalldataCheckDatahash(
            address(lending),
            MockLending.deposit.selector,
            0,
            keccak256(bytes("incorrect data hash"))
        );
    }

    /// @notice fuzz test adding multiple AND and OR checks for each contract and function selector pair
    /// and removing all the checks for each pair by using removeCalldataCheck or removeCalldataCheckDatahash chosen randomly
    /// @param fuzzyCheckData fuzzed CheckDataFuzzParams struct array
    function testAddAndRemoveCalldataFuzzy(
        CheckDataFuzzParams[] memory fuzzyCheckData
    ) public {
        /// length of fuzzed contract-selector pair
        uint256 fuzzyLength;

        /// adddition of checks
        {
            fuzzyLength = fuzzyCheckData.length;

            /// assume that fuzzyCheckData is not zero length
            vm.assume(fuzzyLength > 0);

            /// bound calldata length for each pair between 4 and 32, max is 32 so that
            /// multiple calldatas can be generate from the seed calldata using generateCalldatas
            /// min is 4 so that there are is no collision in generated calldatas
            for (uint256 len = 0; len < fuzzyLength; len++) {
                fuzzyCheckData[len].calldataLength =
                    uint16(bound(fuzzyCheckData[len].calldataLength, 4, 32));
            }

            /// number of AND and OR checks for each selected pair
            uint256 checkCount = randomInRange(4, 20, true);
            /// total length of all the AND and OR checks
            uint256 length = checkCount * fuzzyLength;
            /// initial start index for first check
            uint16 currentStartIndex = 4;

            CheckData memory checkData = _initializeCheckData(length);

            /// generate checkCount number of checks for each selected pair
            for (uint256 i = 0; i < fuzzyLength; i++) {
                /// target should not be safe or timelock address or zero address
                /// selector should not be empty
                vm.assume(
                    fuzzyCheckData[i].target != address(safe)
                        && fuzzyCheckData[i].target != address(timelock)
                        && fuzzyCheckData[i].target != address(0)
                        && fuzzyCheckData[i].selector != bytes4(0)
                );

                /// generate checkCount number of checks for the selected pair
                for (uint256 j = 0; j < checkCount; j++) {
                    /// index where the new check is added
                    uint256 index = i * checkCount + j;
                    /// for all the checkCount number of checks target contract is same
                    checkData.targets[index] = fuzzyCheckData[i].target;
                    /// for all the checkCount number of checks target selector is same
                    checkData.selectors[index] = fuzzyCheckData[i].selector;
                    /// generate multiple OR data hashes corresponding to the current index
                    checkData.calldatas = generateCalldatas(
                        checkData.calldatas,
                        abi.encodePacked(fuzzyCheckData[i].seedCalldata, j),
                        fuzzyCheckData[i].calldataLength,
                        index
                    );
                    /// set start index
                    checkData.startIndexes[index] = currentStartIndex;
                    // set end index to start index + calldata length
                    checkData.endIndexes[index] = checkData.startIndexes[index]
                        + fuzzyCheckData[i].calldataLength;

                    /// keep start and end index same for the next check if j <= checkCount / 2
                    /// update start and end index if j > checkCount / 2
                    if (j > checkCount / 2) {
                        /// update start index for next check to avoid overlap
                        currentStartIndex = checkData.endIndexes[index] + 1;
                        /// AND checks count only increases if j > checkCount / 2
                        totalChecks[fuzzyCheckData[i].target][fuzzyCheckData[i]
                            .selector] += 1;
                    }
                }
            }

            vm.prank(address(timelock));
            timelock.addCalldataChecks(
                checkData.targets,
                checkData.selectors,
                checkData.startIndexes,
                checkData.endIndexes,
                checkData.calldatas
            );

            // assert calldata checks were added
            for (uint256 i = 0; i < fuzzyLength; i++) {
                uint256 finalCheckLength = timelock.getCalldataChecks(
                    fuzzyCheckData[i].target, fuzzyCheckData[i].selector
                ).length;
                /// assert added checks count is correct
                assertTrue(
                    finalCheckLength
                        == totalChecks[fuzzyCheckData[i].target][fuzzyCheckData[i]
                            .selector]
                );
            }
        }

        /// removal of checks
        {
            for (uint256 i = 0; i < fuzzyLength; i++) {
                /// get number of AND checks for the selected pair
                uint256 checksLength = timelock.getCalldataChecks(
                    fuzzyCheckData[i].target, fuzzyCheckData[i].selector
                ).length;

                uint256 index;
                /// delete all the AND checks in random order
                while (checksLength > 0) {
                    index = randomInRange(0, checksLength - 1, false);
                    /// 50% chance that removeCalldataCheck will be used to remove the complete AND check
                    /// other 50% chance that removeCalldataCheckDatahash will be used to remove all the
                    /// OR checks for the AND check, finally removing the end check
                    if (randomInRange(1, 100, true) % 2 == 0) {
                        vm.prank(address(timelock));
                        timelock.removeCalldataCheck(
                            fuzzyCheckData[i].target,
                            fuzzyCheckData[i].selector,
                            index
                        );
                    } else {
                        /// set number of OR checks for the AND check
                        uint256 dataHashesLength = timelock.getCalldataChecks(
                            fuzzyCheckData[i].target, fuzzyCheckData[i].selector
                        )[index].dataHashes.length;
                        uint256 indexDataHashes;
                        /// delete all the OR checks in random order
                        while (dataHashesLength > 0) {
                            /// current array of OR data hashes
                            bytes32[] memory dataHashes = timelock
                                .getCalldataChecks(
                                fuzzyCheckData[i].target,
                                fuzzyCheckData[i].selector
                            )[index].dataHashes;
                            /// random index that will be removed
                            indexDataHashes =
                                randomInRange(0, dataHashesLength - 1, false);
                            vm.prank(address(timelock));
                            timelock.removeCalldataCheckDatahash(
                                fuzzyCheckData[i].target,
                                fuzzyCheckData[i].selector,
                                index,
                                dataHashes[indexDataHashes]
                            );
                            dataHashesLength--;
                        }
                    }
                    checksLength--;
                }
                /// assert calldata checks removed for the selected pair
                assertEq(
                    timelock.getCalldataChecks(
                        fuzzyCheckData[i].target, fuzzyCheckData[i].selector
                    ).length,
                    0,
                    "all checks not removed"
                );
            }
        }
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

        bytes[][] memory checkedCalldatas = new bytes[][](0);

        vm.expectRevert("CalldataList: Array lengths must be equal");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        checkedCalldatas = new bytes[][](3);
        checkedCalldatas[0] = new bytes[](1);
        checkedCalldatas[1] = new bytes[](1);

        vm.expectRevert("CalldataList: Array lengths must be equal");
        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        checkedCalldatas = new bytes[][](2);
        bytes[] memory checkedCalldata2 = new bytes[](2);
        checkedCalldata2[0] = abi.encodePacked(address(timelock));
        checkedCalldata2[1] = abi.encodePacked(address(lending));
        checkedCalldatas[0] = checkedCalldata2;
        checkedCalldatas[1] = checkedCalldata2;

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
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
        datas[0] = abi.encodePacked(timelock);

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Start index must be greater than 3");
        timelock.addCalldataCheck(
            address(lending), MockLending.deposit.selector, 3, 4, datas
        );
    }

    function testAddCalldataCheckFailsStartIndexEqEndIndexAlreadyExistingCheck()
        public
    {
        bytes[] memory datas = new bytes[](1);
        datas[0] = hex"12";

        vm.prank(address(timelock));
        timelock.addCalldataCheck(
            address(lending), MockLending.deposit.selector, 4, 5, datas
        );

        datas[0] = abi.encodePacked(timelock);

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Add wildcard only if no existing check");
        timelock.addCalldataCheck(
            address(lending), MockLending.deposit.selector, 4, 4, datas
        );
    }

    function testAddCalldataCheckFailsStartIndexGtEndIndex() public {
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodePacked(timelock);

        vm.prank(address(timelock));
        vm.expectRevert(
            "CalldataList: End index must be greater than start index"
        );
        timelock.addCalldataCheck(
            address(lending), MockLending.deposit.selector, 4, 3, datas
        );
    }

    function testAddCalldataCheckFailsWhitelistedCalldataTimelock() public {
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodePacked(timelock);

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Address cannot be this");
        timelock.addCalldataCheck(
            address(timelock), Timelock.schedule.selector, 4, 5, datas
        );
    }

    function testAddCalldataCheckFailsWhitelistedCalldataSafe() public {
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodePacked(timelock);

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Address cannot be safe");
        timelock.addCalldataCheck(
            address(safe), Timelock.schedule.selector, 4, 5, datas
        );
    }

    function testAddCalldataCheckFailsStartIndexEqEndIndexNotEq4() public {
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodePacked(timelock);

        vm.prank(address(timelock));
        vm.expectRevert(
            "CalldataList: End index equals start index only when 4"
        );
        timelock.addCalldataCheck(
            address(lending), MockLending.deposit.selector, 5, 5, datas
        );
    }

    function testAddCalldataCheckFailsWildcardAlreadyAdded() public {
        bytes[] memory datas = new bytes[](0);

        vm.prank(address(timelock));
        timelock.addCalldataCheck(
            address(lending), MockLending.deposit.selector, 4, 4, datas
        );

        datas = new bytes[](1);
        datas[0] = hex"12";

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Cannot add check with wildcard");
        timelock.addCalldataCheck(
            address(lending), MockLending.deposit.selector, 4, 5, datas
        );
    }

    function testAddArbitraryCheckSucceeds() public {
        address[] memory targetAddresses = new address[](1);
        targetAddresses[0] = address(lending);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](1);
        startIndexes[0] = 4;

        uint16[] memory endIndexes = new uint16[](1);
        endIndexes[0] = 4;

        bytes[][] memory checkedCalldatas = new bytes[][](1);
        checkedCalldatas[0] = new bytes[](0);

        vm.prank(address(timelock));
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        // Check that the check is there
        timelock.checkCalldata(
            targetAddresses[0], abi.encodePacked(selectors[0])
        );

        // Remove it
        vm.prank(address(timelock));
        timelock.removeCalldataCheck(targetAddresses[0], selectors[0], 0);

        // Show that now it reverts
        vm.expectRevert("CalldataList: No calldata checks found");
        timelock.checkCalldata(
            targetAddresses[0], abi.encodePacked(selectors[0])
        );
    }

    function testAddArbitraryCheckWithCalldataFails() public {
        address[] memory targetAddresses = new address[](1);
        targetAddresses[0] = address(lending);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = MockLending.deposit.selector;

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](1);
        startIndexes[0] = 4;

        uint16[] memory endIndexes = new uint16[](1);
        endIndexes[0] = 4;

        bytes[][] memory checkedCalldatas = new bytes[][](1);
        checkedCalldatas[0] = new bytes[](1);
        checkedCalldatas[0][0] = abi.encodePacked(address(this));

        vm.prank(address(timelock));
        vm.expectRevert("CalldataList: Data must be empty");
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );

        /// Show that now it still reverts
        vm.expectRevert("CalldataList: No calldata checks found");
        timelock.checkCalldata(
            targetAddresses[0], abi.encodePacked(selectors[0])
        );
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function sliceBytes32(bytes32 data, uint256 length)
        internal
        pure
        returns (bytes memory)
    {
        require(length <= 32, "sliceBytes32: length must be <= 32");
        bytes memory slicedData = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            slicedData[i] = data[i];
        }
        return slicedData;
    }

    function generateCalldatas(
        bytes[][] memory calldatas,
        bytes memory data,
        uint256 count,
        uint256 index
    ) internal pure returns (bytes[][] memory) {
        /// length of each OR data
        uint256 calldataLength = count;
        /// number of OR datas for each check
        count = bound(count, 1, 10);

        bytes32 dataHash = keccak256(data);
        bytes[] memory singleCheckCalldata = new bytes[](count);

        /// generate count number of OR datas
        for (uint256 i = 0; i < count; i++) {
            singleCheckCalldata[i] = sliceBytes32(dataHash, calldataLength);
            dataHash = keccak256(abi.encode(dataHash));
        }
        calldatas[index] = singleCheckCalldata;
        return calldatas;
    }

    function _initializeCheckData(uint256 length)
        internal
        pure
        returns (CheckData memory)
    {
        return CheckData({
            targets: new address[](length),
            selectors: new bytes4[](length),
            startIndexes: new uint16[](length),
            endIndexes: new uint16[](length),
            calldatas: new bytes[][](length)
        });
    }

    function getNextNonce() internal returns (uint256) {
        return _nonce == type(uint256).max ? 0 : ++_nonce;
    }

    function randomInRange(uint256 min, uint256 max, bool nonZero)
        internal
        returns (uint256)
    {
        require(min <= max, "randomInRange bad inputs");
        if (max == 0 && nonZero) return 1;
        else if (max == min) return max;
        return (
            uint256(keccak256(abi.encodePacked(msg.sender, getNextNonce())))
                % (max - min + 1)
        ) + min;
    }
}
