// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {MockSafe} from "test/mock/MockSafe.sol";
import {RecoverySpell} from "@src/RecoverySpell.sol";
import {RecoveryFactory} from "@src/RecoveryFactory.sol";

contract RecoverySpellUnitTest is Test {
    RecoveryFactory recoveryFactory;
    uint256 public recoveryDelay = 1 days;
    MockSafe safe;

    /// @notice event emitted when the recovery is executed
    event SafeRecovered(uint256 indexed time);

    function setUp() public {
        vm.warp(1000);

        address[] memory owners = new address[](5);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);
        owners[3] = address(0x4);
        owners[4] = address(0x5);

        safe = new MockSafe();
        safe.setOwners(owners);
        recoveryFactory = new RecoveryFactory();
    }

    function testDeployTwiceSameParamsFails(
        bytes32 salt,
        uint8 ownerLength,
        address safeAddress,
        uint256 threshold,
        uint256 delay
    ) public {
        ownerLength = uint8(_bound(ownerLength, 1, 10));
        threshold = _bound(threshold, 1, ownerLength);
        delay = _bound(delay, 1 days, 20 days);

        address[] memory owners = new address[](ownerLength);
        for (uint8 i = 0; i < ownerLength; i++) {
            owners[i] = address(uint160(i));
        }

        RecoverySpell recovery1 = recoveryFactory.createRecoverySpell(
            salt, owners, safeAddress, threshold, delay
        );

        vm.expectRevert();
        RecoverySpell recovery2 = recoveryFactory.createRecoverySpell(
            salt, owners, safeAddress, threshold, delay
        );

        assertEq(
            address(
                recoveryFactory.calculateAddress(
                    salt, owners, safeAddress, threshold, delay
                )
            ),
            address(recovery1),
            "RecoverySpell addresses should be the same"
        );

        assertEq(
            address(0),
            address(recovery2),
            "RecoverySpell addresses should be the same"
        );
    }

    function testViewFunctionFailsThresholdGtOwners() public {
        vm.expectRevert("RecoverySpell: Threshold must be lte number of owners");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), address(0), 2, 1
        );
    }

    function testViewFunctionFailsThresholdEqZero() public {
        vm.expectRevert("RecoverySpell: Threshold must be gt 0");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), address(0), 0, 1
        );
    }

    function testViewFunctionFailsDaysOutOfBand() public {
        vm.expectRevert("RecoverySpell: Delay must be lte 20 days");
        recoveryFactory.calculateAddress(
            bytes32(0), new address[](1), address(0), 1, 20 days + 1
        );
    }

    function testCreateFunctionFailsThresholdGtOwners() public {
        vm.expectRevert("RecoverySpell: Threshold must be lte number of owners");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), address(0), 2, 1
        );
    }

    function testCreateFunctionFailsThresholdEqZero() public {
        vm.expectRevert("RecoverySpell: Threshold must be gt 0");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), address(0), 0, 1
        );
    }

    function testCreateFunctionFailsDaysOutOfBand() public {
        vm.expectRevert("RecoverySpell: Delay must be lte 20 days");
        recoveryFactory.createRecoverySpell(
            bytes32(0), new address[](1), address(0), 1, 20 days + 1
        );
    }

    function testParamSubstitutionSaltChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safeAddress = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                bytes32(0), owners, safeAddress, threshold, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionOwnerChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safeAddress = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay
            )
        );

        owners[2] = address(0x4);
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionSafeChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safeAddress = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, address(0x4), threshold, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionThresholdChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safeAddress = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold + 1, delay
            )
        );
        address thirdAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold - 1, delay
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
        assertNotEq(
            secondAddress, thirdAddress, "addresses should not be the same"
        );
        assertNotEq(
            firstAddress, thirdAddress, "addresses should not be the same"
        );
    }

    function testParamSubstitutionDelayChangesAddress() public view {
        bytes32 salt = bytes32(uint256(1));

        address[] memory owners = new address[](3);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);

        address safeAddress = address(0x3);
        uint256 threshold = 2;
        uint256 delay = 2 days;

        address firstAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay
            )
        );
        address secondAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay + 1
            )
        );
        address thirdAddress = address(
            recoveryFactory.calculateAddress(
                salt, owners, safeAddress, threshold, delay - 1
            )
        );

        assertNotEq(
            firstAddress, secondAddress, "addresses should not be the same"
        );
        assertNotEq(
            secondAddress, thirdAddress, "addresses should not be the same"
        );
        assertNotEq(
            firstAddress, thirdAddress, "addresses should not be the same"
        );
    }

    /// recovery tests

    function testInitiateRecoverySucceedsOwner()
        public
        returns (RecoverySpell recovery)
    {
        address[] memory owners = new address[](4);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);
        owners[3] = address(0x4);

        recovery = new RecoverySpell(owners, address(safe), 2, recoveryDelay);

        vm.prank(owners[0]);
        recovery.initiateRecovery();

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );
    }

    function testInitiateRecoveryFailsRecoveryInitiated() public {
        RecoverySpell recovery = testInitiateRecoverySucceedsOwner();

        vm.expectRevert("RecoverySpell: Recovery already initiated");
        recovery.initiateRecovery();
    }

    function testInitiateRecoveryFailsNotOwner() public {
        RecoverySpell recovery =
            new RecoverySpell(new address[](3), address(safe), 1, 4 days);

        vm.expectRevert("RecoverySpell: Sender is not an owner");
        recovery.initiateRecovery();
    }

    function testExecuteRecoveryFailsNotInitiated() public {
        RecoverySpell recovery =
            new RecoverySpell(new address[](0), address(safe), 0, 1);

        vm.expectRevert("RecoverySpell: Recovery not ready");
        recovery.executeRecovery(address(1));
    }

    function testExecuteRecoveryFailsNotPassedDelay() public {
        RecoverySpell recovery = testInitiateRecoverySucceedsOwner();

        vm.expectRevert("RecoverySpell: Recovery not ready");
        recovery.executeRecovery(address(1));
    }

    function testRecoverySucceeds() public returns (RecoverySpell recovery) {
        recovery = testInitiateRecoverySucceedsOwner();

        vm.warp(block.timestamp + recoveryDelay + 1);

        safe.setExecTransactionModuleSuccess(true);

        vm.expectEmit(true, true, true, true, address(recovery));
        emit SafeRecovered(block.timestamp);

        recovery.executeRecovery(address(1));

        assertEq(recovery.getOwners().length, 0, "Owners not removed");
        assertEq(
            recovery.recoveryInitiated(),
            type(uint256).max,
            "Recovery not reset"
        );
    }

    function testInitiateRecoveryFailsPostRecovery() public {
        RecoverySpell recovery = testRecoverySucceeds();

        vm.expectRevert("RecoverySpell: Recovery already initiated");
        recovery.initiateRecovery();
    }

    function testRecoveryFailsMulticall() public {
        RecoverySpell recovery = testInitiateRecoverySucceedsOwner();

        vm.warp(block.timestamp + recoveryDelay + 1);

        safe.setExecTransactionModuleSuccess(false);

        vm.expectRevert("RecoverySpell: Recovery failed");
        recovery.executeRecovery(address(1));
    }
}
