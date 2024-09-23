pragma solidity 0.8.25;

import {ECDSA} from
    "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {Test, stdError} from "forge-std/Test.sol";

import {MockSafe} from "test/mock/MockSafe.sol";
import {RecoverySpell} from "@src/RecoverySpell.sol";

contract RecoverySpellUnitTest is Test {
    uint256 public recoveryDelay = 1 days;
    MockSafe safe;

    uint256[] public recoveryPrivateKeys;

    address[] public recoveryOwners;

    /// @notice event emitted when the recovery is executed
    event SafeRecovered(uint256 indexed time);

    function setUp() public {
        vm.warp(1000);

        recoveryPrivateKeys.push(10);
        recoveryPrivateKeys.push(20);
        recoveryPrivateKeys.push(30);
        recoveryPrivateKeys.push(40);
        recoveryPrivateKeys.push(50);

        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            recoveryOwners.push(vm.addr(recoveryPrivateKeys[i]));
        }

        safe = new MockSafe();
        safe.setOwners(recoveryOwners);
    }

    function testDomainSeparatorDifferentTwoContracts() public {
        RecoverySpell recovery1 = new RecoverySpell(
            recoveryOwners, address(safe), 2, 4, recoveryDelay
        );

        RecoverySpell recovery2 = new RecoverySpell(
            recoveryOwners, address(safe), 2, 4, recoveryDelay
        );

        assertNotEq(
            recovery1.getDigest(),
            recovery2.getDigest(),
            "Domain separator should be different"
        );
    }

    /// recovery tests

    function testInitiateRecoverySucceeds()
        public
        returns (RecoverySpell recovery)
    {
        address[] memory owners = new address[](4);
        owners[0] = address(0x1);
        owners[1] = address(0x2);
        owners[2] = address(0x3);
        owners[3] = address(0x4);

        recovery = new RecoverySpell(owners, address(safe), 2, 0, recoveryDelay);

        vm.prank(owners[0]);

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );
    }

    function testExecuteRecoveryFailsNotInitiated() public {
        RecoverySpell recovery =
            new RecoverySpell(new address[](1), address(safe), 0, 0, 1);

        vm.expectRevert("RecoverySpell: Recovery not ready");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );
    }

    function testExecuteRecoveryFailsNotPassedDelay() public {
        RecoverySpell recovery = testInitiateRecoverySucceeds();

        vm.expectRevert("RecoverySpell: Recovery not ready");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );
    }

    function testRecoveryFailsNotPassedDelay() public {
        RecoverySpell recovery = new RecoverySpell(
            recoveryOwners, address(safe), 2, 4, recoveryDelay
        );

        vm.expectRevert("RecoverySpell: Recovery not ready");
        recovery.executeRecovery(
            address(1), new uint8[](1), new bytes32[](1), new bytes32[](1)
        );
    }

    function testRecoverySucceeds() public returns (RecoverySpell recovery) {
        recovery = testInitiateRecoverySucceeds();

        vm.warp(block.timestamp + recoveryDelay + 1);

        safe.setExecTransactionModuleSuccess(true);

        vm.expectEmit(true, true, true, true, address(recovery));
        emit SafeRecovered(block.timestamp);

        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );

        assertEq(recovery.getOwners().length, 0, "Owners not removed");
        assertEq(
            recovery.recoveryInitiated(),
            type(uint256).max,
            "Recovery not reset"
        );
    }

    function testRecoverySucceedsMultipleSignatures() public {
        RecoverySpell recovery = new RecoverySpell(
            recoveryOwners, address(safe), 2, 4, recoveryDelay
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
        bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
        uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

        bytes32 digest = recovery.getDigest();
        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
        }

        safe.setExecTransactionModuleSuccess(true);

        vm.expectEmit(true, true, true, true, address(recovery));
        emit SafeRecovered(block.timestamp);

        recovery.executeRecovery(address(1), v, r, s);

        assertEq(recovery.getOwners().length, 0, "Owners not removed");
        assertEq(
            recovery.recoveryInitiated(),
            type(uint256).max,
            "Recovery not reset"
        );
    }

    function testRecoveryFailsDuplicateSignature() public {
        RecoverySpell recovery = new RecoverySpell(
            recoveryOwners, address(safe), 2, 4, recoveryDelay
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
        bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
        uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

        bytes32 digest = recovery.getDigest();
        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
        }

        /// final signature duplicate
        v[v.length - 1] = v[v.length - 2];
        r[r.length - 1] = r[r.length - 2];
        s[s.length - 1] = s[s.length - 2];

        vm.expectRevert("RecoverySpell: Invalid signature");
        recovery.executeRecovery(address(1), v, r, s);
    }

    function testRecoveryFailsInvalidSignature() public {
        RecoverySpell recovery = new RecoverySpell(
            recoveryOwners, address(safe), 2, 4, recoveryDelay
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
        bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
        uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

        bytes32 digest = recovery.getDigest();
        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
        }
        /// invalid signature
        v[v.length - 1] = v[v.length - 1] + 1;

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        recovery.executeRecovery(address(1), v, r, s);

        v[v.length - 1] = v[v.length - 1] - 1;
        bytes32 rval = r[0];
        r[0] = bytes32(uint256(21));

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        recovery.executeRecovery(address(1), v, r, s);

        v[v.length - 1] = v[v.length - 1] - 1;
        r[r.length - 1] = bytes32(uint256(21));
        r[0] = rval;

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        recovery.executeRecovery(address(1), v, r, s);
    }

    function testExecuteRecoveryFailsPostRecoverySuccess() public {
        RecoverySpell recovery = testRecoverySucceeds();

        vm.expectRevert("RecoverySpell: Already recovered");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );
    }

    function testRecoveryNoSignaturesFailsMulticall() public {
        RecoverySpell recovery = testInitiateRecoverySucceeds();

        vm.warp(block.timestamp + recoveryDelay + 1);

        safe.setExecTransactionModuleSuccess(false);

        vm.expectRevert("RecoverySpell: Recovery failed");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );
    }

    function testRecoveryWithSignaturesFailsMulticall() public {
        RecoverySpell recovery = new RecoverySpell(
            recoveryOwners, address(safe), 2, 4, recoveryDelay
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
        bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
        uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

        bytes32 digest = recovery.getDigest();
        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
        }

        safe.setExecTransactionModuleSuccess(false);

        vm.expectRevert("RecoverySpell: Recovery failed");
        recovery.executeRecovery(address(1), v, r, s);
    }

    function testRecoveryNotEnoughSignaturesFails() public {
        RecoverySpell recovery = new RecoverySpell(
            recoveryOwners, address(safe), 2, 5, recoveryDelay
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length - 1);
        bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length - 1);
        uint8[] memory v = new uint8[](recoveryPrivateKeys.length - 1);

        bytes32 digest = recovery.getDigest();
        for (uint256 i = 0; i < recoveryPrivateKeys.length - 1; i++) {
            (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
        }

        vm.expectRevert("RecoverySpell: Not enough signatures");
        recovery.executeRecovery(address(1), v, r, s);
    }

    function testRecoveryFailsSignatureLengthMismatch() public {
        RecoverySpell recovery = new RecoverySpell(
            recoveryOwners, address(safe), 2, 5, recoveryDelay
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "Recovery initiated time not stored"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        {
            bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length - 1);
            bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length - 1);
            uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

            bytes32 digest = recovery.getDigest();
            for (uint256 i = 0; i < recoveryPrivateKeys.length - 1; i++) {
                (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
            }

            vm.expectRevert("RecoverySpell: Invalid signature parameters");
            recovery.executeRecovery(address(1), v, r, s);
        }

        {
            bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length - 1);
            bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
            uint8[] memory v = new uint8[](recoveryPrivateKeys.length - 1);

            bytes32 digest = recovery.getDigest();
            for (uint256 i = 0; i < recoveryPrivateKeys.length - 1; i++) {
                (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
            }

            vm.expectRevert("RecoverySpell: Invalid signature parameters");
            recovery.executeRecovery(address(1), v, r, s);
        }
        {
            bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
            bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length - 1);
            uint8[] memory v = new uint8[](recoveryPrivateKeys.length - 1);

            bytes32 digest = recovery.getDigest();
            for (uint256 i = 0; i < recoveryPrivateKeys.length - 1; i++) {
                (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
            }

            vm.expectRevert("RecoverySpell: Invalid signature parameters");
            recovery.executeRecovery(address(1), v, r, s);
        }
    }
}
