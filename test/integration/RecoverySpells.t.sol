pragma solidity 0.8.25;

import {ECDSA} from
    "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import "test/utils/SystemIntegrationFixture.sol";

contract RecoverySpellsIntegrationTest is SystemIntegrationFixture {
    using BytesHelper for bytes;

    function testCreateAddAndUseCounterfactualRecoverySpellRecoveryThresholdTwo(
    ) public {
        assertTrue(
            safe.isModuleEnabled(address(timelock)), "timelock not a module"
        );
        assertTrue(
            safe.isModuleEnabled(recoverySpellAddress),
            "recovery spell not a module"
        );

        /// create spell
        assertEq(
            address(
                recoveryFactory.createRecoverySpell(
                    recoverySalt,
                    recoveryOwners,
                    address(safe),
                    recoveryThreshold,
                    RECOVERY_THRESHOLD_OWNERS,
                    recoveryDelay
                )
            ),
            recoverySpellAddress,
            "recovery spell address mismatch"
        );

        RecoverySpell spell = RecoverySpell(recoverySpellAddress);
        assertEq(spell.delay(), recoveryDelay, "delay mismatch");

        vm.warp(spell.delay() + block.timestamp + 1);

        /// sign recovery transaction
        bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
        bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
        uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

        bytes32 digest = spell.getDigest();

        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
        }

        vm.expectEmit(true, true, true, true, address(spell));
        emit SafeRecovered(block.timestamp);

        /// execute recovery transaction
        spell.executeRecovery(address(1), v, r, s);

        assertFalse(
            safe.isModuleEnabled(recoverySpellAddress),
            "recovery spell should be removed as a module after execution"
        );

        for (uint256 i = 0; i < owners.length; i++) {
            assertFalse(
                safe.isOwner(owners[i]),
                "owner should be removed after recovery"
            );
        }

        for (uint256 i = 0; i < owners.length; i++) {
            assertTrue(
                safe.isOwner(recoveryOwners[i]),
                "recovery owners should be added after recovery"
            );
        }

        assertEq(spell.getOwners().length, 0, "owners should be empty");
        assertEq(
            spell.recoveryInitiated(),
            type(uint256).max,
            "recovery initiated should be uint max"
        );

        assertEq(safe.getThreshold(), recoveryThreshold, "threshold incorrect");
    }

    function testRecoverySpellRotatesAllSigners()
        public
        returns (RecoverySpell recovery)
    {
        recovery = recoveryFactory.createRecoverySpell(
            recoverySalt,
            recoveryOwners,
            address(safe),
            recoveryThreshold,
            RECOVERY_THRESHOLD_OWNERS,
            recoveryDelay
        );

        assertEq(
            recoverySpellAddress,
            address(recovery),
            "recovery spell address incorrect"
        );
        assertTrue(
            address(recovery).code.length != 0, "recovery spell not created"
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "recovery not initiated"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        /// sign recovery transaction
        bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
        bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
        uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

        bytes32 digest = recovery.getDigest();

        for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
            (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
        }

        vm.expectEmit(true, true, true, true, address(recovery));
        emit SafeRecovered(block.timestamp);

        /// execute recovery transaction
        recovery.executeRecovery(address(1), v, r, s);

        assertFalse(
            safe.isModuleEnabled(recoverySpellAddress),
            "recovery spell should be removed after execution"
        );

        for (uint256 i = 0; i < owners.length; i++) {
            assertFalse(
                safe.isOwner(owners[i]),
                "owner should be removed after recovery"
            );
        }

        for (uint256 i = 0; i < recoveryOwners.length; i++) {
            assertTrue(
                safe.isOwner(recoveryOwners[i]),
                "recovery owner should be an owner"
            );
        }

        assertEq(recovery.getOwners().length, 0, "owners should be empty");
        assertEq(
            recovery.recoveryInitiated(),
            type(uint256).max,
            "recovery initiated should be uint max"
        );

        assertEq(safe.getThreshold(), recoveryThreshold, "threshold incorrect");
    }

    function testRecoverySpellRecoverFailsNotEnoughSignatures() public {
        uint256 recoveryThresholdOwners = 2;
        recoverySpellAddress = recoveryFactory.calculateAddress(
            recoverySalt,
            recoveryOwners,
            address(safe),
            recoveryThreshold,
            recoveryThresholdOwners,
            recoveryDelay
        );

        RecoverySpell recovery = recoveryFactory.createRecoverySpell(
            recoverySalt,
            recoveryOwners,
            address(safe),
            recoveryThreshold,
            recoveryThresholdOwners,
            recoveryDelay
        );

        vm.warp(block.timestamp + recoveryDelay - 1);

        vm.expectRevert("RecoverySpell: Recovery not ready");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );

        /// now timestamp exactly at recovery delay
        vm.warp(block.timestamp + 1);
        vm.expectRevert("RecoverySpell: Recovery not ready");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );

        /// now timestamp is exactly 1 second past recovery delay and recovery can commence
        vm.warp(block.timestamp + 1);

        vm.expectRevert("RecoverySpell: Not enough signatures");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );

        vm.expectRevert("RecoverySpell: Invalid signature parameters");
        recovery.executeRecovery(
            address(1), new uint8[](1), new bytes32[](0), new bytes32[](0)
        );

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

        v[0] += 2;
        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        recovery.executeRecovery(address(1), v, r, s);
    }

    function testExecuteRecoveryPostRecoveryFails() public {
        RecoverySpell recovery =
            testRecoverySpellNoSignersNeededRotatesSafeSigners();

        vm.expectRevert("RecoverySpell: Already recovered");
        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );
    }

    function testAddRecoverySpellNoSignersNeeded()
        public
        returns (RecoverySpell recovery)
    {
        uint256 recoveryThresholdOwners = 0;
        recovery = RecoverySpell(
            recoveryFactory.calculateAddress(
                recoverySalt,
                recoveryOwners,
                address(safe),
                recoveryThreshold,
                recoveryThresholdOwners,
                recoveryDelay
            )
        );

        assertTrue(address(recovery).code.length == 0, "recovery spell created");

        /// timelock calls multisig, multisig calls multisig

        bytes memory calldatas = abi.encodeWithSelector(
            ModuleManager.execTransactionFromModule.selector,
            address(safe),
            0,
            abi.encodeWithSelector(
                ModuleManager.enableModule.selector, address(recovery)
            ),
            Enum.Operation.Call
        );
        bytes memory innerCalldatas = abi.encodeWithSelector(
            Timelock.schedule.selector,
            address(safe),
            0,
            calldatas,
            /// salt
            bytes32(0),
            timelock.minDelay()
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(timelock),
            0,
            innerCalldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        bytes memory collatedSignatures =
            signTxAllOwners(transactionHash, pk1, pk2, pk3);

        safe.checkNSignatures(
            transactionHash, innerCalldatas, collatedSignatures, 3
        );

        safe.execTransaction(
            address(timelock),
            0,
            innerCalldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        vm.warp(block.timestamp + timelock.minDelay());

        timelock.execute(address(safe), 0, calldatas, bytes32(0));

        assertTrue(
            safe.isModuleEnabled(recoverySpellAddress),
            "recovery spell should be removed after execution"
        );
        assertEq(
            timelock.getAllProposals().length, 0, "proposal should be removed"
        );
    }

    function testRecoverySpellNoSignersNeededRotatesSafeSigners()
        public
        returns (RecoverySpell)
    {
        RecoverySpell recovery = testAddRecoverySpellNoSignersNeeded();

        RecoverySpell createdRecovery = recoveryFactory.createRecoverySpell(
            recoverySalt,
            recoveryOwners,
            address(safe),
            recoveryThreshold,
            0,
            recoveryDelay
        );

        assertEq(
            address(createdRecovery),
            address(recovery),
            "expected recovery address not correct"
        );

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "recovery not initiated"
        );

        vm.warp(block.timestamp + recoveryDelay + 1);

        recovery.executeRecovery(
            address(1), new uint8[](0), new bytes32[](0), new bytes32[](0)
        );

        assertEq(safe.getThreshold(), recoveryThreshold, "quorum not updated");
        assertEq(
            safe.getOwners().length,
            recoveryOwners.length,
            "signer list not rotated"
        );

        for (uint256 i = 0; i < recoveryOwners.length; i++) {
            assertTrue(
                safe.isOwner(recoveryOwners[i]),
                "recovery owner should be an owner"
            );
        }

        return recovery;
    }
}
