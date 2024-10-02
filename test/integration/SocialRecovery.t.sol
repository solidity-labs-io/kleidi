pragma solidity 0.8.25;

import "test/utils/SystemIntegrationFixture.sol";

import {generateCalldatas} from "test/utils/NestedArrayHelper.sol";

contract SocialRecoveryIntegrationTest is SystemIntegrationFixture {
    using BytesHelper for bytes;

    struct RecoveryFuzz {
        uint8 currentOwnerLength;
        uint8 recoveryOwnerLength;
        uint8 recoveryThreshold;
        uint8 threshold;
    }

    function testRecoverySpellFuzz(RecoveryFuzz memory recoveryFuzz) public {
        recoveryFuzz.currentOwnerLength = uint8(
            bound(
                uint256(recoveryFuzz.currentOwnerLength),
                1,
                safe.getOwners().length - 1
            )
        );
        recoveryFuzz.recoveryOwnerLength =
            uint8(bound(uint256(recoveryFuzz.recoveryOwnerLength), 1, 100));
        recoveryFuzz.threshold = uint8(
            bound(
                uint256(recoveryFuzz.threshold),
                1,
                recoveryFuzz.recoveryOwnerLength
            )
        );
        recoveryFuzz.recoveryThreshold = uint8(
            bound(
                uint256(recoveryFuzz.threshold),
                1,
                recoveryFuzz.recoveryOwnerLength
            )
        );

        uint256[] memory recoveryKeys =
            new uint256[](recoveryFuzz.recoveryOwnerLength);

        address[] memory newRecoveryOwners =
            new address[](recoveryFuzz.recoveryOwnerLength);

        for (uint256 i = 0; i < newRecoveryOwners.length; i++) {
            recoveryKeys[i] = uint256(keccak256(abi.encodePacked(i)));
            newRecoveryOwners[i] = vm.addr(recoveryKeys[i]);
        }

        /// first remove owners until the currentOwnerLength is reached
        IMulticall3.Call3[] memory calls3 = new IMulticall3.Call3[](
            safe.getOwners().length - recoveryFuzz.currentOwnerLength + 1
        );

        for (
            uint256 i = 0;
            i < safe.getOwners().length - recoveryFuzz.currentOwnerLength;
            i++
        ) {
            calls3[i] = IMulticall3.Call3({
                target: address(safe),
                callData: abi.encodeWithSelector(
                    OwnerManager.removeOwner.selector,
                    address(1),
                    safe.getOwners()[i],
                    1
                ),
                allowFailure: false
            });
        }

        address recoveryAddress = recoveryFactory.calculateAddress(
            recoverySalt,
            newRecoveryOwners,
            address(safe),
            recoveryFuzz.threshold,
            recoveryFuzz.recoveryThreshold,
            recoveryDelay
        );

        calls3[calls3.length - 1] = IMulticall3.Call3({
            target: address(safe),
            callData: abi.encodeWithSelector(
                ModuleManager.enableModule.selector, recoveryAddress
            ),
            allowFailure: false
        });

        /// remove safe owners, add recovery spell as module
        bytes memory calldatas = abi.encodeWithSelector(
            ModuleManager.execTransactionFromModule.selector,
            multicall,
            0,
            abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls3),
            Enum.Operation.DelegateCall
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

        /// then calculate the recovery spell address for the new recoveryOwners
        /// then add the new module to the safe
        /// then execute the recovery spell

        RecoverySpell recovery = recoveryFactory.createRecoverySpell(
            recoverySalt,
            newRecoveryOwners,
            address(safe),
            recoveryFuzz.threshold,
            recoveryFuzz.recoveryThreshold,
            recoveryDelay
        );

        assertEq(
            recoveryAddress,
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

        {
            bytes32[] memory r = new bytes32[](recoveryKeys.length);
            bytes32[] memory s = new bytes32[](recoveryKeys.length);
            uint8[] memory v = new uint8[](recoveryKeys.length);

            bytes32 digest = recovery.getDigest();

            for (uint256 i = 0; i < recoveryKeys.length; i++) {
                (v[i], r[i], s[i]) = vm.sign(recoveryKeys[i], digest);
            }

            recovery.executeRecovery(address(1), v, r, s);
        }

        assertFalse(
            safe.isModuleEnabled(recoveryAddress),
            "recovery spell should be removed after execution"
        );

        for (uint256 i = 0; i < owners.length; i++) {
            assertFalse(
                safe.isOwner(owners[i]),
                "owner should be removed after recovery"
            );
        }

        for (uint256 i = 0; i < newRecoveryOwners.length; i++) {
            assertTrue(
                safe.isOwner(newRecoveryOwners[i]),
                "recovery owner should be an owner"
            );
        }

        assertEq(
            safe.getThreshold(), recoveryFuzz.threshold, "threshold incorrect"
        );
    }
}
