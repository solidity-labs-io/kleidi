// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "test/utils/SystemIntegrationFixture.sol";

contract SystemIntegrationTest is SystemIntegrationFixture {
    using BytesHelper for bytes;

    function testSafeSetup() public view {
        (address[] memory modules,) = safe.getModulesPaginated(address(1), 10);
        assertEq(
            modules.length,
            2,
            "incorrect modules length, should be timelock and recovery spell"
        );

        address[] memory currentOwners = safe.getOwners();
        assertEq(currentOwners.length, 3, "incorrect owners length");

        assertEq(currentOwners[2], vm.addr(pk1), "incorrect owner 1");
        assertEq(currentOwners[1], vm.addr(pk2), "incorrect owner 2");
        assertEq(currentOwners[0], vm.addr(pk3), "incorrect owner 3");

        assertTrue(safe.isOwner(vm.addr(pk1)), "pk1 is not an owner");
        assertTrue(safe.isOwner(vm.addr(pk2)), "pk2 is not an owner");
        assertTrue(safe.isOwner(vm.addr(pk3)), "pk3 is not an owner");

        assertEq(safe.getThreshold(), 2, "incorrect threshold");

        bytes32 fallbackHandler = vm.load(
            address(safe),
            0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5
        );
        assertEq(fallbackHandler, bytes32(0), "fallback handler is not 0");

        bytes32 guardData = vm.load(
            address(safe),
            0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8
        );
        assertEq(
            guardData,
            bytes32(uint256(uint160(address(guard)))),
            "guard is not set correctly"
        );

        assertEq(
            safe.nonce(),
            1,
            "incorrect nonce, should have incremented on initialization transaction"
        );
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

        assertTrue(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_ONE),
            "Hot signer one should have role"
        );
        assertTrue(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_TWO),
            "Hot signer two should have role"
        );
        assertTrue(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_THREE),
            "Hot signer three should have role"
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
    function testInitializeViaDelegateCallFails() public {
        IMulticall3.Call3[] memory calls3 = new IMulticall3.Call3[](4);

        calls3[0].target = address(guard);
        calls3[0].allowFailure = false;

        calls3[1].target = address(safe);
        calls3[1].allowFailure = false;

        calls3[2].target = address(safe);
        calls3[2].allowFailure = false;

        calls3[3].target = address(safe);
        calls3[3].allowFailure = false;

        calls3[0].callData = abi.encodeWithSelector(Guard.checkSafe.selector);

        calls3[1].callData = abi.encodeWithSelector(
            GuardManager.setGuard.selector, address(guard)
        );

        calls3[2].callData = abi.encodeWithSelector(
            ModuleManager.enableModule.selector, address(timelock)
        );

        calls3[3].callData = abi.encodeWithSelector(
            ModuleManager.enableModule.selector, recoverySpellAddress
        );

        bytes memory safeData =
            abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls3);

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

        bytes memory collatedSignatures =
            signTxAllOwners(transactionHash, pk1, pk2, pk3);

        safe.checkNSignatures(transactionHash, safeData, collatedSignatures, 3);

        vm.expectRevert("Guard: delegate call disallowed");
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

        assertEq(guard, address(guard), "guard is not guard");
        assertTrue(
            safe.isModuleEnabled(address(timelock)), "timelock not a module"
        );
        assertTrue(
            safe.isModuleEnabled(recoverySpellAddress),
            "recovery spell not a module"
        );
    }

    ///
    /// construction of all calls within this system outside of setup:
    ///    safe calls timelock, timelock calls external contracts
    ///    encoding:
    ///       1. gather array of addresses, values and bytes for the calls
    ///       2. encode the array of calls to call the scheduleBatch function on the timelock
    ///       3. encode this data to call the Safe contract
    ///

    function testTransactionAddingWhitelistedCalldataSucced() public {
        address[] memory calls = new address[](1);
        calls[0] = address(timelock);

        bytes memory innerCalldatas;
        bytes memory contractCall;
        {
            /// each morpho blue function call needs two checks:
            /// 1). check the pool id where funds are being deposited is whitelisted.
            /// 2). check the recipient of the funds is whitelisted whether withdrawing
            /// or depositing.

            uint16[] memory startIndexes = new uint16[](9);
            /// morpho blue supply
            startIndexes[0] = 4;
            /// only grab last twenty bytes of the 8th argument
            startIndexes[1] = 4 + 32 * 7 + 12;
            /// ethena usd approve morpho
            startIndexes[2] = 16;
            /// only check last twenty bytes of the 9th argument
            startIndexes[3] = 4 + 32 * 8 + 12;
            /// only grab last twenty bytes of the 8th argument
            startIndexes[4] = 4 + 32 * 7 + 12;
            /// only grab last twenty bytes of the 9th argument
            startIndexes[5] = 4 + 32 * 8 + 12;
            /// check last twenty bytes of the 7th argument
            startIndexes[6] = 4 + 32 * 6 + 12;
            /// check last twenty bytes of the 8th argument
            startIndexes[7] = 4 + 32 * 7 + 12;
            /// dai approve morpho
            startIndexes[8] = 16;

            uint16[] memory endIndexes = new uint16[](9);
            /// morpho blue supply
            endIndexes[0] = startIndexes[0] + 32 * 5;
            /// last twenty bytes represents who supplying on behalf of
            endIndexes[1] = startIndexes[1] + 20;
            /// ethena usd approve morpho
            endIndexes[2] = startIndexes[2] + 20;
            /// last twenty bytes represents who is approved to spend the tokens
            /// morpho borrow
            endIndexes[3] = startIndexes[3] + 20;
            /// morpho repay
            endIndexes[4] = startIndexes[4] + 20;
            /// morpho withdraw
            endIndexes[5] = startIndexes[5] + 20;
            /// last twenty bytes represents asset receiver
            endIndexes[6] = startIndexes[6] + 20;
            /// last twenty bytes represents asset receiver
            endIndexes[7] = startIndexes[7] + 20;
            /// dai approve morpho
            endIndexes[8] = startIndexes[2] + 20;

            bytes4[] memory selectors = new bytes4[](9);
            selectors[0] = IMorphoBase.supply.selector;
            selectors[1] = IMorphoBase.supply.selector;
            selectors[2] = IERC20.approve.selector;
            selectors[3] = IMorphoBase.borrow.selector;
            selectors[4] = IMorphoBase.repay.selector;
            selectors[5] = IMorphoBase.withdraw.selector;
            /// if borrowable assets are supplied to a market where there is bad debt, there is a possibility of loss
            /// so the timelock should be the only one allowed to supply borrowable assets to the whitelisted market
            /// supplying collateral to markets with bad debt should not pose a risk to capital because the
            /// collateral is not borrowed
            selectors[6] = IMorphoBase.supplyCollateral.selector;
            selectors[7] = IMorphoBase.withdrawCollateral.selector;
            selectors[8] = IERC20.approve.selector;

            bytes[] memory calldatas = new bytes[](9);
            /// can only deposit to dai/eusd pool
            calldatas[0] = abi.encode(dai, ethenaUsd, oracle, irm, lltv);
            /// can only deposit to timelock
            calldatas[1] = "";
            /// morpho blue address can be approved to spend eUSD
            calldatas[2] = abi.encodePacked(morphoBlue);
            /// can only borrow to timelock
            calldatas[3] = "";
            /// can only repay on behalf of timelock
            calldatas[4] = "";
            /// only withdraw asset back to timelock
            calldatas[5] = "";
            /// can only supply collateral on behalf of timelock
            calldatas[6] = "";
            /// can only withdraw collateral back to timelock
            calldatas[7] = "";
            /// morpho blue address can be approved to spend dai
            calldatas[8] = abi.encodePacked(morphoBlue);

            address[] memory targets = new address[](9);
            targets[0] = morphoBlue;
            targets[1] = morphoBlue;
            targets[2] = ethenaUsd;
            targets[3] = morphoBlue;
            targets[4] = morphoBlue;
            targets[5] = morphoBlue;
            targets[6] = morphoBlue;
            targets[7] = morphoBlue;
            targets[8] = dai;

            bool[] memory isSelfAddressCheck = new bool[](9);
            isSelfAddressCheck[0] = false;
            isSelfAddressCheck[1] = true;
            isSelfAddressCheck[2] = false;
            isSelfAddressCheck[3] = true;
            isSelfAddressCheck[4] = true;
            isSelfAddressCheck[5] = true;
            isSelfAddressCheck[6] = true;
            isSelfAddressCheck[7] = true;
            isSelfAddressCheck[8] = false;

            contractCall = abi.encodeWithSelector(
                Timelock.addCalldataChecks.selector,
                targets,
                selectors,
                startIndexes,
                endIndexes,
                calldatas,
                isSelfAddressCheck
            );

            /// inner calldata
            innerCalldatas = abi.encodeWithSelector(
                Timelock.schedule.selector,
                address(timelock),
                0,
                contractCall,
                bytes32(0),
                /// salt
                timelock.minDelay()
            );
        }

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

        vm.prank(owners[0]);
        timelock.execute(address(timelock), 0, contractCall, bytes32(0));
    }

    function testSetFallbackHandlerFails() public {
        bytes memory calldatas = abi.encodeWithSelector(
            FallbackManager.setFallbackHandler.selector, address(0)
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            0,
            calldatas,
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

        /// warp forward to allowed time

        vm.expectRevert("Guard: no self calls");
        safe.execTransaction(
            address(safe),
            0,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );
    }

    function testRemoveOwnerFails() public {
        /// threshold unchanged
        bytes memory calldatas = abi.encodeWithSelector(
            OwnerManager.removeOwner.selector, address(0), address(0), 2
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            0,
            calldatas,
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

        /// warp forward to allowed time

        vm.expectRevert("Guard: no self calls");
        safe.execTransaction(
            address(safe),
            0,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );
    }

    function testAddOwnerFails() public {
        /// threshold unchanged
        bytes memory calldatas = abi.encodeWithSelector(
            OwnerManager.addOwnerWithThreshold.selector, address(0), 2
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            0,
            calldatas,
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

        /// warp forward to allowed time

        vm.expectRevert("Guard: no self calls");
        safe.execTransaction(
            address(safe),
            0,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );
    }

    function testSwapOwnerFails() public {
        bytes memory calldatas = abi.encodeWithSelector(
            OwnerManager.swapOwner.selector, address(0), address(0), address(0)
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            0,
            calldatas,
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

        /// warp forward to allowed time

        vm.expectRevert("Guard: no self calls");
        safe.execTransaction(
            address(safe),
            0,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );
    }

    function testChangeThresholdFails() public {
        /// threshold unchanged
        bytes memory calldatas =
            abi.encodeWithSelector(OwnerManager.changeThreshold.selector, 2);

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            0,
            calldatas,
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

        /// warp forward to allowed time

        vm.expectRevert("Guard: no self calls");
        safe.execTransaction(
            address(safe),
            0,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );
    }

    function testEnableModuleFails() public {
        bytes memory calldatas = abi.encodeWithSelector(
            ModuleManager.enableModule.selector, address(1111111111)
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            0,
            calldatas,
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

        /// warp forward to allowed time

        vm.expectRevert("Guard: no self calls");
        safe.execTransaction(
            address(safe),
            0,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );
    }

    function testRemoveModuleFails() public {
        /// remove timelock as a module
        bytes memory calldatas = abi.encodeWithSelector(
            ModuleManager.disableModule.selector, address(timelock)
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            0,
            calldatas,
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

        /// warp forward to allowed time

        /// fails because call to self + calldata not zero length
        vm.expectRevert("Guard: no self calls");
        safe.execTransaction(
            address(safe),
            0,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );
    }

    function testOnchainCancellationSucceeds() public {
        bytes memory calldatas = "";
        uint256 value = 0;
        uint256 startingNonce = safe.nonce();

        bytes32 transactionHash = safe.getTransactionHash(
            address(safe),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            startingNonce
        );

        bytes memory collatedSignatures =
            signTxAllOwners(transactionHash, pk1, pk2, pk3);

        /// warp forward to allowed time

        /// call to self succeeds because calldata length is zero
        /// and value is 0
        safe.execTransaction(
            address(safe),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        assertEq(
            safe.nonce(),
            startingNonce + 1,
            "incorrect nonce, did not cancel original transaction"
        );
    }

    function testRecoverySpellAfterPauseGaurdian() public {
        /// safe owners enact malicious proposal to disable timelock module
        bytes memory calldatas = abi.encodeWithSelector(
            ModuleManager.execTransactionFromModule.selector,
            address(safe),
            0,
            abi.encodeWithSelector(
                ModuleManager.disableModule.selector,
                recoverySpellAddress,
                address(timelock)
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

        /// guardian pauses timelock after 1 day passes
        vm.warp(block.timestamp + timelock.minDelay() / 2);
        vm.prank(guardian);
        timelock.pause();

        /// initiate recovery
        RecoverySpell recovery = recoveryFactory.createRecoverySpell(
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

        recovery.initiateRecovery();

        assertEq(
            recovery.recoveryInitiated(),
            block.timestamp,
            "recovery not initiated"
        );

        /// execute recovery
        vm.warp(block.timestamp + recoveryDelay + 1);

        {
            /// sign recovery transaction
            bytes32[] memory r = new bytes32[](recoveryPrivateKeys.length);
            bytes32[] memory s = new bytes32[](recoveryPrivateKeys.length);
            uint8[] memory v = new uint8[](recoveryPrivateKeys.length);

            bytes32 digest = recovery.getDigest();

            for (uint256 i = 0; i < recoveryPrivateKeys.length; i++) {
                (v[i], r[i], s[i]) = vm.sign(recoveryPrivateKeys[i], digest);
            }

            /// execute recovery transaction
            recovery.executeRecovery(address(1), v, r, s);
        }
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

        assertEq(safe.getThreshold(), recoveryThreshold, "threshold incorrect");

        /// skip the pause duration
        vm.warp(block.timestamp + timelock.pauseDuration() + 1);

        /// set old guardian again as guardian
        calldatas = abi.encodeWithSelector(
            Timelock.setGuardian.selector, address(guardian)
        );

        innerCalldatas = abi.encodeWithSelector(
            Timelock.schedule.selector,
            address(timelock),
            0,
            calldatas,
            /// salt
            bytes32(0),
            timelock.minDelay()
        );

        transactionHash = safe.getTransactionHash(
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

        collatedSignatures = signTxAllOwners(
            transactionHash,
            recoveryPrivateKeys[1],
            recoveryPrivateKeys[0],
            recoveryPrivateKeys[2]
        );

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

        timelock.execute(address(timelock), 0, calldatas, bytes32(0));

        /// add a new recovery spell
        uint256 newRecoveryOwnersLength = 3;
        address[] memory newRecoveryOwners =
            new address[](newRecoveryOwnersLength);

        for (uint256 i = 0; i < newRecoveryOwnersLength; i++) {
            newRecoveryOwners[i] =
                makeAddr(string(abi.encodePacked("newRecoveryAddress", i)));
        }

        address newRecoverySpellAddress = recoveryFactory.calculateAddress(
            recoverySalt,
            newRecoveryOwners,
            address(safe),
            2,
            RECOVERY_THRESHOLD_OWNERS,
            recoveryDelay
        );

        calldatas = abi.encodeWithSelector(
            ModuleManager.execTransactionFromModule.selector,
            address(safe),
            0,
            abi.encodeWithSelector(
                ModuleManager.enableModule.selector,
                address(newRecoverySpellAddress)
            ),
            Enum.Operation.Call
        );
        innerCalldatas = abi.encodeWithSelector(
            Timelock.schedule.selector,
            address(safe),
            0,
            calldatas,
            /// salt
            bytes32(0),
            timelock.minDelay()
        );

        transactionHash = safe.getTransactionHash(
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

        collatedSignatures = signTxAllOwners(
            transactionHash,
            recoveryPrivateKeys[1],
            recoveryPrivateKeys[0],
            recoveryPrivateKeys[2]
        );

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
            safe.isModuleEnabled(address(newRecoverySpellAddress)),
            "new recovery spell is not a module"
        );
    }

    function testExecuteWhitelistedCalldataSucceedsSupplyWithdrawCollateral()
        public
    {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 supplyAmount = 100000;

        {
            address[] memory targets = new address[](2);
            targets[0] = address(ethenaUsd);
            targets[1] = address(morphoBlue);

            uint256[] memory values = new uint256[](2);

            bytes[] memory calldatas = new bytes[](2);

            deal(ethenaUsd, address(timelock), supplyAmount);

            calldatas[0] = abi.encodeWithSelector(
                IERC20.approve.selector, morphoBlue, supplyAmount
            );

            calldatas[1] = abi.encodeWithSelector(
                IMorphoBase.supplyCollateral.selector,
                dai,
                ethenaUsd,
                oracle,
                irm,
                lltv,
                supplyAmount,
                /// supply supplyAmount of eUSD
                address(timelock),
                ""
            );

            IMorphoBase(morphoBlue).accrueInterest(
                MarketParams(dai, ethenaUsd, oracle, irm, lltv)
            );

            vm.prank(HOT_SIGNER_ONE);
            timelock.executeWhitelistedBatch(targets, values, calldatas);
        }

        bytes32 marketId = id(MarketParams(dai, ethenaUsd, oracle, irm, lltv));

        Position memory position =
            IMorpho(morphoBlue).position(marketId, address(timelock));

        assertEq(position.supplyShares, 0, "incorrect supply shares");
        assertEq(position.borrowShares, 0, "incorrect borrow shares");
        assertEq(position.collateral, supplyAmount, "incorrect collateral");

        {
            address[] memory targets = new address[](1);
            targets[0] = address(morphoBlue);

            uint256[] memory values = new uint256[](1);
            values[0] = 0;

            bytes[] memory calldatas = new bytes[](1);
            calldatas[0] = abi.encodeWithSelector(
                IMorphoBase.withdrawCollateral.selector,
                dai,
                ethenaUsd,
                oracle,
                irm,
                lltv,
                supplyAmount,
                address(timelock),
                address(timelock)
            );

            vm.prank(HOT_SIGNER_TWO);
            timelock.executeWhitelistedBatch(targets, values, calldatas);

            position = IMorpho(morphoBlue).position(marketId, address(timelock));

            assertEq(position.supplyShares, 0, "incorrect supply shares");
            assertEq(position.borrowShares, 0, "incorrect borrow shares");
            assertEq(position.collateral, 0, "incorrect collateral");

            assertEq(
                IERC20(ethenaUsd).balanceOf(address(timelock)),
                supplyAmount,
                "incorrect eUSD balance post withdrawal"
            );
        }
    }

    function testSupplyCollateralOnBehalfNonWhitelistedAddressFails() public {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 supplyAmount = 100000;

        address[] memory targets = new address[](1);
        targets[0] = address(morphoBlue);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            IMorphoBase.supplyCollateral.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            supplyAmount,
            address(this),
            ""
        );

        vm.prank(HOT_SIGNER_THREE);
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelistedBatch(targets, values, calldatas);
    }

    function testWithdrawCollateralToNonWhitelistedAddressFails() public {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 supplyAmount = 100000;

        address[] memory targets = new address[](1);
        targets[0] = address(morphoBlue);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            IMorphoBase.withdrawCollateral.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            supplyAmount,
            address(timelock),
            address(this)
        );

        vm.prank(HOT_SIGNER_THREE);
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelistedBatch(targets, values, calldatas);
    }

    function testExecuteWhitelistedCalldataSucceedsSupplyWithdrawAsset()
        public
    {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 supplyAmount = 100000;
        uint256 supplyShares = 1000;

        {
            address[] memory targets = new address[](2);
            targets[0] = address(dai);
            targets[1] = address(morphoBlue);

            uint256[] memory values = new uint256[](2);

            bytes[] memory calldatas = new bytes[](2);

            deal(dai, address(timelock), supplyAmount);

            calldatas[0] = abi.encodeWithSelector(
                IERC20.approve.selector, morphoBlue, supplyAmount
            );

            calldatas[1] = abi.encodeWithSelector(
                IMorphoBase.supply.selector,
                dai,
                ethenaUsd,
                oracle,
                irm,
                lltv,
                0,
                supplyShares,
                address(timelock),
                ""
            );

            IMorphoBase(morphoBlue).accrueInterest(
                MarketParams(dai, ethenaUsd, oracle, irm, lltv)
            );

            vm.prank(HOT_SIGNER_ONE);
            timelock.executeWhitelistedBatch(targets, values, calldatas);
        }

        bytes32 marketId = id(MarketParams(dai, ethenaUsd, oracle, irm, lltv));

        Position memory position =
            IMorpho(morphoBlue).position(marketId, address(timelock));

        assertEq(position.supplyShares, supplyShares, "incorrect supply shares");
        assertEq(position.borrowShares, 0, "incorrect borrow shares");
        assertEq(position.collateral, 0, "incorrect collateral");

        {
            address[] memory targets = new address[](1);
            targets[0] = address(morphoBlue);

            uint256[] memory values = new uint256[](1);
            values[0] = 0;

            bytes[] memory calldatas = new bytes[](1);
            calldatas[0] = abi.encodeWithSelector(
                IMorphoBase.withdraw.selector,
                dai,
                ethenaUsd,
                oracle,
                irm,
                lltv,
                0,
                supplyShares,
                address(timelock),
                address(timelock)
            );

            vm.prank(HOT_SIGNER_TWO);
            timelock.executeWhitelistedBatch(targets, values, calldatas);

            position = IMorpho(morphoBlue).position(marketId, address(timelock));

            assertEq(position.supplyShares, 0, "incorrect supply shares");
            assertEq(position.borrowShares, 0, "incorrect borrow shares");
            assertEq(position.collateral, 0, "incorrect collateral");
        }
    }

    function testSupplyAssetOnBehalfNonWhitelistedAddressFails() public {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 supplyShares = 1000;

        address[] memory targets = new address[](1);
        targets[0] = address(morphoBlue);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            IMorphoBase.supply.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            0,
            supplyShares,
            address(this),
            ""
        );

        vm.prank(HOT_SIGNER_THREE);
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelistedBatch(targets, values, calldatas);
    }

    function testWithdrawAssetToNonWhitelistedAddressFails() public {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 supplyShares = 1000;

        address[] memory targets = new address[](1);
        targets[0] = address(morphoBlue);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            IMorphoBase.withdraw.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            0,
            supplyShares,
            address(timelock),
            address(this)
        );

        vm.prank(HOT_SIGNER_THREE);
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelistedBatch(targets, values, calldatas);
    }

    function testExecuteWhitelistedCalldataSucceedsBorrowRepay() public {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 supplyAmount = 100000;
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory calldatas = new bytes[](2);

        targets[0] = address(dai);
        targets[1] = address(morphoBlue);

        deal(dai, address(timelock), supplyAmount);

        calldatas[0] = abi.encodeWithSelector(
            IERC20.approve.selector, morphoBlue, supplyAmount
        );

        calldatas[1] = abi.encodeWithSelector(
            IMorphoBase.supply.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            supplyAmount,
            0,
            address(timelock),
            ""
        );

        IMorphoBase(morphoBlue).accrueInterest(
            MarketParams(dai, ethenaUsd, oracle, irm, lltv)
        );

        vm.prank(HOT_SIGNER_ONE);
        timelock.executeWhitelistedBatch(targets, values, calldatas);

        bytes32 marketId = id(MarketParams(dai, ethenaUsd, oracle, irm, lltv));

        Position memory position =
            IMorpho(morphoBlue).position(marketId, address(timelock));

        assertGt(position.supplyShares, 0, "incorrect supply shares");
        assertEq(position.borrowShares, 0, "incorrect borrow shares");
        assertEq(position.collateral, 0, "incorrect collateral");

        assertEq(
            IERC20(dai).balanceOf(address(timelock)),
            0,
            "incorrect dai balance post supply"
        );

        targets[0] = address(ethenaUsd);
        targets[1] = address(morphoBlue);

        deal(ethenaUsd, address(timelock), supplyAmount);

        calldatas[0] = abi.encodeWithSelector(
            IERC20.approve.selector, morphoBlue, supplyAmount
        );

        calldatas[1] = abi.encodeWithSelector(
            IMorphoBase.supplyCollateral.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            supplyAmount,
            /// supply supplyAmount of eUSD
            address(timelock),
            ""
        );

        IMorphoBase(morphoBlue).accrueInterest(
            MarketParams(dai, ethenaUsd, oracle, irm, lltv)
        );

        vm.prank(HOT_SIGNER_ONE);
        timelock.executeWhitelistedBatch(targets, values, calldatas);

        position = IMorpho(morphoBlue).position(marketId, address(timelock));

        assertGt(position.supplyShares, 0, "incorrect supply shares");
        assertEq(position.borrowShares, 0, "incorrect borrow shares");
        assertEq(position.collateral, supplyAmount, "incorrect collateral");

        assertEq(
            IERC20(ethenaUsd).balanceOf(address(timelock)),
            0,
            "incorrect eUSD balance post supply"
        );

        targets = new address[](1);
        values = new uint256[](1);
        calldatas = new bytes[](1);

        targets[0] = address(morphoBlue);

        calldatas[0] = abi.encodeWithSelector(
            IMorphoBase.borrow.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            supplyAmount / 2,
            0,
            address(timelock),
            address(timelock)
        );

        IMorphoBase(morphoBlue).accrueInterest(
            MarketParams(dai, ethenaUsd, oracle, irm, lltv)
        );

        vm.prank(HOT_SIGNER_ONE);
        timelock.executeWhitelistedBatch(targets, values, calldatas);

        position = IMorpho(morphoBlue).position(marketId, address(timelock));

        assertGt(position.supplyShares, 0, "incorrect supply shares");
        assertGt(position.borrowShares, 0, "incorrect borrow shares");
        assertEq(position.collateral, supplyAmount, "incorrect collateral");

        assertEq(
            IERC20(dai).balanceOf(address(timelock)),
            supplyAmount / 2,
            "incorrect dai balance post borrow"
        );

        targets = new address[](2);
        values = new uint256[](2);
        calldatas = new bytes[](2);

        targets[0] = address(dai);
        targets[1] = address(morphoBlue);

        calldatas[0] = abi.encodeWithSelector(
            IERC20.approve.selector, morphoBlue, supplyAmount / 2
        );
        calldatas[1] = abi.encodeWithSelector(
            IMorphoBase.repay.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            supplyAmount / 2,
            0,
            address(timelock),
            ""
        );

        IMorphoBase(morphoBlue).accrueInterest(
            MarketParams(dai, ethenaUsd, oracle, irm, lltv)
        );

        vm.prank(HOT_SIGNER_ONE);
        timelock.executeWhitelistedBatch(targets, values, calldatas);

        position = IMorpho(morphoBlue).position(marketId, address(timelock));

        assertGt(position.supplyShares, 0, "incorrect supply shares");
        /// borrow shares decrease to 1 and not 0 due to rounding
        assertEq(position.borrowShares, 1, "incorrect borrow shares");
        assertEq(position.collateral, supplyAmount, "incorrect collateral");

        assertEq(
            IERC20(dai).balanceOf(address(timelock)),
            0,
            "incorrect dai balance post borrow"
        );
    }

    function testBorrowToNonWhitelistedAddressFails() public {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 borrowAmount = 1000;

        address[] memory targets = new address[](1);
        targets[0] = address(morphoBlue);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            IMorphoBase.borrow.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            borrowAmount,
            0,
            address(timelock),
            address(this)
        );

        vm.prank(HOT_SIGNER_THREE);
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelistedBatch(targets, values, calldatas);
    }

    function testRepayOnBehalfNonWhitelistedAddressFails() public {
        testTransactionAddingWhitelistedCalldataSucced();

        /// warp to current timestamp to prevent math underflow
        /// with cached timestamp in the future which doesn't work
        vm.warp(startTimestamp);
        uint256 repayAmount = 1000;

        address[] memory targets = new address[](1);
        targets[0] = address(morphoBlue);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            IMorphoBase.repay.selector,
            dai,
            ethenaUsd,
            oracle,
            irm,
            lltv,
            repayAmount,
            0,
            address(this),
            ""
        );

        vm.prank(HOT_SIGNER_THREE);
        vm.expectRevert("CalldataList: Calldata does not match expected value");
        timelock.executeWhitelistedBatch(targets, values, calldatas);
    }

    function testSafeRevokeHotSignerSucceed() public {
        bytes memory calldatas = abi.encodeWithSelector(
            Timelock.revokeHotSigner.selector, HOT_SIGNER_ONE
        );
        uint256 value = 0;

        bytes32 transactionHash = safe.getTransactionHash(
            address(timelock),
            value,
            calldatas,
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

        safe.execTransaction(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        assertFalse(
            timelock.hasRole(timelock.HOT_SIGNER_ROLE(), HOT_SIGNER_ONE),
            "Hot signer one should not have role"
        );
    }

    function testWhenPausedMutativeFunctionsFail() public {
        uint256 value = 0;

        bytes memory calldatas = abi.encodeWithSelector(
            Timelock.schedule.selector,
            address(timelock),
            value,
            "",
            bytes32(0),
            timelock.minDelay()
        );

        bytes32 transactionHash = safe.getTransactionHash(
            address(timelock),
            value,
            calldatas,
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

        /// create snapshot when unpaused
        uint256 snapshot = vm.snapshot();

        /// schedule succeeds when unpaused
        safe.execTransaction(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        vm.revertTo(snapshot);

        vm.prank(guardian);
        timelock.pause();

        /// schedule reverts when paused
        vm.expectRevert("GS013");
        safe.execTransaction(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        {
            address[] memory targets = new address[](1);
            targets[0] = address(timelock);

            uint256[] memory values = new uint256[](1);
            bytes[] memory payloads = new bytes[](1);
            payloads[0] = abi.encodeWithSelector(
                Timelock.updateDelay.selector, MINIMUM_DELAY * 2
            );

            calldatas = abi.encodeWithSelector(
                Timelock.scheduleBatch.selector,
                targets,
                values,
                payloads,
                bytes32(0),
                timelock.minDelay()
            );

            transactionHash = safe.getTransactionHash(
                address(timelock),
                value,
                calldatas,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                address(0),
                safe.nonce()
            );

            collatedSignatures = signTxAllOwners(transactionHash, pk1, pk2, pk3);

            /// unpause
            vm.revertTo(snapshot);

            /// batch schedule succeeds when unpaused
            safe.execTransaction(
                address(timelock),
                value,
                calldatas,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                collatedSignatures
            );

            vm.revertTo(snapshot);
            vm.prank(guardian);
            timelock.pause();

            ///batch schedule reverts when paused
            vm.expectRevert("GS013");
            safe.execTransaction(
                address(timelock),
                value,
                calldatas,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                collatedSignatures
            );

            /// unpause
            vm.revertTo(snapshot);

            /// schedule a batch transaction
            safe.execTransaction(
                address(timelock),
                value,
                calldatas,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                collatedSignatures
            );

            vm.warp(block.timestamp + timelock.minDelay());

            /// batch execute succeeds when not paused
            timelock.executeBatch(targets, values, payloads, bytes32(0));

            assertEq(
                timelock.minDelay(), MINIMUM_DELAY * 2, "delay not updated"
            );

            /// unpause
            vm.revertTo(snapshot);

            /// schedule a batch transaction
            safe.execTransaction(
                address(timelock),
                value,
                calldatas,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                collatedSignatures
            );

            vm.warp(block.timestamp + timelock.minDelay());

            /// pause
            vm.prank(guardian);
            timelock.pause();

            /// batch execute reverts when paused
            vm.expectRevert("Pausable: paused");
            timelock.executeBatch(targets, values, payloads, bytes32(0));
        }

        /// unpause
        vm.revertTo(snapshot);

        calldatas = abi.encodeWithSelector(
            Timelock.updateDelay.selector, MINIMUM_DELAY * 2
        );

        calldatas = abi.encodeWithSelector(
            Timelock.schedule.selector,
            address(timelock),
            value,
            calldatas,
            bytes32(0),
            timelock.minDelay()
        );

        transactionHash = safe.getTransactionHash(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        collatedSignatures = signTxAllOwners(transactionHash, pk1, pk2, pk3);

        /// schedule an operation
        safe.execTransaction(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        /// snapshot state when unpaused
        /// and updateDelay operation scheduled
        snapshot = vm.snapshot();

        bytes32 proposalId = timelock.hashOperation(
            address(timelock),
            value,
            abi.encodeWithSelector(
                Timelock.updateDelay.selector, MINIMUM_DELAY * 2
            ),
            bytes32(0)
        );

        calldatas = abi.encodeWithSelector(Timelock.cancel.selector, proposalId);

        transactionHash = safe.getTransactionHash(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        collatedSignatures = signTxAllOwners(transactionHash, pk1, pk2, pk3);

        /// cancel scheduled operation
        safe.execTransaction(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        vm.revertTo(snapshot);

        transactionHash = safe.getTransactionHash(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        collatedSignatures = signTxAllOwners(transactionHash, pk1, pk2, pk3);

        /// pause
        vm.prank(guardian);
        timelock.pause();

        /// cancel reverts as paused
        vm.expectRevert("GS013");
        safe.execTransaction(
            address(timelock),
            value,
            calldatas,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collatedSignatures
        );

        vm.revertTo(snapshot);

        calldatas = abi.encodeWithSelector(
            Timelock.updateDelay.selector, MINIMUM_DELAY * 2
        );

        vm.warp(block.timestamp + timelock.minDelay());

        /// executing updateDelay succeeds
        timelock.execute(address(timelock), value, calldatas, bytes32(0));

        assertEq(timelock.minDelay(), MINIMUM_DELAY * 2, "delay not updated");

        vm.revertTo(snapshot);

        vm.prank(guardian);
        timelock.pause();

        vm.warp(block.timestamp + timelock.minDelay());

        /// executing updateDelay reverts when paused
        vm.expectRevert("Pausable: paused");
        timelock.execute(address(timelock), value, calldatas, bytes32(0));

        vm.revertTo(snapshot);

        /// warp to expiration timestamp
        vm.warp(timelock.timestamps(proposalId) + timelock.expirationPeriod());

        /// cleanup updateDelay succeeds
        timelock.cleanup(proposalId);

        vm.revertTo(snapshot);

        vm.prank(guardian);
        timelock.pause();

        vm.warp(timelock.timestamps(proposalId) + timelock.expirationPeriod());

        /// cleanup reverts when paused
        vm.expectRevert("Pausable: paused");
        timelock.cleanup(proposalId);

        /// unpause
        vm.revertTo(snapshot);

        testTransactionAddingWhitelistedCalldataSucced();

        vm.prank(guardian);
        timelock.pause();

        calldatas =
            abi.encodeWithSelector(IERC20.approve.selector, morphoBlue, 1000);

        /// executeWhitelisted reverts when paused
        vm.prank(HOT_SIGNER_ONE);
        vm.expectRevert("Pausable: paused");
        timelock.executeWhitelisted(address(ethenaUsd), value, calldatas);

        address[] memory targets = new address[](1);
        targets[0] = address(ethenaUsd);

        bytes[] memory payloads = new bytes[](1);
        payloads[0] = calldatas;

        /// batch executeWhitelisted reverts when paused
        vm.prank(HOT_SIGNER_ONE);
        vm.expectRevert("Pausable: paused");
        timelock.executeWhitelistedBatch(targets, new uint256[](1), payloads);
    }
}
