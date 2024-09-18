pragma solidity 0.8.25;

import {EIP712} from
    "@openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

import {IMulticall3} from "@interface/IMulticall3.sol";
import {OwnerManager} from "@safe/base/OwnerManager.sol";
import {ModuleManager} from "@safe/base/ModuleManager.sol";
import {calculateCreate2Address} from "src/utils/Create2Helper.sol";

contract RecoverySpellSingleton is EIP712("Recovery Spell", "0.1.0") {
    /// -------------------------------------------------------
    /// -------------------------------------------------------
    /// ---------------------- CONSTANTS ----------------------
    /// -------------------------------------------------------
    /// -------------------------------------------------------

    /// @notice the multicall3 contract address
    address public constant MULTICALL3 =
        0xcA11bde05977b3631167028862bE2a173976CA11;

    /// @notice the sentinel address that all linked lists start with
    address public constant SENTINEL = address(0x1);

    /// @notice the recovery type hash for the EIP712 domain separator
    bytes32 public constant RECOVERY_TYPEHASH = keccak256(
        "Recovery(bytes32 salt,address safe,address[] newOwners,uint256 newSafeThreshold,uint256 newRecoveryThreshold,uint256 delay)"
    );

    /// @notice reference to the instance deployer contract
    address public immutable instanceDeployer;

    /// -------------------------------------------------------
    /// -------------------------------------------------------
    /// ------------------- DATA STRUCTURES -------------------
    /// -------------------------------------------------------
    /// -------------------------------------------------------

    /// @notice used for recovering the safe, holds the signatures
    struct RecoveryData {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct RecoverySpell {
        /// address of the safe to recover
        address safe;
        /// true if the spell has been executed
        bool executed;
        /// time the operation can be executed
        uint256 executionTime;
    }

    /// @notice store the recovery spell information based on its hash
    mapping(bytes32 hash => RecoverySpell spell) public recoverySpells;

    /// -------------------------------------------------------
    /// -------------------------------------------------------
    /// ------------------------ EVENTS -----------------------
    /// -------------------------------------------------------
    /// -------------------------------------------------------

    /// @notice event emitted when the recovery is initiated
    /// @param time the time the recovery was initiated
    /// @param caller the address that initiated the recovery
    event RecoveryInitiated(uint256 indexed time, address indexed caller, address indexed safe);

    /// @notice event emitted when the recovery is executed
    /// @param time the time the recovery was executed
    event SafeRecovered(uint256 indexed time, address indexed safe);

    /// @param spellHash the hash of the registered recovery spell
    /// @param safe the address of the safe to recover
    event RecoverySpellRegistered(
        bytes32 indexed spellHash, address indexed safe
    );

    /// @param _instanceDeployer the address of the instance deployer contract
    constructor(address _instanceDeployer) {
        instanceDeployer = _instanceDeployer;
    }

    /// -------------------------------------------------------
    /// -------------------------------------------------------
    /// ----------------- VIEW ONLY FUNCTIONS -----------------
    /// -------------------------------------------------------
    /// -------------------------------------------------------

    /// @notice get the digest for the EIP712 domain separator
    /// @return the digest for the EIP712 domain separator
    function getDigest(
        bytes32 salt,
        address safe,
        address[] memory newOwners,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparatorV4(),
                keccak256(
                    abi.encode(
                        RECOVERY_TYPEHASH,
                        salt,
                        safe,
                        newOwners,
                        threshold,
                        recoveryThreshold,
                        delay
                    )
                )
            )
        );
    }

    function registerRecoverySpell(bytes32 spellHash, address safe) external {
        require(
            msg.sender == instanceDeployer,
            "RecoverySpellSingleton: not instance deployer"
        );
        require(
            recoverySpells[spellHash].safe == address(0),
            "RecoverySpell: spell exists"
        );

        recoverySpells[spellHash] = RecoverySpell(safe, false, 0);

        emit RecoverySpellRegistered(spellHash, safe);
    }

    function initiateRecovery(
        bytes32 salt,
        address[] memory owners,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay,
        RecoveryData[] memory recoveryData
    ) external {
        _paramChecks(owners, threshold, recoveryThreshold, delay);

        bytes32 spellHash = keccak256(
            abi.encode(salt, owners, threshold, recoveryThreshold, delay)
        );

        RecoverySpell storage spell = recoverySpells[spellHash];

        require(!spell.executed, "RecoverySpell: already executed");
        require(spell.safe.code.length != 0, "RecoverySpell: safe non-existent");
        require(
            spell.executionTime == 0, "RecoverySpell: recovery already queued"
        );

        require(
            recoveryThreshold <= recoveryData.length,
            "RecoverySpell: Not enough signatures"
        );

        spell.executionTime = block.timestamp + delay;

        for (uint256 i = 0; i < owners.length; i++) {
            address owner = owners[i];
            assembly ("memory-safe") {
                tstore(owner, 1)
            }
        }

        /// duplication and validity checks
        /// ensure the signatures are
        /// 1. valid signatures
        /// 2. unique signers
        /// 3. recovery owners about to be added to the safe

        /// check if an address that provided a signature is an owner
        /// in storage, then remove that address from used addresses
        /// to prevent the same owner passing multiple signatures.

        bytes32 digest =
            getDigest(salt, spell.safe, owners, threshold, recoveryThreshold, delay);
        
        for (uint256 i = 0; i < recoveryData.length; i++) {
            address recoveredAddress = ecrecover(
                digest, recoveryData[i].v, recoveryData[i].r, recoveryData[i].s
            );
            require(
                recoveredAddress != address(0),
                "RecoverySpell: Invalid signature"
            );

            bool valid;
            assembly ("memory-safe") {
                valid := tload(recoveredAddress)
                if eq(valid, 1) { tstore(recoveredAddress, 0) }
            }

            /// if the address of the signer was not in storage, the value will
            /// be 0 and the require will fail.
            /// if the address of the signer duplicated signatures, the value
            /// will be 0 on the second retrieval and the require will fail.
            require(valid, "RecoverySpell: Duplicate signature");
        }

        emit RecoveryInitiated(block.timestamp, msg.sender, spell.safe);
    }

    function executeRecoverySpell(
        bytes32 salt,
        address[] memory owners,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay,
        address previousModule
    ) external {
        _paramChecks(owners, threshold, recoveryThreshold, delay);

        bytes32 spellHash = keccak256(
            abi.encode(salt, owners, threshold, recoveryThreshold, delay)
        );

        RecoverySpell storage spell = recoverySpells[spellHash];

        /// no checks on parameters as all valid recovery spells are
        /// deployed from the factory which will not allow a recovery
        /// spell to be created that does not have valid parameters
        require(spell.safe != address(0), "RecoverySpell: spell non-existent");
        require(spell.safe.code.length != 0, "RecoverySpell: safe non-existent");
        require(!spell.executed, "RecoverySpell: already executed");
        require(spell.executionTime <= block.timestamp, "RecoverySpell: execution not ready");

        /// effects - make this recovery spell unusable so it can only be used
        /// once
        spell.executed = true;
        spell.executionTime = type(uint256).max;

        address[] memory newOwners = owners;
        address[] memory existingOwners = Safe(payable(spell.safe)).getOwners();
        uint256 existingOwnersLength = existingOwners.length;

        IMulticall3.Call3[] memory calls3 =
            new IMulticall3.Call3[](newOwners.length + existingOwnersLength + 1);

        uint256 index = 0;

        /// build interactions

        /// remove all existing owners except the last one
        for (uint256 i = 0; i < existingOwnersLength - 1; i++) {
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.removeOwner.selector,
                SENTINEL,
                existingOwners[i],
                1
            );
        }

        calls3[index++].callData = abi.encodeWithSelector(
            OwnerManager.swapOwner.selector,
            SENTINEL,
            existingOwners[existingOwnersLength - 1],
            newOwners[0]
        );

        /// only cover indexes 1 through newOwners.length - 1
        for (uint256 i = 1; i < newOwners.length - 1; i++) {
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.addOwnerWithThreshold.selector, newOwners[i], 1
            );
        }

        /// add new owner with the updated threshold
        calls3[index++].callData = abi.encodeWithSelector(
            OwnerManager.addOwnerWithThreshold.selector,
            newOwners[newOwners.length - 1],
            threshold
        );

        calls3[index].callData = abi.encodeWithSelector(
            ModuleManager.disableModule.selector, previousModule, address(this)
        );

        for (uint256 i = 0; i < calls3.length; i++) {
            calls3[i].allowFailure = false;
            calls3[i].target = spell.safe;
        }

        /// interactions

        require(
            Safe(payable(spell.safe)).execTransactionFromModule(
                MULTICALL3,
                0,
                abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls3),
                Enum.Operation.DelegateCall
            ),
            "RecoverySpell: Recovery failed"
        );

        emit SafeRecovered(block.timestamp, spell.safe);
    }

    /// @notice check the parameters of the RecoverySpell contract
    /// @param owners the owners of the contract
    /// @param threshold of owners required to execute transactions
    /// @param recoveryThreshold of owners required to execute recovery transactions
    /// @param delay time required before the recovery transaction can be executed
    function _paramChecks(
        address[] memory owners,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay
    ) private pure {
        require(
            threshold <= owners.length,
            "RecoverySpell: Threshold must be lte number of owners"
        );
        require(
            recoveryThreshold <= owners.length,
            "RecoverySpell: Recovery threshold must be lte number of owners"
        );

        require(threshold != 0, "RecoverySpell: Threshold must be gt 0");
        require(delay <= 365 days, "RecoverySpell: Delay must be lte a year");
    }
}
