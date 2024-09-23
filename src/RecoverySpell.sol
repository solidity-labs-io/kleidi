pragma solidity 0.8.25;

import {EIP712} from
    "@openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from
    "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

import {IMulticall3} from "@interface/IMulticall3.sol";
import {OwnerManager} from "@safe/base/OwnerManager.sol";
import {ModuleManager} from "@safe/base/ModuleManager.sol";

/// @notice if two recovery spells with exactly the same parameters are
/// deployed for the same safe, the domain separator will not be the same
/// because the address of the recovery spell contract is different.
/// This is important as it prevents signature re-use across different
/// recovery spells and chains for the same safe.
contract RecoverySpell is EIP712("Recovery Spell", "0.1.0") {
    /// -------------------------------------------------------
    /// -------------------------------------------------------
    /// ------------------ STORAGE VARIABLES ------------------
    /// -------------------------------------------------------
    /// -------------------------------------------------------

    /// @notice the new owners of the contract once the spell is cast
    /// @dev starts off with non zero array if created by factory
    /// and then is deleted after recovery execution
    address[] public owners;

    /// @notice the time the recovery was initiated
    /// @dev value can only go from 0 to non zero when owner calls
    /// goes from block.timestamp (always lt type(uint32).max)
    /// to type(uint256).max
    /// value can only ever increase
    uint256 public recoveryInitiated;

    /// -------------------------------------------------------
    /// -------------------------------------------------------
    /// ---------------------- IMMUTABLES ---------------------
    /// -------------------------------------------------------
    /// -------------------------------------------------------

    /// @notice the address to recover
    Safe public immutable safe;

    /// @notice the threshold of owners required to execute transactions
    /// after the recovery is executed
    /// threshold must be lte the number of owners
    uint256 public immutable threshold;

    /// @notice the number of new owner signatures required to execute the
    /// recovery process. This is to prevent a single owner from initiating
    /// the recovery process without the consent of the other owners
    uint256 public immutable recoveryThreshold;

    /// @notice the time delay required before the recovery transaction
    /// can be executed
    uint256 public immutable delay;

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
        "Recovery(address safe,uint256 newSafeThreshold,uint256 newRecoveryThreshold,uint256 delay)"
    );

    /// -------------------------------------------------------
    /// -------------------------------------------------------
    /// ------------------------ EVENTS -----------------------
    /// -------------------------------------------------------
    /// -------------------------------------------------------

    /// @notice event emitted when the recovery is initiated
    /// @param time the time the recovery was initiated
    /// @param caller the address that initiated the recovery
    event RecoveryInitiated(uint256 indexed time, address indexed caller);

    /// @notice event emitted when the recovery is executed
    /// @param time the time the recovery was executed
    event SafeRecovered(uint256 indexed time);

    /// @notice it is of critical importance that the delay is shorter
    /// than the timelock delay so that a recovery action can be executed
    /// before the timelock delay expires if need be. There is no way to enforce
    /// this in the contract, so it is up to the deployer to ensure that the
    /// delay is shorter than the timelock delay
    /// @param _owners the new owners of the contract if recovery is executed
    /// @param _safe the address to recover
    /// @param _safeThreshold number of owners required to execute transactions on the safe
    /// @param _recoveryThreshold number of signers required to execute recovery transaction
    /// @param _delay time required before the recovery transaction can be executed
    constructor(
        address[] memory _owners,
        address _safe,
        uint256 _safeThreshold,
        uint256 _recoveryThreshold,
        uint256 _delay
    ) {
        /// no checks on parameters as all valid recovery spells are
        /// deployed from the factory which will not allow a recovery
        /// spell to be created that does not have valid parameters.
        /// A recovery spell can only be created by the factory if the Safe has
        /// already been created on the chain the RecoverySpell is being
        /// deployed on.
        owners = _owners;
        safe = Safe(payable(_safe));
        threshold = _safeThreshold;
        recoveryThreshold = _recoveryThreshold;
        delay = _delay;

        recoveryInitiated = block.timestamp;

        emit RecoveryInitiated(block.timestamp, msg.sender);
    }

    /// @notice get the owners of the contract
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    /// @notice get the digest for the EIP712 domain separator
    /// @return the digest for the EIP712 domain separator
    function getDigest() public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparatorV4(),
                keccak256(
                    abi.encode(
                        RECOVERY_TYPEHASH,
                        safe,
                        threshold,
                        recoveryThreshold,
                        delay
                    )
                )
            )
        );
    }

    /// @notice execute the recovery process, can only be called
    /// after the recovery delay has passed. Callable by any address
    /// @param previousModule the address of the previous module
    /// if the previous module is incorrect, this function will fail
    ///
    /// this function executes actions in the following order:
    ///   1). remove all but final existing owner, sets owner threshold to 1
    ///   2). swap final existing owner for the first new owner
    ///   3). add the remaining new owners to the safe
    ///   4). update the quorum to the new value
    ///   4). remove the recovery module from the safe
    function executeRecovery(
        address previousModule,
        uint8[] calldata v,
        bytes32[] calldata r,
        bytes32[] calldata s
    ) external {
        /// checks
        require(
            recoveryInitiated != type(uint256).max,
            "RecoverySpell: Already recovered"
        );

        /// fails if recovery already executed due to math overflow
        /// even if delay is 0, uint256.max + 1 will always revert
        /// recovery initiated will always be lte block timestamp before the recovery is executed
        require(
            block.timestamp > recoveryInitiated + delay,
            "RecoverySpell: Recovery not ready"
        );
        require(
            v.length == r.length && r.length == s.length,
            "RecoverySpell: Invalid signature parameters"
        );
        /// if there are not enough signers, even if all signatures are
        /// valid and not duplicated, there is no possibility of this being
        /// enough to execute the recovery.
        require(
            recoveryThreshold <= v.length,
            "RecoverySpell: Not enough signatures"
        );

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

        bytes32 digest = getDigest();
        for (uint256 i = 0; i < v.length; i++) {
            address recoveredAddress = ECDSA.recover(digest, v[i], r[i], s[i]);
            bool valid;

            assembly ("memory-safe") {
                valid := tload(recoveredAddress)
                if eq(valid, 1) { tstore(recoveredAddress, 0) }
            }

            /// if the address of the signer was not in storage, the value will
            /// be 0 and the require will fail.
            /// if the address of the signer duplicated signatures, the value
            /// will be 0 on the second retrieval and the require will fail.
            require(
                valid && recoveredAddress != address(0),
                "RecoverySpell: Invalid signature"
            );
        }

        /// @notice execute the recovery process, can only be called
        /// after the recovery delay has passed. Callable by any address

        /// @param previousModule the address of the previous module
        /// if the previous module is incorrect, this function will fail
        ///
        /// this function executes actions in the following order:
        ///   1). remove all but final existing owner, set owner threshold to 1
        ///   2). swap final existing owner for the first new owner
        ///   3). add the remaining new owners to the safe, with the
        ///   last owner being added updating the threshold to the new value
        ///   4). remove the recovery module from the safe
        address[] memory existingOwners = safe.getOwners();
        uint256 existingOwnersLength = existingOwners.length;

        /// + 1 is for the module removal
        /// new owner length = 1
        /// existing owner length = 1
        IMulticall3.Call3[] memory calls3 =
            new IMulticall3.Call3[](owners.length + existingOwnersLength + 1);

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
            owners[0]
        );

        /// only cover indexes 1 through new owners length
        for (uint256 i = 1; i < owners.length; i++) {
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.addOwnerWithThreshold.selector, owners[i], 1
            );
        }

        /// add new owner with the updated threshold
        calls3[index++].callData = abi.encodeWithSelector(
            OwnerManager.changeThreshold.selector, threshold
        );

        calls3[index].callData = abi.encodeWithSelector(
            ModuleManager.disableModule.selector, previousModule, address(this)
        );

        for (uint256 i = 0; i < calls3.length; i++) {
            calls3[i].allowFailure = false;
            calls3[i].target = address(safe);
        }

        /// effects
        /// now impossible to call initiate recovery as owners array is empty
        delete owners;

        /// array length is set to 0 impossible for executeRecovery to be
        /// callable again as the require check will always revert
        recoveryInitiated = type(uint256).max;

        /// interactions

        require(
            safe.execTransactionFromModule(
                MULTICALL3,
                0,
                abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls3),
                Enum.Operation.DelegateCall
            ),
            "RecoverySpell: Recovery failed"
        );

        emit SafeRecovered(block.timestamp);
    }
}
