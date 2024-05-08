pragma solidity 0.8.25;

import {Safe} from "@safe/Safe.sol";
import {Enum} from "@safe/common/Enum.sol";

import {Test, console} from "forge-std/Test.sol";

import {IMulticall3} from "@interface/IMulticall3.sol";
import {OwnerManager} from "@safe/base/OwnerManager.sol";
import {ModuleManager} from "@safe/base/ModuleManager.sol";

contract RecoverySpell {
    /// @notice the new owners of the contract once the spell is cast
    address[] public owners;

    /// @notice the address to recover
    Safe public immutable safe;

    /// @notice the threshold of owners required to execute transactions
    uint256 public immutable threshold;

    /// @notice the time required before the recovery transaction can be executed
    uint256 public immutable delay;

    /// @notice the time the recovery was initiated
    uint256 public recoveryInitiated;

    /// @notice address of the multicall3 contract
    address public constant multicall3 =
        0xcA11bde05977b3631167028862bE2a173976CA11;

    /// @notice the sentinel address that all linked lists start with
    address public constant SENTINEL = address(0x1);

    /// @notice event emitted when the recovery is initiated
    event RecoveryInitiated(uint256 indexed time, address indexed caller);

    /// @notice event emitted when the recovery is executed
    event SafeRecovered(uint256 indexed time);

    /// @notice it is of critical importance that the delay is shorter
    /// than the timelock delay so that a recovery action can be executed
    /// before the timelock delay expires if need be
    /// @param _owners the new owners of the contract if recovery is executed
    /// @param _safe the address to recover
    /// @param _threshold number of owners required to execute transactions
    /// @param _delay time required before the recovery transaction can be executed
    constructor(
        address[] memory _owners,
        address _safe,
        uint256 _threshold,
        uint256 _delay
    ) {
        require(
            _threshold <= _owners.length,
            "RecoverySpell: Threshold must be lte number of owners"
        );
        require(
            _threshold != 0, "RecoverySpell: Threshold must be greater than 0"
        );
        require(
            _delay >= 1 days && _delay <= 20 days,
            "RecoverySpell: Delay must be between 1 and 20 days"
        );

        owners = _owners;
        safe = Safe(payable(_safe));
        threshold = _threshold;
        delay = _delay;
    }

    /// @notice initiate the recovery process
    /// can only be called by a new safe owner
    function initiateRecovery() external {
        require(
            recoveryInitiated == 0, "RecoverySpell: Recovery already initiated"
        );

        bool ownerFound;
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == msg.sender) {
                ownerFound = true;
                break;
            }
        }
        require(ownerFound, "RecoverySpell: Sender is not an owner");
        recoveryInitiated = block.timestamp;

        emit RecoveryInitiated(block.timestamp, msg.sender);
    }

    /// @notice execute the recovery process, can only be called
    /// after the recovery delay has passed, and the recovery
    /// has been initiated. Callable by any address
    /// @param previousModule the address of the previous recovery module
    function executeRecovery(address previousModule) external {
        /// checks
        require(
            block.timestamp >= recoveryInitiated + delay,
            "RecoverySpell: Recovery not ready"
        );

        address[] memory newOwners = owners;
        address[] memory existingOwners = safe.getOwners();
        uint256 existingOwnersLength = existingOwners.length;

        IMulticall3.Call3[] memory calls3 =
            new IMulticall3.Call3[](newOwners.length + existingOwnersLength + 2);

        /// effects
        /// now impossible to call initiate recovery as owners array is empty
        delete owners;

        /// array length is set to 0
        /// impossible for executeRecovery to be callable again as the
        /// require check will always revert with a math overflow error
        recoveryInitiated = type(uint256).max;

        /// index for the call3 array
        uint256 index = 0;

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

        for (uint256 i = 1; i < newOwners.length; i++) {
            calls3[index++].callData = abi.encodeWithSelector(
                OwnerManager.addOwnerWithThreshold.selector, newOwners[i], 1
            );
        }

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

        /// @notice
        /// if the previous module is incorrect, this function will fail

        ///
        /// interactions
        ///
        /// execute all actions in the following order:
        ///   1). remove all but final existing owner, set owner threshold to 1
        ///   2). swap final existing owner for the first new owner
        ///   3). add the remaining new owners to the safe
        ///   4). set the safe's threshold to the new threshold
        ///   5). remove the recovery module from the safe
        require(
            safe.execTransactionFromModule(
                multicall3,
                0,
                abi.encodeWithSelector(IMulticall3.aggregate3.selector, calls3),
                Enum.Operation.DelegateCall
            ),
            "RecoverySpell: Remove recovery module failed"
        );

        emit SafeRecovered(block.timestamp);
    }
}
