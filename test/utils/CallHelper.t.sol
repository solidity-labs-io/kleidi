pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

import {Guard} from "src/Guard.sol";
import {Timelock} from "src/Timelock.sol";

contract CallHelper is Test {
    /**
     * Guard events *
     */

    /// @notice Emitted when a time range is added to the allowed days
    /// @param safe address of the safe
    /// @param dayOfWeek day of the week to modify transactions allow time
    /// @param startHour start hour of the allowed time range
    /// @param endHour end hour of the allowed time range
    event TimeRangeAdded(
        address indexed safe, uint8 dayOfWeek, uint8 startHour, uint8 endHour
    );

    /// @notice Emitted when a time range is updated for the allowed days
    /// @param safe address of the safe
    /// @param dayOfWeek day of the week to modify transactions allow time
    /// @param oldStartHour old start hour of the allowed time range
    /// @param newStartHour new start hour of the allowed time range
    /// @param oldEndHour old end hour of the allowed time range
    /// @param newEndHour new end hour of the allowed time range
    event TimeRangeUpdated(
        address indexed safe,
        uint8 dayOfWeek,
        uint8 oldStartHour,
        uint8 newStartHour,
        uint8 oldEndHour,
        uint8 newEndHour
    );

    /// @notice Emitted when a time range is removed from the allowed days
    /// @param safe address of the safe
    /// @param dayOfWeek day of the week to remove
    /// @param startHour previous start hour of the allowed time range
    /// @param endHour previous end hour of the allowed time range
    event TimeRangeDeleted(
        address indexed safe, uint8 dayOfWeek, uint8 startHour, uint8 endHour
    );

    /// @notice Emitted when the guard is removed from a safe
    /// @param safe address of the safe
    event GuardDisabled(address indexed safe);

    /// @notice Emitted when the guard is added to a safe
    /// @param safe address of the safe
    event GuardEnabled(address indexed safe);

    /**
     * Timelock events *
     */

    /// @notice Emitted when a call is scheduled as part of operation `id`.
    /// @param id unique identifier for the operation
    /// @param index index of the call within the operation, non zero if not first call in a batch
    /// @param target the address of the contract to call
    /// @param value the amount of native asset to send with the call
    /// @param data the calldata to send with the call
    /// @param salt the salt to be used in the operation
    /// @param delay the delay before the operation becomes valid
    event CallScheduled(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data,
        bytes32 salt,
        uint256 delay
    );

    /// @notice Emitted when a call is performed as part of operation `id`.
    /// @param id unique identifier for the operation
    /// @param index index of the call within the operation, non zero if not first call in a batch
    /// @param target the address of the contract called
    /// @param value the amount of native asset sent with the call
    /// @param data the calldata sent with the call
    event CallExecuted(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data
    );

    /**
     * Guard helper functions to check emitted events *
     */
    function _initializeConfiguration(address caller, address guard) internal {
        vm.expectEmit(true, true, true, true, guard);
        emit GuardEnabled(caller);

        vm.prank(caller);
        Guard(guard).checkSafe();
    }

    /**
     * Timelock helper functions to check emitted events *
     */
    function _schedule(
        address caller,
        address timelock,
        address target,
        uint256 value,
        bytes memory data,
        bytes32 salt,
        uint256 delay
    ) internal {
        bytes32 id =
            Timelock(payable(timelock)).hashOperation(target, value, data, salt);
        vm.expectEmit(true, true, true, true, timelock);
        emit CallScheduled(id, 0, target, value, data, salt, delay);

        vm.prank(caller);
        Timelock(payable(timelock)).schedule(target, value, data, salt, delay);

        assertEq(
            Timelock(payable(timelock)).timestamps(id),
            block.timestamp + delay,
            "timestamps should equal block timestamp"
        );
    }

    function _scheduleBatch(
        address caller,
        address timelock,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory payloads,
        bytes32 salt,
        uint256 delay
    ) internal {
        bytes32 id = Timelock(payable(timelock)).hashOperationBatch(
            targets, values, payloads, salt
        );
        vm.expectEmit(true, true, true, true, timelock);
        for (uint256 i = 0; i < targets.length; ++i) {
            emit CallScheduled(
                id, i, targets[i], values[i], payloads[i], salt, delay
            );
        }

        vm.prank(caller);
        Timelock(payable(timelock)).scheduleBatch(
            targets, values, payloads, salt, delay
        );
    }

    function _execute(
        address caller,
        address timelock,
        address target,
        uint256 value,
        bytes memory payload,
        bytes32 salt
    ) internal {
        bytes32 id = Timelock(payable(timelock)).hashOperation(
            target, value, payload, salt
        );
        vm.expectEmit(true, true, true, true, timelock);
        emit CallExecuted(id, 0, target, value, payload);

        vm.prank(caller);
        Timelock(payable(timelock)).execute(target, value, payload, salt);
    }

    function _executeBatch(
        address caller,
        address timelock,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory payloads,
        bytes32 salt
    ) internal {
        bytes32 id = Timelock(payable(timelock)).hashOperationBatch(
            targets, values, payloads, salt
        );
        for (uint256 i = 0; i < targets.length; ++i) {
            vm.expectEmit(true, true, true, true, timelock);
            emit CallExecuted(id, i, targets[i], values[i], payloads[i]);
        }

        vm.prank(caller);
        Timelock(payable(timelock)).executeBatch(
            targets, values, payloads, salt
        );
    }

    function _executeWhiteListed(
        address caller,
        address timelock,
        address target,
        uint256 value,
        bytes memory payload
    ) internal {
        vm.expectEmit(true, true, true, true, timelock);
        emit CallExecuted(bytes32(0), 0, target, value, payload);

        vm.prank(caller);
        Timelock(payable(timelock)).executeWhitelisted(target, value, payload);
    }

    function _executeWhitelistedBatch(
        address caller,
        address timelock,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory payloads
    ) internal {
        for (uint256 i = 0; i < targets.length; ++i) {
            vm.expectEmit(true, true, true, true, timelock);
            emit CallExecuted(bytes32(0), i, targets[i], values[i], payloads[i]);
        }

        vm.prank(caller);
        Timelock(payable(timelock)).executeWhitelistedBatch(
            targets, values, payloads
        );
    }
}
