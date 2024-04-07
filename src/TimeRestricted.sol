pragma solidity 0.8.19;

import {EnumerableSet} from "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {BaseGuard} from "@safe/base/GuardManager.sol";
import {Enum} from "@safe/common/Enum.sol";

import {BokkyPooBahsDateTimeLibrary} from "src/calendar/BokkyPooBahsDateTimeLibrary.sol";

/// @title TimeRestricted contract that restricts
/// contract interaction to a specific time range
contract TimeRestricted is BaseGuard {
    using BokkyPooBahsDateTimeLibrary for uint256;
    using EnumerableSet for EnumerableSet.UintSet;

    /// @notice allowed days to interact with the contract
    mapping(address safe => EnumerableSet.UintSet allowedDay)
        private _allowedDays;

    struct TimeRange {
        /// @notice start hour of the allowed time range
        uint8 startHour;
        /// @notice end hour of the allowed time range
        uint8 endHour;
    }

    /// @notice hours allowed to interact with the contract for each given day
    mapping(address safe => mapping(uint8 dayOfWeek => TimeRange allowedHours))
        public dayTimeRanges;

    /// @notice Emitted when a time range is added to the allowed days
    /// @param safe address of the safe
    /// @param dayOfWeek day of the week to modify transactions allow time
    /// @param startHour start hour of the allowed time range
    /// @param endHour end hour of the allowed time range
    event TimeRangeAdded(
        address indexed safe,
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
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
        address indexed safe,
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    );

    /// @notice Emitted when the guard is removed from a safe
    event GuardDisabled(address indexed safe);

    /// @notice returns whether or not the safe has this guard enabled
    /// if no days are set, even if this contract is set as a guard,
    /// all actions are allowed.
    function safeEnabled(address safe) public view returns (bool) {
        return _allowedDays[safe].length() != 0;
    }

    /// @notice returns whether or not a transaction is allowed
    /// @param safe address of the safe
    /// @param timestamp timestamp of the transaction
    function transactionAllowed(
        address safe,
        uint256 timestamp
    ) public view returns (bool) {
        /// the following downcasts to uint8 are safe because
        /// getDayOfWeek() returns values in the range of [1, 7], inclusive, and
        /// getHour() returns values in the range of [0, 23], inclusive
        uint8 dayOfWeek = uint8(timestamp.getDayOfWeek());
        uint8 hour = uint8(timestamp.getHour());

        TimeRange memory time = dayTimeRanges[safe][dayOfWeek];

        /// if safe is not enabled, all actions are allowed
        if (!safeEnabled(safe)) {
            return true;
        }

        /// otherwise actions are restricted to day and time windows
        return
            hour >= time.startHour &&
            hour <= time.endHour &&
            _allowedDays[safe].contains(dayOfWeek);
    }

    /// @notice primitive contract that restricts interaction
    /// to only a specific time range in specified days.
    /// no granularity to specify different hours for different allowed days.
    /// all allowed days have the same allowed hours.
    function checkTransaction(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external view {
        /// If a safe has no allowed days, all actions are allowed
        /// once the safe has allowed days, transactions can only
        /// execute within the allowed hours.
        /// Prevents a flow where a safe adds TimeRestricted as a guard,
        /// and then does not add any allowed days, effectively locking
        /// the safe from any further transactions, forever.
        require(
            transactionAllowed(msg.sender, block.timestamp),
            "transaction outside of allowed hours"
        );
    }

    /// @notice no-op function, required by the Guard interface.
    /// No checks needed after the tx has been executed.
    /// The pre-checks are enough to ensure the transaction is valid.
    function checkAfterExecution(bytes32, bool) external pure {}

    /// @notice callable by a safe, adds a time range to the allowed days
    /// for the safe to execute transactions
    /// @param dayOfWeek day of the week to allow transactions
    /// - valid range [1, 7]
    /// @param startHour start hour of the allowed time range
    /// - valid range: [0, 23]
    /// @param endHour end hour of the allowed time range
    /// - valid range: [0, 23]
    function addTimeRange(
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    ) external {
        require(dayOfWeek >= 1 && dayOfWeek <= 7, "invalid day of week");
        require(
            !_allowedDays[msg.sender].contains(dayOfWeek),
            "day already allowed"
        );
        require(endHour <= 23, "invalid end hour");
        require(startHour < endHour, "invalid time range");

        _allowedDays[msg.sender].add(dayOfWeek);

        TimeRange storage time = dayTimeRanges[msg.sender][dayOfWeek];

        time.startHour = startHour;
        time.endHour = endHour;

        emit TimeRangeAdded(msg.sender, dayOfWeek, startHour, endHour);
    }

    /// @notice callable by a safe, updates the time range for the allowed days
    /// @param dayOfWeek day of the week to allow transactions
    /// @param startHour start hour of the allowed time range
    /// @param endHour end hour of the allowed time range
    /// must allow at least a 1 hour window for transactions be executed
    function editTimeRange(
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    ) external {
        require(endHour <= 23, "invalid end hour");
        require(startHour < endHour, "invalid time range");
        require(dayOfWeek >= 1 && dayOfWeek <= 7, "invalid day of week");
        require(
            _allowedDays[msg.sender].contains(dayOfWeek),
            "day not allowed"
        );

        TimeRange memory oldTime = dayTimeRanges[msg.sender][dayOfWeek];

        TimeRange storage currentTime = dayTimeRanges[msg.sender][dayOfWeek];
        currentTime.startHour = startHour;
        currentTime.endHour = endHour;

        emit TimeRangeUpdated(
            msg.sender,
            dayOfWeek,
            oldTime.startHour,
            startHour,
            oldTime.endHour,
            endHour
        );
    }

    /// @notice remove an allowed day from the safe. This will remove
    /// the time range for the day. Cannot remove all allowed days.
    /// There must always be at least a single day allowed.
    function removeAllowedDay(uint8 dayOfWeek) external {
        require(dayOfWeek >= 1 && dayOfWeek <= 7, "invalid day of week");

        TimeRange memory oldTime = dayTimeRanges[msg.sender][dayOfWeek];
        delete dayTimeRanges[msg.sender][dayOfWeek];

        require(
            _allowedDays[msg.sender].remove(dayOfWeek),
            "day not allowed to be removed"
        );

        /// safe is not allowed to remove all allowed days
        /// if there are no allowed days, all actions are allowed
        /// if a safe wants to disable this guard, it can call disableGuard
        assert(_allowedDays[msg.sender].length() != 0);

        emit TimeRangeDeleted(
            msg.sender,
            dayOfWeek,
            oldTime.startHour,
            oldTime.endHour
        );
    }

    /// @notice removes all time restrictions for the safe
    function disableGuard() external {
        uint256[] memory allowedDays = _allowedDays[msg.sender].values();

        for (uint256 i = 0; i < allowedDays.length; i++) {
            delete dayTimeRanges[msg.sender][uint8(allowedDays[i])];
            require(
                _allowedDays[msg.sender].remove(uint8(allowedDays[i])),
                "day not allowed to be removed"
            );
        }

        emit GuardDisabled(msg.sender);
    }
}
