pragma solidity 0.8.25;

import {BokkyPooBahsDateTimeLibrary} from
    "src/calendar/BokkyPooBahsDateTimeLibrary.sol";
import {EnumerableSet} from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {BaseGuard} from "@safe/base/GuardManager.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

import {BytesHelper} from "src/BytesHelper.sol";

/// @notice Only the timelock can add, edit, remove or disable
/// time ranges after initialization.
/// Contract that restricts Safe interactions to a specific time range
/// This guard also restricts changing owners and modules. It enforces
/// that the owners and modules remain the same after a transaction is
/// executed. If there is any changes, transactions are reverted.

/// Config:
///  - the timelock must be a module of the safe to enact changes to the owners and modules
///  - the safe must not be the only executor on the timelock, otherwise the safe could be
///  locked out of making changes, except dark spells

/// no new modules, upgrades, owners, or fallback handlers can added or
/// removed by a transaction because all self calls are disallowed.
/// this implies that the only way these values can be set are through
/// the timelock, which can call back into the safe and use delegatecall
/// if needed.

/// after the transaction in checkAfterExecution, check that the number of modules
/// and the actual module addresses are the same
/// check that the owners are the same

/// Blocks all delegate calls, as the owners and modules could be changed.
/// Does not allow changing of the implementation contract either through
/// a normal safe transaction.
/// The implementation contract can still be upgraded through the timelock
/// using module calls back into the safe with a delegatecall.

contract TimeRestricted is BaseGuard {
    using BytesHelper for bytes;
    using BokkyPooBahsDateTimeLibrary for uint256;
    using EnumerableSet for EnumerableSet.UintSet;

    /// @notice storage slot for the fallback handler
    /// keccak256("fallback_manager.handler.address")
    uint256 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    /// @notice set of allowed days for a safe
    uint256 public constant MAX_DAYS = 7;

    /// @notice period in 24 hour time range
    struct TimeRange {
        /// @notice start hour of the allowed time range
        uint8 startHour;
        /// @notice end hour of the allowed time range
        uint8 endHour;
    }

    /// @notice hours allowed to interact with the contract for each given day
    /// there can only be a single periods per day that transactions can be proposed
    mapping(address safe => mapping(uint8 dayOfWeek => TimeRange allowedHours))
        public dayTimeRanges;

    /// @notice mapping of safe to authorized timelock that can add time ranges
    mapping(address safe => address timelock) public authorizedTimelock;

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

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ---------------- Initialize Function ----------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice initialize configuration for a safe as the gnosis safe
    /// @param timelock address of the timelock that can add time ranges
    /// @param timeRanges array of time ranges to allow transactions
    /// @param allowedDays corresponding array of days to allow transactions
    function initializeConfiguration(
        address timelock,
        TimeRange[] calldata timeRanges,
        uint8[] calldata allowedDays
    ) external {
        require(
            timeRanges.length == allowedDays.length,
            "TimeRestricted: arity mismatch"
        );
        require(!safeEnabled(msg.sender), "TimeRestricted: already initialized");
        require(
            authorizedTimelock[msg.sender] == address(0),
            "TimeRestricted: timelock already set"
        );
        require(msg.sender.code.length != 0, "TimeRestricted: invalid safe");
        require(timelock.code.length != 0, "TimeRestricted: invalid timelock");
        require(
            timelock != msg.sender, "TimeRestricted: safe cannot equal timelock"
        );

        authorizedTimelock[msg.sender] = timelock;

        /// it's really hard to reason about what a fallback handler could do
        /// so do not accept a safe that has an active fallback handler to
        /// initialize itself with this guard.
        bytes memory fallBackHandlerBytes = Safe(payable(msg.sender))
            .getStorageAt(FALLBACK_HANDLER_STORAGE_SLOT, 1);

        address fallbackHandler =
            address(uint160(uint256(fallBackHandlerBytes.getFirstWord())));

        require(
            fallbackHandler == address(0),
            "TimeRestricted: cannot initialize with fallback handler"
        );

        for (uint256 i = 0; i < timeRanges.length; i++) {
            _addTimeRange(
                msg.sender,
                allowedDays[i],
                timeRanges[i].startHour,
                timeRanges[i].endHour
            );
        }
    }

    /// @notice modifier that restricts access to the timelock
    modifier onlyTimelock(address safe) {
        require(
            authorizedTimelock[safe] == msg.sender,
            "TimeRestricted: only timelock"
        );
        _;
    }

    /// @notice returns whether or not the safe has this guard enabled
    /// if no days are set, even if this contract is set as a guard,
    /// all actions are allowed.
    /// @param safe to check if the guard is enabled
    /// returns true if one or more days are allowed
    function safeEnabled(address safe) public view returns (bool) {
        for (uint256 i = 1; i <= MAX_DAYS; i++) {
            if (dayTimeRanges[safe][uint8(i)].endHour != 0) {
                return true;
            }
        }

        /// no days set, all actions allowed
        return false;
    }

    /// @notice returns the number of allowed days for a safe per week.
    /// @param safe to retrieve current allowed days
    function numDaysEnabled(address safe) public view returns (uint256) {
        uint256 daysEnabled = 0;
        for (uint256 i = 1; i <= MAX_DAYS; i++) {
            if (dayTimeRanges[safe][uint8(i)].endHour != 0) {
                daysEnabled++;
            }
        }

        return daysEnabled;
    }

    /// @notice returns array of safe days enabled for a user
    /// Day 1 is Monday, 7 is Sunday
    /// should never have duplicates
    /// @param safe to retrieve current allowed days
    function safeDaysEnabled(address safe)
        public
        view
        returns (uint256[] memory)
    {
        uint256[] memory daysEnabled = new uint256[](numDaysEnabled(safe));
        uint256 index = 0;

        for (uint256 i = 1; i <= MAX_DAYS; i++) {
            if (dayTimeRanges[safe][uint8(i)].endHour != 0) {
                daysEnabled[index] = i;
                index++;
            }
        }

        return daysEnabled;
    }

    /// @notice returns whether or not a transaction is allowed
    /// @param safe address of the safe
    /// @param timestamp timestamp of the transaction
    function transactionAllowed(address safe, uint256 timestamp)
        public
        view
        returns (bool)
    {
        /// if safe is not enabled, all actions are allowed
        if (!safeEnabled(safe)) {
            return true;
        }

        /// the following downcasts to uint8 are safe because
        /// getDayOfWeek() returns values in the range of [1, 7], inclusive, and
        /// getHour() returns values in the range of [0, 23], inclusive
        uint8 dayOfWeek = uint8(timestamp.getDayOfWeek());
        uint8 hour = uint8(timestamp.getHour());

        /// only allocate memory and read from storage if the day is allowed
        TimeRange memory time = dayTimeRanges[safe][dayOfWeek];

        /// if not in currently allowed day, return false as there will be no allowed hours
        if (time.endHour == 0) {
            return false;
        }

        /// actions are restricted to day and time windows
        return hour >= time.startHour && hour <= time.endHour;
    }

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ----------------- Safe Hooks ------------------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice function that restricts Gnosis Safe interaction
    /// to only a specific time range in specified days.
    /// no granularity to specify different hours for different allowed days.
    /// all allowed days have the same allowed hours.
    function checkTransaction(
        address to,
        uint256,
        bytes memory,
        Enum.Operation operationType,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external view {
        require(to != msg.sender, "TimeRestricted: no self calls");
        /// if delegate calls are allowed, owners or modules could be added
        /// or removed outside of the expected flow, and the only way to reason
        /// about this is to disallow delegate calls as we cannot prove unknown
        /// slots were not written to in the owner or modules mapping
        require(
            operationType == Enum.Operation.Call,
            "TimeRestricted: delegate call disallowed"
        );

        /// If a safe has no allowed days, all actions are allowed
        /// once the safe has allowed days, transactions can only
        /// execute within the allowed hours.
        /// Prevents a flow where a safe adds TimeRestricted as a guard,
        /// and then does not add any allowed days, effectively locking
        /// the safe from any further transactions, forever.
        require(
            transactionAllowed(msg.sender, block.timestamp),
            "TimeRestricted: transaction outside of allowed hours"
        );
    }

    /// @notice no-op function, required by the Guard interface.
    /// No checks needed after the tx has been executed.
    /// The pre-checks are enough to ensure the transaction is valid.
    function checkAfterExecution(bytes32, bool) external pure {}

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ------------ External Mutative Functions ------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice callable by a safe, adds a time range to the allowed days
    /// for the safe to execute transactions
    /// @param safe address of the safe to add the time range to
    /// @param dayOfWeek day of the week to allow transactions
    /// - valid range [1, 7]
    /// @param startHour start hour of the allowed time range
    /// - valid range: [0, 23]
    /// @param endHour end hour of the allowed time range
    /// - valid range: [0, 23]
    function addTimeRange(
        address safe,
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    ) external onlyTimelock(safe) {
        _addTimeRange(safe, dayOfWeek, startHour, endHour);
    }

    /// @notice callable by a safe, updates the time range for the allowed days
    /// @param safe address of the safe
    /// @param dayOfWeek day of the week to allow transactions
    /// @param startHour start hour of the allowed time range
    /// @param endHour end hour of the allowed time range
    /// must allow at least a 1 hour window for transactions be executed
    function editTimeRange(
        address safe,
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    ) external onlyTimelock(safe) {
        require(endHour <= 23, "TimeRestricted: invalid end hour");
        require(startHour < endHour, "TimeRestricted: invalid time range");
        require(dayOfWeek >= 1 && dayOfWeek <= 7, "TimeRestricted: invalid day of week");

        TimeRange memory oldTime = dayTimeRanges[safe][dayOfWeek];

        require(oldTime.endHour != 0, "TimeRestricted: day not allowed");

        TimeRange storage currentTime = dayTimeRanges[safe][dayOfWeek];
        currentTime.startHour = startHour;
        currentTime.endHour = endHour;

        emit TimeRangeUpdated(
            safe,
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
    /// @param safe address of the safe to remove the allowed day from
    /// @param dayOfWeek day of the week to remove
    function removeAllowedDay(address safe, uint8 dayOfWeek)
        external
        onlyTimelock(safe)
    {
        require(dayOfWeek >= 1 && dayOfWeek <= MAX_DAYS, "TimeRestricted: invalid day of week");

        TimeRange memory oldTime = dayTimeRanges[safe][dayOfWeek];

        require(oldTime.endHour != 0, "TimeRestricted: day not allowed");

        delete dayTimeRanges[safe][dayOfWeek];

        /// safe is not allowed to remove all allowed days
        /// if there are no allowed days, all actions are allowed
        /// if a safe wants to disable this guard, it can call disableGuard
        assert(numDaysEnabled(safe) != 0);

        emit TimeRangeDeleted(
            safe, dayOfWeek, oldTime.startHour, oldTime.endHour
        );
    }

    /// @notice removes all time restrictions for the safe
    /// callable only by the timelock
    /// @param safe address of the safe to disable the guard for
    function disableGuard(address safe) external onlyTimelock(safe) {
        uint256[] memory allowedDays = safeDaysEnabled(safe);

        for (uint256 i = 0; i < allowedDays.length; i++) {
            delete dayTimeRanges[safe][uint8(allowedDays[i])];
        }

        emit GuardDisabled(safe);
    }

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ----------------- Internal Helpers ------------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice callable by a safe, adds a time range to the allowed days
    /// for the safe to execute transactions
    /// @param safe address of the safe to add the time range to
    /// @param dayOfWeek day of the week to allow transactions
    /// - valid range [1, 7]
    /// @param startHour start hour of the allowed time range
    /// - valid range: [0, 23]
    /// @param endHour end hour of the allowed time range
    /// - valid range: [0, 23]
    function _addTimeRange(
        address safe,
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    ) private {
        TimeRange storage time = dayTimeRanges[safe][dayOfWeek];

        require(dayOfWeek >= 1 && dayOfWeek <= 7, "TimeRestricted: invalid day of week");
        require(time.endHour == 0, "day already allowed");
        require(endHour <= 23, "TimeRestricted: invalid end hour");
        require(startHour < endHour, "TimeRestricted: invalid time range");

        time.startHour = startHour;
        time.endHour = endHour;

        emit TimeRangeAdded(safe, dayOfWeek, startHour, endHour);
    }
}
