pragma solidity 0.8.25;

import {BokkyPooBahsDateTimeLibrary} from "src/calendar/BokkyPooBahsDateTimeLibrary.sol";
import {EnumerableSet} from "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {BaseGuard} from "@safe/base/GuardManager.sol";
import {Enum} from "@safe/common/Enum.sol";
import {Safe} from "@safe/Safe.sol";

import {BytesHelper} from "src/BytesHelper.sol";

/// @notice Only the timelock can add, edit, remove or disable
/// time ranges after initialization.
/// @title TimeRestricted contract that restricts
/// contract interaction to a specific time range
/// This guard also restricts changing owners and modules
/// It enforce that the owners and modules
/// remain the same after a transaction is executed
/// If there is any changes, transactions are reverted

/// Config:
///  - the timelock must be a module of the safe to enact changes to the owners and modules
///  - the safe must not be the only executor on the timelock, otherwise the safe could be
///  locked out of making changes, except dark spells

/// implements checks that no new modules were added or removed by a transaction
/// uses TSTORE/TLOAD to store the current state of the modules
/// iterate over modules starting at the sentinel address, then go through the linked list
/// until the end is reached, storing the address of each module in a TSTORE slot
/// store the number of modules in another TSTORE slot

/// implement checks that no new owners were added or removed by a transaction
/// uses getOwners() method for this
/// then store the owners in TSTORE slots

/// after the transaction in checkAfterExecution, check that the number of modules
/// and the actual module addresses are the same
/// check that the owners are the same

contract TimeRestricted is BaseGuard {
    using BytesHelper for bytes;
    using BokkyPooBahsDateTimeLibrary for uint256;
    using EnumerableSet for EnumerableSet.UintSet;

    /// @notice allowed days to interact with the contract
    mapping(address safe => EnumerableSet.UintSet allowedDay)
        private _allowedDays;

    /// @notice storage slot for the guard
    uint256 internal constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @notice sentinel modules address
    address internal constant SENTINEL_MODULES = address(0x1);

    /// @notice TSTORE slot for the number of owners
    uint256 public constant OWNER_LENGTH_SLOT =
        uint256(keccak256("OWNER_LENGTH_SLOT"));

    /// @notice TSTORE slot for the number of modules
    uint256 public constant MODULE_LENGTH_SLOT =
        uint256(keccak256("MODULE_LENGTH_SLOT"));

    /// @notice the number of modules to retrieve in a single call
    uint256 public constant PAGE_SIZE = 10;

    struct TimeRange {
        /// @notice start hour of the allowed time range
        uint8 startHour;
        /// @notice end hour of the allowed time range
        uint8 endHour;
    }

    /// @notice hours allowed to interact with the contract for each given day
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
    /// @param safe address of the safe
    event GuardDisabled(address indexed safe);

    /// @notice modifier that restricts access to the timelock
    modifier onlyTimelock(address safe) {
        require(
            authorizedTimelock[safe] == msg.sender,
            "TimeRestricted: only timelock"
        );
        _;
    }

    /// @notice initialize configuration for a safe as the gnosis safe
    /// @param timelock address of the timelock that can add time ranges
    /// @param timeRanges array of time ranges to allow transactions
    /// @param allowedDays corresponding array of days to allow transactions
    function initializeConfiguration(
        address timelock,
        TimeRange[] memory timeRanges,
        uint8[] memory allowedDays
    ) external {
        require(
            timeRanges.length == allowedDays.length,
            "TimeRestricted: arity mismatch"
        );
        require(
            !safeEnabled(msg.sender),
            "TimeRestricted: already initialized"
        );
        require(
            authorizedTimelock[msg.sender] == address(0),
            "TimeRestricted: timelock already set"
        );
        require(msg.sender.code.length != 0, "TimeRestricted: invalid safe");
        require(timelock.code.length != 0, "TimeRestricted: invalid timelock");
        require(
            timelock != msg.sender,
            "TimeRestricted: safe cannot equal timelock"
        );

        authorizedTimelock[msg.sender] = timelock;

        unchecked {
            for (uint256 i = 0; i < timeRanges.length; i++) {
                _addTimeRange(
                    msg.sender,
                    allowedDays[i],
                    timeRanges[i].startHour,
                    timeRanges[i].endHour
                );
            }
        }
    }

    /// @notice returns whether or not the safe has this guard enabled
    /// if no days are set, even if this contract is set as a guard,
    /// all actions are allowed.
    function safeEnabled(address safe) public view returns (bool) {
        return _allowedDays[safe].length() != 0;
    }

    /// @notice returns the number of allowed days for a safe per week.
    /// @param safe to retrieve current allowed days
    function numDaysEnabled(address safe) public view returns (uint256) {
        return _allowedDays[safe].length();
    }

    /// @notice returns array of safe days enabled for a user
    /// Day 1 is Monday, 7 is Sunday
    /// should never have duplicates
    /// @param safe to retrieve current allowed days
    function safeDaysEnabled(
        address safe
    ) public view returns (uint256[] memory) {
        return _allowedDays[safe].values();
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
    /// Stores the current modules and owners in transient storage
    /// If these change, then the transaction is reverted.
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
    ) external {
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

        {
            address[] memory owners = Safe(payable(msg.sender)).getOwners();
            uint256 ownerLength = owners.length;
            uint256 ownerSlot = OWNER_LENGTH_SLOT;

            assembly {
                tstore(ownerSlot, ownerLength)
            }

            for (uint256 i = 0; i < ownerLength; i++) {
                uint256 ownerAddress = uint256(uint160(owners[i]));
                // store owners in TSTORE slots
                // store the number of owners in another TSTORE slot
                assembly {
                    tstore(ownerAddress, 1)
                }
            }
        }

        /// store modules in transient storage
        /// store number of modules in transient storage
        _traverseModules(SENTINEL_MODULES, tstoreValue, tstoreValue);
    }

    function tstoreValue(uint256 slot, uint256 value) internal {
        assembly {
            tstore(slot, value)
        }
    }

    function checktTstoreValue(uint256 slot, uint256 value) internal view {
        uint256 storedValue;
        assembly {
            storedValue := tload(slot)
        }

        require(storedValue == value, "TimeRestricted: value mismatch");
    }

    /// @notice recursively traverse through all modules by asking the Safe for its
    /// modules in a paginated manner, storing the module addresses in TSTORE slots
    /// and finally storing the total number of module addresses in a TSTORE slot.
    /// Algorithm:
    ///     query for 10 modules at a time, starting at sentinel address
    ///     if the number of modules is less than 10, store the number of modules and total number of module addresses
    ///     else, recurse with the next address and the total number of modules found so far
    function _traverseModules(
        address start,
        function(uint256, uint256) internal moduleOperation,
        function(uint256, uint256) internal moduleLengthOperation
    ) internal returns (uint256 moduleAmountFound) {
        (address[] memory modules, address next) = Safe(payable(msg.sender))
            .getModulesPaginated(start, PAGE_SIZE);
        uint256 moduleLength = modules.length;

        for (uint256 i = 0; i < moduleLength; i++) {
            uint256 moduleAddress = uint256(uint160(modules[i]));
            // there should be no overlap between modules and owners so this operation is safe
            // store modules in TSTORE slots
            // store the number of modules in another TSTORE slot
            moduleOperation(moduleAddress, 1);
        }

        /// if next == modules[modules.length - 1], we need to recurse
        /// otherwise we are at the end of the modules list

        /// if there are less than page_size modules, or the next is
        /// the sentinel module, traversal ends
        if (modules.length < PAGE_SIZE || next == SENTINEL_MODULES) {
            moduleLengthOperation(
                MODULE_LENGTH_SLOT,
                moduleAmountFound + modules.length
            );

            return 0;
        } else {
            return
                _traverseModules(next, moduleOperation, moduleLengthOperation) +
                modules.length;
        }
    }

    /// @notice no-op function, required by the Guard interface.
    /// No checks needed after the tx has been executed.
    /// The pre-checks are enough to ensure the transaction is valid.
    function checkAfterExecution(bytes32, bool success) external {
        /// if the transaction failed, no need to waste gas on further checks
        if (!success) return;

        bytes memory guardBytesPostExecution = Safe(payable(msg.sender))
            .getStorageAt(GUARD_STORAGE_SLOT, 1);

        address guardPostExecution = address(
            uint160(uint256(guardBytesPostExecution.getFirstWord()))
        );

        require(
            guardPostExecution == address(this),
            "TimeRestricted: cannot remove guard"
        );

        address[] memory owners = Safe(payable(msg.sender)).getOwners();
        uint256 ownerLength;
        uint256 ownerSlot = OWNER_LENGTH_SLOT;

        assembly {
            ownerLength := tload(ownerSlot)
        }

        require(
            ownerLength == owners.length,
            "TimeRestricted: owners length changed"
        );

        for (uint256 i = 0; i < ownerLength; i++) {
            uint256 ownerAddress = uint256(uint160(owners[i]));
            uint256 found;
            // retrieve whether owners were stored from TSTORE slots
            assembly {
                found := tload(ownerAddress)
            }
            require(found == 1, "TimeRestricted: owner not found");
        }

        /// check the modules in TSTORE slots, ensuring they are all 1
        /// check the value of total modules in TSTORE slots, ensuring before and after is the same
        /// if both of these are true, it means there were no changes made to the modules
        _traverseModules(
            SENTINEL_MODULES,
            checktTstoreValue,
            checktTstoreValue
        );
    }

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
        require(dayOfWeek >= 1 && dayOfWeek <= 7, "invalid day of week");
        require(!_allowedDays[safe].contains(dayOfWeek), "day already allowed");
        require(endHour <= 23, "invalid end hour");
        require(startHour < endHour, "invalid time range");

        _allowedDays[safe].add(dayOfWeek);

        TimeRange storage time = dayTimeRanges[safe][dayOfWeek];

        time.startHour = startHour;
        time.endHour = endHour;

        emit TimeRangeAdded(safe, dayOfWeek, startHour, endHour);
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
        _editTimeRange(safe, dayOfWeek, startHour, endHour);
    }

    /// @notice callable by a safe, updates the time range for the allowed days
    /// @param safe address of the safe
    /// @param dayOfWeek day of the week to allow transactions
    /// @param startHour start hour of the allowed time range
    /// @param endHour end hour of the allowed time range
    /// must allow at least a 1 hour window for transactions be executed
    function _editTimeRange(
        address safe,
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    ) private {
        require(endHour <= 23, "invalid end hour");
        require(startHour < endHour, "invalid time range");
        require(dayOfWeek >= 1 && dayOfWeek <= 7, "invalid day of week");
        require(_allowedDays[safe].contains(dayOfWeek), "day not allowed");

        TimeRange memory oldTime = dayTimeRanges[safe][dayOfWeek];

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
    function removeAllowedDay(
        address safe,
        uint8 dayOfWeek
    ) external onlyTimelock(safe) {
        require(dayOfWeek >= 1 && dayOfWeek <= 7, "invalid day of week");

        TimeRange memory oldTime = dayTimeRanges[safe][dayOfWeek];
        delete dayTimeRanges[safe][dayOfWeek];

        require(
            _allowedDays[safe].remove(dayOfWeek),
            "day not allowed to be removed"
        );

        /// safe is not allowed to remove all allowed days
        /// if there are no allowed days, all actions are allowed
        /// if a safe wants to disable this guard, it can call disableGuard
        assert(_allowedDays[safe].length() != 0);

        emit TimeRangeDeleted(
            msg.sender,
            dayOfWeek,
            oldTime.startHour,
            oldTime.endHour
        );
    }

    /// @notice removes all time restrictions for the safe
    /// callable only by the timelock
    /// @param safe address of the safe to disable the guard for
    function disableGuard(address safe) external onlyTimelock(safe) {
        uint256[] memory allowedDays = _allowedDays[safe].values();

        for (uint256 i = 0; i < allowedDays.length; i++) {
            delete dayTimeRanges[safe][uint8(allowedDays[i])];
            require(
                _allowedDays[safe].remove(uint8(allowedDays[i])),
                "day not allowed to be removed"
            );
        }

        emit GuardDisabled(safe);
    }
}
