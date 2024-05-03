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
/// This guard also restricts changing owners and modules It enforce
/// that the owners and modules remain the same after a transaction is
/// executed. If there is any changes, transactions are reverted

/// Config:
///  - the timelock must be a module of the safe to enact changes to the owners and modules
///  - the safe must not be the only executor on the timelock, otherwise the safe could be
///  locked out of making changes, except dark spells

/// checks that no new modules were added or removed by a transaction
/// uses TSTORE/TLOAD to store the current state of the modules
/// iterate over modules starting at the sentinel address, then go through the linked list
/// until the end is reached, storing the address of each module in a TSTORE slot
/// store the number of modules in another TSTORE slot

/// checks that no new owners were added or removed by a transaction
/// uses getOwners() method for this
/// then store the owners in TSTORE slots

/// after the transaction in checkAfterExecution, check that the number of modules
/// and the actual module addresses are the same
/// check that the owners are the same

/// Blocks all delegate calls, as the owners and modules could be changed.
/// Does not allow changing of the implementation contract either through
/// a normal safe transaction.
/// The implementation contract can still be upgraded through the timelock
/// using module calls back into the safe with a delegatecall.

///
///    ----------------------------
///    | Transient Storage Layout |
///    ----------------------------
///
///   OWNER LENGTH SLOT: keccak256("OWNER_LENGTH_SLOT")
///     bc7e8d41d75c307c01ea641eda963f96ac09a6542df3a05c010a2fd29d630d82
///
///   MODULE LENGTH SLOT: keccak256("MODULE_LENGTH_SLOT")
///     bde7218dcb21739a1aaca037623a8b8214be11b3dfd84faa6057b1c05ed1c1c7
///
///   PROXY IMPL SLOT: keccak256("PROXY_IMPL_SLOT")
///     f4960e73deed6441b1be092948373dda9c9143f60826d8929193d006148a875e
///
///    OWNER TSTORE OFFSET: 0
///        Owner: 0x388C818CA8B9251b393131C08a736A67ccB19297
///        data: abi.encode(owner, OWNER_TSTORE_OFFSET) => 0x000000000000000000000000388c818ca8b9251b393131c08a736a67ccb192970000000000000000000000000000000000000000000000000000000000000000
///        hash: keccak256(data) => 0xd6a6c19fc1a19d228284c0c19a930aa3ae80b6cbdaafbca10ae2ef8fd16f0eca
///
///    MODULE TSTORE OFFSET: 1
///        Module: 0x55F772c952f9d040C2b1d2E896Ad4BD2C84d70ee
///        data: abi.encode(module, MODULE_TSTORE_OFFSET) => 00000000000000000000000055f772c952f9d040c2b1d2e896ad4bd2c84d70ee0000000000000000000000000000000000000000000000000000000000000001
///        hash: keccak256(data) => 0x36e88d08a3a3be0e16d482ab0136429625bd305e6614234840d96ab0d091eb48
///

contract TimeRestricted is BaseGuard {
    using BytesHelper for bytes;
    using BokkyPooBahsDateTimeLibrary for uint256;
    using EnumerableSet for EnumerableSet.UintSet;

    /// @notice storage slot for the guard
    /// keccak256("guard_manager.guard.address")
    uint256 private constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @notice storage slot for the fallback handler
    /// keccak256("fallback_manager.handler.address")
    uint256 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    /// @notice storage slot for the singleton contract address
    uint256 private constant SINGLETON_STORAGE_SLOT = 0;

    /// @notice sentinel modules address
    address private constant SENTINEL_MODULES = address(0x1);

    /// @notice TSTORE slot for the number of owners
    uint256 public constant OWNER_LENGTH_SLOT =
        uint256(keccak256("OWNER_LENGTH_SLOT"));

    /// @notice TSTORE slot for the number of modules
    uint256 public constant MODULE_LENGTH_SLOT =
        uint256(keccak256("MODULE_LENGTH_SLOT"));

    /// @notice TSTORE slot for proxy implementation
    uint256 public constant PROXY_IMPL_SLOT =
        uint256(keccak256("PROXY_IMPL_SLOT"));

    /// @notice the number of modules to retrieve in a single call
    uint256 public constant PAGE_SIZE = 10;

    /// @notice TSTORE slot salt for the stored owners
    uint256 public constant OWNER_TSTORE_OFFSET = 0;

    /// @notice TSTORE slot salt for the stored modules
    uint256 public constant MODULE_TSTORE_OFFSET = 1;

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

    /// @notice allowed days to interact with the contract
    mapping(address safe => EnumerableSet.UintSet allowedDay) private
        _allowedDays;

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
    function safeDaysEnabled(address safe)
        public
        view
        returns (uint256[] memory)
    {
        return _allowedDays[safe].values();
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

        /// if not in currently allowed day, return false as there will be no allowed hours
        if (!_allowedDays[safe].contains(dayOfWeek)) {
            return false;
        }

        /// only allocate memory and read from storage if the day is allowed
        TimeRange memory time = dayTimeRanges[safe][dayOfWeek];

        /// actions are restricted to day and time windows
        return hour >= time.startHour && hour <= time.endHour;
    }

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ----------------- Safe Hooks ------------------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

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
        Enum.Operation operationType,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external {
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

        {
            address[] memory owners = Safe(payable(msg.sender)).getOwners();
            uint256 ownerLength = owners.length;
            uint256 ownerSlot = OWNER_LENGTH_SLOT;

            // store the number of owners in a TSTORE slot
            assembly {
                tstore(ownerSlot, ownerLength)
            }

            for (uint256 i = 0; i < ownerLength; i++) {
                // store owners in TSTORE slots
                uint256 ownerAddress = uint256(
                    keccak256(abi.encode(owners[i], OWNER_TSTORE_OFFSET))
                );
                assembly {
                    tstore(ownerAddress, 1)
                }
            }
        }

        /// ensure the safe contract is not upgraded
        {
            bytes memory singletonBytesPreExecution = Safe(payable(msg.sender))
                .getStorageAt(SINGLETON_STORAGE_SLOT, 1);

            uint256 singletonPreExecution =
                uint256(singletonBytesPreExecution.getFirstWord());

            _tstoreValueDirect(PROXY_IMPL_SLOT, singletonPreExecution);
        }

        /// store modules in transient storage
        /// store number of modules in transient storage
        _traverseModules(
            SENTINEL_MODULES, 0, _tstoreValueModule, _tstoreValueDirect
        );
    }

    /// @notice no-op function, required by the Guard interface.
    /// No checks needed after the tx has been executed.
    /// The pre-checks are enough to ensure the transaction is valid.
    function checkAfterExecution(bytes32, bool success) external {
        /// if the transaction failed, no need to waste gas on further checks
        if (!success) return;

        /// check that the guard did not change
        {
            bytes memory guardBytesPostExecution =
                Safe(payable(msg.sender)).getStorageAt(GUARD_STORAGE_SLOT, 1);

            address guardPostExecution = address(
                uint160(uint256(guardBytesPostExecution.getFirstWord()))
            );

            require(
                guardPostExecution == address(this),
                "TimeRestricted: cannot remove guard"
            );
        }

        /// check that fallback handler did not get set
        {
            bytes memory fallBackHandlerBytesPostExecution = Safe(
                payable(msg.sender)
            ).getStorageAt(FALLBACK_HANDLER_STORAGE_SLOT, 1);

            address fallbackHandlerPostExecution = address(
                uint160(
                    uint256(fallBackHandlerBytesPostExecution.getFirstWord())
                )
            );

            require(
                fallbackHandlerPostExecution == address(0),
                "TimeRestricted: cannot add fallback handler"
            );
        }

        /// check that the safe contract did not upgrade its implementation
        {
            bytes memory singletonBytesPostExecution = Safe(payable(msg.sender))
                .getStorageAt(SINGLETON_STORAGE_SLOT, 1);

            uint256 singletonPostExecution =
                uint256(singletonBytesPostExecution.getFirstWord());

            _checktStoreValueDirect(PROXY_IMPL_SLOT, singletonPostExecution);
        }

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
            uint256 ownerAddress =
                uint256(keccak256(abi.encode(owners[i], OWNER_TSTORE_OFFSET)));
            _checktStoreValueDirect(ownerAddress, 1);
        }

        /// check the modules in TSTORE slots, ensuring they are all 1
        /// check the value of total modules in TSTORE slots, ensuring before and after is the same
        /// if both of these are true, it means there were no changes made to the modules
        _traverseModules(
            SENTINEL_MODULES,
            0,
            _checktTstoreValueModule,
            _checktStoreValueDirect
        );
    }

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ------------ External Mutative Functions ------------
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
    function removeAllowedDay(address safe, uint8 dayOfWeek)
        external
        onlyTimelock(safe)
    {
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
            safe, dayOfWeek, oldTime.startHour, oldTime.endHour
        );
    }

    /// @notice removes all time restrictions for the safe
    /// callable only by the timelock
    /// @param safe address of the safe to disable the guard for
    function disableGuard(address safe) external onlyTimelock(safe) {
        uint256[] memory allowedDays = _allowedDays[safe].values();

        for (uint256 i = 0; i < allowedDays.length; i++) {
            delete dayTimeRanges[safe][uint8(allowedDays[i])];
            /// should not be possible to reach this path
            require(
                _allowedDays[safe].remove(uint8(allowedDays[i])),
                "day not allowed to be removed"
            );
        }

        emit GuardDisabled(safe);
    }

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// ----------------- Internal Helpers ------------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice recursively traverse through all modules by asking the Safe for its
    /// modules in a paginated manner, storing the module addresses in TSTORE slots
    /// and finally storing the total number of module addresses in a TSTORE slot.
    /// Algorithm:
    ///     query for 10 modules at a time, starting at sentinel address
    ///     if the number of modules is less than 10, store the number of modules and total number of module addresses
    ///     else, recurse with the next address and the total number of modules found so far
    function _traverseModules(
        address start,
        uint256 moduleAmountFound,
        function(uint256, uint256) internal moduleOperation,
        function(uint256, uint256) internal moduleLengthOperation
    ) internal {
        (address[] memory modules, address next) =
            Safe(payable(msg.sender)).getModulesPaginated(start, PAGE_SIZE);
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
                MODULE_LENGTH_SLOT, moduleAmountFound + modules.length
            );
        } else {
            /// add found modules to the total amount of modules found so far
            /// and continue recursion without writing to transient storage
            return _traverseModules(
                next,
                modules.length + moduleAmountFound,
                moduleOperation,
                moduleLengthOperation
            );
        }
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

    /// -----------------------------------------------------
    /// -----------------------------------------------------
    /// -------------- Transient Storage Ops ----------------
    /// -----------------------------------------------------
    /// -----------------------------------------------------

    /// @notice stores an address for a module in the module mapping
    /// @param slot address to store the value in,
    /// will then have slot calculated from it
    /// @param value value to store in the slot
    function _tstoreValueModule(uint256 slot, uint256 value) internal {
        uint256 calculatedSlot =
            uint256(keccak256(abi.encode(slot, MODULE_TSTORE_OFFSET)));

        _tstoreValueDirect(calculatedSlot, value);
    }

    /// @notice stores a value in transient storage
    /// @param slot to store the value in
    /// @param value value to store in the slot
    function _tstoreValueDirect(uint256 slot, uint256 value) internal {
        assembly {
            tstore(slot, value)
        }
    }

    /// @notice checks whether an address for a module is stored in
    /// the module mapping
    /// @param slot address to check the value in
    /// @param value expected in the given slot
    function _checktTstoreValueModule(uint256 slot, uint256 value)
        internal
        view
    {
        uint256 calculatedSlot =
            uint256(keccak256(abi.encode(slot, MODULE_TSTORE_OFFSET)));

        _checktStoreValueDirect(calculatedSlot, value);
    }

    /// @notice checks whether a value is stored in a transient slot
    /// @param slot to check the value in
    /// @param value expected in the given slot
    function _checktStoreValueDirect(uint256 slot, uint256 value)
        internal
        view
    {
        uint256 storedValue;

        assembly {
            storedValue := tload(slot)
        }

        require(storedValue == value, "TimeRestricted: value mismatch");
    }
}
