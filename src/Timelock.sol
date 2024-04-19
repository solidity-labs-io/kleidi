// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (governance/TimelockController.sol)

pragma solidity ^0.8.0;

import {AccessControlEnumerable} from "@openzeppelin-contracts/contracts/access/AccessControlEnumerable.sol";
import {IERC1155Receiver} from "@openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {EnumerableSet} from "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {IERC165} from "@openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";

import {CalldataList} from "src/CalldataList.sol";

import {Safe} from "@safe/Safe.sol";

/// @notice known issues:
/// - a malicious canceler can cancel proposals indefinitely,
// effectively locking funds forever.
/// - a dark spell could bypass all time checked restrictions
/// on proposing actions to the timelock.
/// - incorrectly formed whitelisted calldata can allow safe
/// owners the ability to steal funds. E.g. whitelist a calldata
/// to approve a token transfer to an address the safe owner
/// controls without checking the spender address.
/// - incorrect calldata can allow any safe owner to arbitrarily change
/// date/time restrictions on the multisig guard.
/// the owner must ensure no calldata is created that allows this.

/// @notice protocol invariants:
/// - there must always be at least 1 proposer
/// - there should be no whitelisted calldata checks for the timelock itself
/// this ensures there is no way to instantly make modifications to the
/// whitelisted timelock calldata.

/**
 * @dev Contract module which acts as a timelocked controller. When set as the
 * owner of an `Ownable` smart contract, it enforces a timelock on all
 * `onlyOwner` maintenance operations. This gives time for users of the
 * controlled contract to exit before a potentially dangerous maintenance
 * operation is applied.
 *
 * By default, this contract is self administered, meaning administration tasks
 * have to go through the timelock process. The proposer (resp executor) role
 * is in charge of proposing (resp executing) operations. A common use case is
 * to position this {TimelockController} as the owner of a smart contract, with
 * a multisig or a DAO as the sole proposer.
 *
 * _Available since v3.3._
 */
contract TimelockController is
    AccessControlEnumerable,
    IERC1155Receiver,
    IERC721Receiver,
    CalldataList
{
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice role that can revoke all other roles
    bytes32 public constant TIMELOCK_ADMIN_ROLE =
        keccak256("TIMELOCK_ADMIN_ROLE");

    /// @notice role that can propose new operations
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

    /// @notice role that can execute timelocked operations, if no executor
    /// role is set, anyone can execute timelocked operations.
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice most powerful role in the entire system. This can completely
    /// DoS the system by cancelling proposals indefinitely.
    /// TODO implement maximum number of cancellations per CANCELLER_ROLE
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

    /// @notice timestamp indicating that an operation is done
    uint256 internal constant _DONE_TIMESTAMP = uint256(1);

    mapping(bytes32 => uint256) private _timestamps;

    /// @notice store list of all live proposals, remove from set once executed or cancelled
    EnumerableSet.Bytes32Set private _liveProposals;

    /// @notice minimum delay for all timelock proposals
    uint256 private _minDelay;

    /// @notice the period of time after which a proposal will be considered
    /// expired if it has not been executed.
    uint256 public expirationPeriod;

    /// @notice the safe address that governs this timelock
    address public immutable safe;

    /// @notice minimum delay for timelocked operations
    uint256 public constant MIN_DELAY = 1 days;

    /// @notice maximum delay for timelocked operations
    uint256 public constant MAX_DELAY = 30 days;

    /// @notice Emitted when a call is scheduled as part of operation `id`.
    event CallScheduled(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    );

    /// @notice Emitted when a call is performed as part of operation `id`.
    event CallExecuted(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data
    );

    /// @notice Emitted when operation `id` is cancelled.
    event Cancelled(bytes32 indexed id);

    /// @notice Emitted when the minimum delay for future operations is modified.
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    /// @notice Emitted when the expiration period is modified
    event ExpirationPeriodChange(uint256 oldPeriod, uint256 newPeriod);

    /// @notice Initializes the contract with the following parameters:
    /// @param _safe safe contract that owns this timelock
    /// @param minDelay initial minimum delay for operations
    /// @param _expirationPeriod timelocked actions expiration period
    /// @param cancellers accounts to be granted proposer and canceller roles
    /// @param executors accounts to be granted executor role
    /// @param contractAddresses accounts that will have calldata whitelisted
    /// @param selector function selectors to be whitelisted
    /// @param startIndex start index of the calldata to be whitelisted
    /// @param endIndex end index of the calldata to be whitelisted
    /// @param data calldata to be whitelisted that resides between start and end index
    constructor(
        address _safe,
        uint256 minDelay,
        uint256 _expirationPeriod,
        address[] memory cancellers,
        address[] memory executors,
        address[] memory contractAddresses,
        bytes4[] memory selector,
        uint16[] memory startIndex,
        uint16[] memory endIndex,
        bytes[] memory data
    ) {
        safe = _safe;

        _setRoleAdmin(TIMELOCK_ADMIN_ROLE, TIMELOCK_ADMIN_ROLE);
        _setRoleAdmin(EXECUTOR_ROLE, TIMELOCK_ADMIN_ROLE);
        _setRoleAdmin(CANCELLER_ROLE, TIMELOCK_ADMIN_ROLE);

        /// self administration
        _setupRole(TIMELOCK_ADMIN_ROLE, address(this));

        /// register cancellers
        for (uint256 i = 0; i < cancellers.length; ++i) {
            _setupRole(CANCELLER_ROLE, cancellers[i]);
        }

        // register executors
        for (uint256 i = 0; i < executors.length; ++i) {
            _setupRole(EXECUTOR_ROLE, executors[i]);
        }

        require(
            minDelay >= MIN_DELAY && minDelay <= MAX_DELAY,
            "TimelockController: delay out of bounds"
        );

        _minDelay = minDelay;
        emit MinDelayChange(0, minDelay);

        require(
            _expirationPeriod >= MIN_DELAY,
            "TimelockController: expiry period too short"
        );

        expirationPeriod = _expirationPeriod;
        emit ExpirationPeriodChange(0, _expirationPeriod);

        _addCalldataChecks(
            contractAddresses,
            selector,
            startIndex,
            endIndex,
            data
        );
    }

    /// @dev Modifier to make a function callable only by a certain role. In
    /// addition to checking the sender's role, `address(0)` 's role is also
    /// considered. Granting a role to `address(0)` is equivalent to enabling
    /// this role for everyone.
    modifier onlyRoleOrOpenRole(bytes32 role) {
        if (!hasRole(role, address(0))) {
            _checkRole(role, _msgSender());
        }
        _;
    }

    /// @notice allows only current safe owners to be able to call the function
    modifier onlySafeOwner() {
        require(
            Safe(payable(safe)).isOwner(msg.sender),
            "TimelockController: caller is not the safe owner"
        );
        _;
    }

    /// @notice allows only the safe to call the function
    modifier onlySafe() {
        require(
            msg.sender == safe,
            "TimelockController: caller is not the safe"
        );
        _;
    }

    /// @notice allows timelocked actions to make certain parameter changes
    modifier onlyTimelock() {
        require(
            msg.sender == address(this),
            "TimelockController: caller is not the timelock"
        );
        _;
    }

    /// @notice returns all currently non cancelled and non-executed proposals
    /// some proposals may not be able to be executed if they have passed the expiration period
    function getAllProposals() public view returns (bytes32[] memory) {
        return _liveProposals.values();
    }

    /// @dev See {IERC165-supportsInterface}.
    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(IERC165, AccessControlEnumerable)
        returns (bool)
    {
        return
            interfaceId == type(IERC1155Receiver).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /// @dev Returns whether an id correspond to a registered operation. This
    /// includes both Pending, Ready and Done operations.
    function isOperation(bytes32 id) public view virtual returns (bool) {
        return getTimestamp(id) > 0;
    }

    /// @dev Returns whether an operation is pending or not.
    /// Note that a "pending" operation may also be "ready".
    function isOperationPending(bytes32 id) public view virtual returns (bool) {
        return getTimestamp(id) > _DONE_TIMESTAMP;
    }

    /// @dev Returns whether an operation is ready for execution.
    /// Note that a "ready" operation is also "pending".
    /// cannot be executed after the expiry period.
    function isOperationReady(bytes32 id) public view virtual returns (bool) {
        uint256 timestamp = getTimestamp(id);
        return
            timestamp > _DONE_TIMESTAMP &&
            timestamp <= block.timestamp &&
            timestamp + expirationPeriod > block.timestamp;
    }

    /// @dev Returns whether an operation is done or not.
    function isOperationDone(bytes32 id) public view virtual returns (bool) {
        return getTimestamp(id) == _DONE_TIMESTAMP;
    }

    /// @dev Returns the timestamp at which an operation becomes ready (0 for
    /// unset operations, 1 for done operations).
    function getTimestamp(bytes32 id) public view virtual returns (uint256) {
        return _timestamps[id];
    }

    /// @dev Returns the minimum delay for an operation to become valid.
    /// This value can be changed by executing an operation that calls `updateDelay`.
    function getMinDelay() public view virtual returns (uint256) {
        return _minDelay;
    }

    /// @dev Returns the identifier of an operation containing a single transaction.
    function hashOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) public pure virtual returns (bytes32) {
        return keccak256(abi.encode(target, value, data, predecessor, salt));
    }

    /// @dev Returns the identifier of an operation containing a batch of transactions.
    function hashOperationBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) public pure virtual returns (bytes32) {
        return
            keccak256(abi.encode(targets, values, payloads, predecessor, salt));
    }

    /// @dev Schedule an operation containing a single transaction.
    /// Emits {CallSalt} if salt is nonzero, and {CallScheduled}.
    /// Requirements:
    ///   the caller must have the 'proposer' role.
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public virtual onlySafe {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);

        require(_liveProposals.add(id), "failed to add proposal, duplicate id");

        _schedule(id, delay);

        emit CallScheduled(
            id,
            0,
            target,
            value,
            data,
            predecessor,
            salt,
            delay
        );
    }

    /// @dev Schedule an operation containing a batch of transactions.
    /// Emits {CallSalt} if salt is nonzero, and one {CallScheduled} event per transaction in the batch.
    /// Requirements:
    /// - the caller must be the safe
    /// @param targets the addresses of the contracts to call
    /// @param values the values to send in the calls
    /// @param payloads the calldata to send in the calls
    /// @param predecessor the id of the predecessor operation
    /// @param salt the salt to be used in the operation
    /// @param delay the delay before the operation becomes valid
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public virtual onlySafe {
        require(
            targets.length == values.length,
            "TimelockController: length mismatch"
        );
        require(
            targets.length == payloads.length,
            "TimelockController: length mismatch"
        );

        bytes32 id = hashOperationBatch(
            targets,
            values,
            payloads,
            predecessor,
            salt
        );

        require(_liveProposals.add(id), "failed to add proposal, duplicate id");

        _schedule(id, delay);

        unchecked {
            for (uint256 i = 0; i < targets.length; ++i) {
                emit CallScheduled(
                    id,
                    i,
                    targets[i],
                    values[i],
                    payloads[i],
                    predecessor,
                    salt,
                    delay
                );
            }
        }
    }

    /// @dev Schedule an operation that is to become valid after a given delay.
    /// @param id the identifier of the operation
    /// @param delay the delay before the operation becomes valid
    function _schedule(bytes32 id, uint256 delay) private {
        require(
            !isOperation(id),
            "TimelockController: operation already scheduled"
        );
        require(
            delay >= getMinDelay(),
            "TimelockController: insufficient delay"
        );
        _timestamps[id] = block.timestamp + delay;
    }

    /// @dev Cancel an operation.
    /// Requirements:
    ///  - the caller must have the 'canceller' role.
    function cancel(bytes32 id) public virtual onlyRole(CANCELLER_ROLE) {
        require(
            isOperationPending(id),
            "TimelockController: operation cannot be cancelled"
        );
        delete _timestamps[id];

        emit Cancelled(id);
    }

    /// @dev Execute a ready operation containing a single transaction.
    /// Requirements:
    ///  - the caller must have the 'executor' role.
    ///  - the operation has not expired.
    /// This function can reenter, but it doesn't pose a risk because _afterCall checks that the proposal is pending,
    /// thus any modifications to the operation during reentrancy should be caught.
    /// slither-disable-next-line reentrancy-eth
    function execute(
        address target,
        uint256 value,
        bytes calldata payload,
        bytes32 predecessor,
        bytes32 salt
    ) public payable virtual onlyRoleOrOpenRole(EXECUTOR_ROLE) {
        bytes32 id = hashOperation(target, value, payload, predecessor, salt);

        require(
            _liveProposals.remove(id),
            "cannot execute non-existent proposal"
        );
        _beforeCall(id, predecessor);
        _execute(target, value, payload);
        emit CallExecuted(id, 0, target, value, payload);
        _afterCall(id);
    }

    /// @dev Execute an (ready) operation containing a batch of transactions.
    /// Requirements:
    ///  - the caller must have the 'executor' role.
    /// This function can reenter, but it doesn't pose a risk because _afterCall checks that the proposal is pending,
    /// thus any modifications to the operation during reentrancy should be caught.
    /// slither-disable-next-line reentrancy-eth
    /// @param targets the addresses of the contracts to call
    /// @param values the values to send in the calls
    /// @param payloads the calldata to send in the calls
    /// @param predecessor the id of the predecessor operation
    /// @param salt the salt to be used in the operation
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) public payable virtual onlyRoleOrOpenRole(EXECUTOR_ROLE) {
        require(
            targets.length == values.length,
            "TimelockController: length mismatch"
        );
        require(
            targets.length == payloads.length,
            "TimelockController: length mismatch"
        );

        bytes32 id = hashOperationBatch(
            targets,
            values,
            payloads,
            predecessor,
            salt
        );
        require(
            _liveProposals.remove(id),
            "cannot execute non-existent proposal"
        );

        _beforeCall(id, predecessor);
        for (uint256 i = 0; i < targets.length; ++i) {
            address target = targets[i];
            uint256 value = values[i];
            bytes calldata payload = payloads[i];
            _execute(target, value, payload);
            emit CallExecuted(id, i, target, value, payload);
        }
        _afterCall(id);
    }

    /// @notice any safe owner can call this function and execute calls
    /// to whitelisted contracts with whitelisted calldatas
    /// @param targets the addresses of the contracts to call
    /// @param values the values to send in the calls
    /// @param payloads the calldata to send in the calls
    function executeWhitelistedBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads
    ) public payable onlySafeOwner {
        require(
            targets.length == values.length,
            "TimelockController: length mismatch"
        );
        require(
            targets.length == payloads.length,
            "TimelockController: length mismatch"
        );

        for (uint256 i = 0; i < targets.length; ++i) {
            address target = targets[i];
            uint256 value = values[i];
            bytes calldata payload = payloads[i];

            /// first ensure calldata to target is whitelisted,
            /// and that parameters are not malicious
            checkCalldata(target, value, payload);
            _execute(target, value, payload);
            emit CallExecuted(bytes32(0), i, target, value, payload);
        }
    }

    /**
     * @dev Execute an operation's call.
     */
    function _execute(
        address target,
        uint256 value,
        bytes calldata data
    ) internal virtual {
        (bool success, ) = target.call{value: value}(data);
        require(success, "TimelockController: underlying transaction reverted");
    }

    /**
     * @dev Checks before execution of an operation's calls.
     */
    function _beforeCall(bytes32 id, bytes32 predecessor) private view {
        require(
            isOperationReady(id),
            "TimelockController: operation is not ready"
        );
        require(
            predecessor == bytes32(0) || isOperationDone(predecessor),
            "TimelockController: missing dependency"
        );
    }

    /**
     * @dev Checks after execution of an operation's calls.
     */
    function _afterCall(bytes32 id) private {
        require(
            isOperationReady(id),
            "TimelockController: operation is not ready"
        );
        _timestamps[id] = _DONE_TIMESTAMP;
    }

    /**
     * @dev Changes the minimum timelock duration for future operations.
     *
     * Emits a {MinDelayChange} event.
     *
     * Requirements:
     *
     * - the caller must be the timelock itself. This can only be achieved by scheduling and later executing
     * an operation where the timelock is the target and the data is the ABI-encoded call to this function.
     */
    function updateDelay(uint256 newDelay) external onlyTimelock {
        require(
            newDelay >= MIN_DELAY && newDelay <= MAX_DELAY,
            "TimelockController: delay out of bounds"
        );

        emit MinDelayChange(_minDelay, newDelay);
        _minDelay = newDelay;
    }

    function updateExpirationPeriod(uint256 newPeriod) external onlyTimelock {
        require(
            newPeriod >= MIN_DELAY,
            "TimelockController: delay out of bounds"
        );

        emit ExpirationPeriodChange(expirationPeriod, newPeriod);
        expirationPeriod = newPeriod;
    }

    /**
     * @dev See {IERC721Receiver-onERC721Received}.
     */
    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /**
     * @dev See {IERC1155Receiver-onERC1155Received}.
     */
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    /**
     * @dev See {IERC1155Receiver-onERC1155BatchReceived}.
     */
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    /// @dev Contract might receive/hold ETH as part of the maintenance process.
    receive() external payable {}
}
