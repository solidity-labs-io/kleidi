// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IERC1155Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from
    "@openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol";
import {
    IERC165,
    ERC165
} from "@openzeppelin-contracts/contracts/utils/introspection/ERC165.sol";
import {EnumerableSet} from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {Safe} from "@safe/Safe.sol";

import {CalldataList} from "src/CalldataList.sol";
import {ConfigurablePauseGuardian} from
    "src/guardian/ConfigurablePauseGuardian.sol";

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
/// There are no checks on native asset balance enshrined into this contract
/// because it is impossible to reason about the state of the native asset
/// given this contract may withdraw from DeFi protocols, or unwrap WETH,
/// thus increasing the native balance.

/// @notice protocol invariants:
/// - there must always be at least 1 proposer
/// - there should be no whitelisted calldata checks for the timelock itself
/// - only safe can propose non-whitelisted calldatas
/// - only safe owners can execute whitelisted calldatas
/// this ensures there is no way to instantly make modifications to the
/// whitelisted timelock calldata.

///  @dev Contract module which acts as a timelocked controller. When set as the
/// owner of an `Ownable` smart contract, it enforces a timelock on all
/// `onlyOwner` maintenance operations. This gives time for users of the
/// controlled contract to exit before a potentially dangerous maintenance
/// operation is applied.
///
/// By default, this contract is self administered, meaning administration tasks
/// have to go through the timelock process. The gnosis safe can propose
/// timelocked operations.
contract Timelock is
    ConfigurablePauseGuardian,
    IERC1155Receiver,
    IERC721Receiver,
    CalldataList,
    ERC165
{
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice timestamp indicating that an operation is done
    uint256 internal constant _DONE_TIMESTAMP = uint256(1);

    /// @notice minimum delay for timelocked operations
    uint256 public constant MIN_DELAY = 1 days;

    /// @notice maximum delay for timelocked operations
    uint256 public constant MAX_DELAY = 30 days;

    /// @notice the safe address that governs this timelock
    address public immutable safe;

    /// @notice minimum delay for all timelock proposals
    uint256 public minDelay;

    /// @notice the period of time after which a proposal will be considered
    /// expired if it has not been executed.
    uint256 public expirationPeriod;

    /// @notice store list of all live proposals, remove from set once executed or cancelled
    EnumerableSet.Bytes32Set private _liveProposals;

    /// @notice mapping of proposal id to execution time
    mapping(bytes32 proposalId => uint256 executionTime) public timestamps;

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

    /// @notice Emitted when operation `id` is cancelled.
    event Cancelled(bytes32 indexed id);

    /// @notice Emitted when the minimum delay for future operations is modified.
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    /// @notice Emitted when the expiration period is modified
    event ExpirationPeriodChange(uint256 oldPeriod, uint256 newPeriod);

    /// @notice Initializes the contract with the following parameters:
    /// @param _safe safe contract that owns this timelock
    /// @param _minDelay initial minimum delay for operations
    /// @param _expirationPeriod timelocked actions expiration period
    /// @param _pauser address that can pause the contract
    /// @param _pauseDuration duration the contract can be paused for
    /// @param contractAddresses accounts that will have calldata whitelisted
    /// @param selector function selectors to be whitelisted
    /// @param startIndex start index of the calldata to be whitelisted
    /// @param endIndex end index of the calldata to be whitelisted
    /// @param data calldata to be whitelisted that resides between start and end index
    constructor(
        address _safe,
        uint256 _minDelay,
        uint256 _expirationPeriod,
        address _pauser,
        uint128 _pauseDuration,
        address[] memory contractAddresses,
        bytes4[] memory selector,
        uint16[] memory startIndex,
        uint16[] memory endIndex,
        bytes[] memory data
    ) {
        safe = _safe;

        require(
            _minDelay >= MIN_DELAY && _minDelay <= MAX_DELAY,
            "Timelock: delay out of bounds"
        );

        minDelay = _minDelay;
        emit MinDelayChange(0, minDelay);

        require(
            _expirationPeriod >= MIN_DELAY, "Timelock: expiry period too short"
        );

        expirationPeriod = _expirationPeriod;
        emit ExpirationPeriodChange(0, _expirationPeriod);

        _grantGuardian(_pauser);
        _updatePauseDuration(_pauseDuration);

        _addCalldataChecks(
            contractAddresses, selector, startIndex, endIndex, data
        );
    }

    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------
    /// -------------------------- Modifiers --------------------------
    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------

    /// @notice allows only current safe owners to be able to call the function
    modifier onlySafeOwner() {
        require(
            Safe(payable(safe)).isOwner(msg.sender),
            "Timelock: caller is not the safe owner"
        );
        _;
    }

    /// @notice allows only the safe to call the function
    modifier onlySafe() {
        require(msg.sender == safe, "Timelock: caller is not the safe");
        _;
    }

    /// @notice allows timelocked actions to make certain parameter changes
    modifier onlyTimelock() {
        require(
            msg.sender == address(this), "Timelock: caller is not the timelock"
        );
        _;
    }

    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------
    /// --------------------- View Only Functions ---------------------
    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------

    /// ---------------------------------------------------------------
    /// ---------------------- System Invariants ----------------------
    /// ---------------------------------------------------------------

    /// getAllProposals length gt 0 => contract is not paused
    /// contract is paused => getAllProposals length eq 0

    /// @notice returns all currently non cancelled and non-executed proposals
    /// some proposals may not be able to be executed if they have passed the expiration period
    function getAllProposals() external view returns (bytes32[] memory) {
        return _liveProposals.values();
    }

    /// @dev See {IERC165-supportsInterface}.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(IERC165, ERC165)
        returns (bool)
    {
        return interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == type(IERC721Receiver).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /// @dev Returns whether an id correspond to a registered operation. This
    /// includes both Pending, Ready and Done operations.
    function isOperation(bytes32 id) public view returns (bool) {
        return getTimestamp(id) > 0;
    }

    /// @dev Returns whether an operation is pending or not.
    /// Note that a "pending" operation may also be "ready".
    function isOperationPending(bytes32 id) external view returns (bool) {
        return getTimestamp(id) > _DONE_TIMESTAMP;
    }

    /// @dev Returns whether an operation is ready for execution.
    /// Note that a "ready" operation is also "pending".
    /// cannot be executed after the expiry period.
    function isOperationReady(bytes32 id) public view returns (bool) {
        uint256 timestamp = getTimestamp(id);
        return timestamp > _DONE_TIMESTAMP && timestamp <= block.timestamp
            && timestamp + expirationPeriod > block.timestamp;
    }

    /// @dev Returns whether an operation is done or not.
    function isOperationDone(bytes32 id) public view returns (bool) {
        return getTimestamp(id) == _DONE_TIMESTAMP;
    }

    /// @dev Returns the timestamp at which an operation becomes ready (0 for
    /// unset operations, 1 for done operations).
    function getTimestamp(bytes32 id) public view returns (uint256) {
        return timestamps[id];
    }

    /// @dev Returns the identifier of an operation containing a single transaction.
    /// @param target the address of the contract to call
    /// @param value the value in native tokens to send in the call
    /// @param data the calldata to send in the call
    /// @param salt the salt to be used in the operation
    function hashOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(target, value, data, salt));
    }

    /// @dev Returns the identifier of an operation containing a batch of transactions.
    /// @param targets the addresses of the contracts to call
    /// @param values the values to send in the calls
    /// @param payloads the calldatas to send in the calls
    /// @param salt the salt to be used in the operation
    function hashOperationBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(targets, values, payloads, salt));
    }

    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------
    /// -------------------- Timelock Functions -----------------------
    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------

    /// @dev Schedule an operation containing a single transaction.
    /// Emits {CallSalt} if salt is nonzero, and {CallScheduled}.
    /// Requirements:
    ///   the caller must have the 'proposer' role.
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 salt,
        uint256 delay
    ) external onlySafe whenNotPaused {
        bytes32 id = hashOperation(target, value, data, salt);

        require(_liveProposals.add(id), "Timelock: duplicate id");

        _schedule(id, delay);

        emit CallScheduled(id, 0, target, value, data, salt, delay);
    }

    /// @dev Schedule an operation containing a batch of transactions.
    /// Emits {CallSalt} if salt is nonzero, and one {CallScheduled} event per transaction in the batch.
    /// Requirements:
    /// - the caller must be the safe
    /// @param targets the addresses of the contracts to call
    /// @param values the values to send in the calls
    /// @param payloads the calldata to send in the calls
    /// @param salt the salt to be used in the operation
    /// @param delay the delay before the operation becomes valid
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 salt,
        uint256 delay
    ) external onlySafe whenNotPaused {
        require(targets.length == values.length, "Timelock: length mismatch");
        require(targets.length == payloads.length, "Timelock: length mismatch");

        bytes32 id = hashOperationBatch(targets, values, payloads, salt);

        require(_liveProposals.add(id), "Timelock: duplicate id");

        _schedule(id, delay);

        unchecked {
            for (uint256 i = 0; i < targets.length; ++i) {
                emit CallScheduled(
                    id, i, targets[i], values[i], payloads[i], salt, delay
                );
            }
        }
    }

    /// @notice cancel all outstanding pending and non executed operations
    /// pauses the contract, revokes the guardian
    function pause() public override {
        /// check that msg.sender is the pause guardian, pause the contract
        super.pause();

        /// kick the pause guardian
        pauseGuardian = address(0);

        while (_liveProposals.values().length > 0) {
            bytes32 id = _liveProposals.at(0);

            delete timestamps[id];
            _liveProposals.remove(id);

            emit Cancelled(id);
        }
    }

    /// @dev Execute a ready operation containing a single transaction.
    /// Requirements:
    ///  - the operation has not expired.
    /// This function can reenter, but it doesn't pose a risk because _afterCall checks that the proposal is pending,
    /// thus any modifications to the operation during reentrancy should be caught.
    /// slither-disable-next-line reentrancy-eth
    /// @param target the address of the contract to call
    /// @param value the value in native tokens to send in the call
    /// @param payload the calldata to send in the call
    /// @param salt the salt to be used in the operation of creating the ID.
    function execute(
        address target,
        uint256 value,
        bytes calldata payload,
        bytes32 salt
    ) external payable whenNotPaused {
        bytes32 id = hashOperation(target, value, payload, salt);

        require(_liveProposals.remove(id), "Timelock: proposal does not exist");
        _beforeCall(id);
        _execute(target, value, payload);
        emit CallExecuted(id, 0, target, value, payload);
        _afterCall(id);
    }

    /// @dev Execute an (ready) operation containing a batch of transactions.
    /// Requirements:
    ///  - the operation has not expired.
    /// This function can reenter, but it doesn't pose a risk because _afterCall checks that the proposal is pending,
    /// thus any modifications to the operation during reentrancy should be caught.
    /// slither-disable-next-line reentrancy-eth
    /// @param targets the addresses of the contracts to call
    /// @param values the values to send in the calls
    /// @param payloads the calldata to send in the calls
    /// @param salt the salt to be used in the operation
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 salt
    ) external payable whenNotPaused {
        require(targets.length == values.length, "Timelock: length mismatch");
        require(targets.length == payloads.length, "Timelock: length mismatch");

        bytes32 id = hashOperationBatch(targets, values, payloads, salt);

        require(_liveProposals.remove(id), "Timelock: proposal does not exist");

        _beforeCall(id);
        for (uint256 i = 0; i < targets.length; ++i) {
            address target = targets[i];
            uint256 value = values[i];
            bytes calldata payload = payloads[i];
            _execute(target, value, payload);
            emit CallExecuted(id, i, target, value, payload);
        }
        _afterCall(id);
    }

    /// @notice any safe owner can call this function and execute
    /// a call to whitelisted contracts with whitelisted calldatas
    /// @param target the addresses of the contracts to call
    /// @param value the values to send in the calls
    /// @param payload the calldata to send in the calls
    function executeWhitelisted(
        address target,
        uint256 value,
        bytes calldata payload
    ) external payable onlySafeOwner {
        /// first ensure calldata to target is whitelisted,
        /// and that parameters are not malicious
        checkCalldata(target, value, payload);
        _execute(target, value, payload);

        emit CallExecuted(bytes32(0), 0, target, value, payload);
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
    ) external payable onlySafeOwner {
        require(
            targets.length == values.length && targets.length == payloads.length,
            "Timelock: length mismatch"
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

    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------
    /// ------------------- Timelock Only Functions -------------------
    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------

    /// @notice function to grant the guardian to a new address
    /// resets the pauseStartTime to 0, which unpauses the contract
    /// @param newGuardian the address of the new guardian
    function setGuardian(address newGuardian) public onlyTimelock {
        _grantGuardian(newGuardian);
    }

    /// @notice add multiple calldata checks
    /// @param contractAddresses the addresses of the contract that the calldata check is added to
    /// @param selectors the function selectors of the function that the calldata check is added to
    /// @param startIndexes the start indexes of the calldata
    /// @param endIndexes the end indexes of the calldata
    /// @param datas the calldatas that are checked for each corresponding function at each index
    /// on each contract
    function addCalldataChecks(
        address[] memory contractAddresses,
        bytes4[] memory selectors,
        uint16[] memory startIndexes,
        uint16[] memory endIndexes,
        bytes[] memory datas
    ) external onlyTimelock {
        _addCalldataChecks(
            contractAddresses, selectors, startIndexes, endIndexes, datas
        );
    }

    /// @notice add a single calldata check
    /// @param contractAddress the address of the contract that the calldata check is added to
    /// @param selector the function selector of the function that the calldata check is added to
    /// @param startIndex the start indexes of the calldata
    /// @param endIndex the end indexes of the calldata
    /// @param data the calldata that is stored
    function addCalldataCheck(
        address contractAddress,
        bytes4 selector,
        uint16 startIndex,
        uint16 endIndex,
        bytes memory data
    ) external onlyTimelock {
        _addCalldataCheck(contractAddress, selector, startIndex, endIndex, data);
    }

    /// @notice remove a single calldata check for a given contract address
    /// @param contractAddress the address of the contract that the
    /// calldata checks are removed from
    /// @param selector the function selector of the function that the
    /// checks will be removed from
    /// @param index the starting index of the calldata check to remove
    function removeCalldataChecks(
        address contractAddress,
        bytes4 selector,
        uint256 index
    ) external onlyTimelock {
        _removeCalldataCheck(contractAddress, selector, index);
    }

    /// @notice remove all calldata checks for a given contract address
    /// @param contractAddress the address of the contract that the
    /// calldata checks are removed from
    /// @param selector the function selector of the function that the
    /// checks will be removed from
    function removeAllCalldataChecks(
        address[] memory contractAddress,
        bytes4[] memory selector
    ) external onlyTimelock {
        require(
            contractAddress.length == selector.length,
            "Timelock: arity mismatch"
        );
        for (uint256 i = 0; i < contractAddress.length; ++i) {
            _removeAllCalldataChecks(contractAddress[i], selector[i]);
        }
    }

    /// @dev Changes the minimum timelock duration for future operations.
    /// Emits a {MinDelayChange} event.
    /// Requirements:
    /// - the caller must be the timelock itself. This can only be achieved by scheduling and later executing
    /// an operation where the timelock is the target and the data is the ABI-encoded call to this function.
    /// @param newDelay the new minimum delay
    function updateDelay(uint256 newDelay) external onlyTimelock {
        require(
            newDelay >= MIN_DELAY && newDelay <= MAX_DELAY,
            "Timelock: delay out of bounds"
        );

        emit MinDelayChange(minDelay, newDelay);
        minDelay = newDelay;
    }

    /// @notice update the expiration period for timelocked actions
    /// @param newPeriod the new expiration period
    function updateExpirationPeriod(uint256 newPeriod) external onlyTimelock {
        require(newPeriod >= MIN_DELAY, "Timelock: delay out of bounds");

        emit ExpirationPeriodChange(expirationPeriod, newPeriod);
        expirationPeriod = newPeriod;
    }

    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------
    /// ------------------ Private Helper Functions -------------------
    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------

    /// @dev Schedule an operation that is to become valid after a given delay.
    /// @param id the identifier of the operation
    /// @param delay the delay before the operation becomes valid
    function _schedule(bytes32 id, uint256 delay) private {
        /// this line is never reachable as no duplicate id's are enforced before this call is made
        require(!isOperation(id), "Timelock: operation already scheduled");
        /// this line is reachable
        require(delay >= minDelay, "Timelock: insufficient delay");
        timestamps[id] = block.timestamp + delay;
    }

    /// @dev Checks before execution of an operation's calls.
    /// @param id the identifier of the operation
    function _beforeCall(bytes32 id) private view {
        require(isOperationReady(id), "Timelock: operation is not ready");
    }

    /// @dev Checks after execution of an operation's calls.
    /// @param id the identifier of the operation
    function _afterCall(bytes32 id) private {
        /// unreachable state because removing the proposal id from the _liveProposals
        /// set prevents this function from being called on the same id twice
        require(isOperationReady(id), "Timelock: operation is not ready");
        timestamps[id] = _DONE_TIMESTAMP;
    }

    /// @dev Execute an operation's call.
    /// @param target the address of the contract to call
    /// @param value the value in native tokens to send in the call
    /// @param data the calldata to send in the call
    function _execute(address target, uint256 value, bytes calldata data)
        private
    {
        (bool success,) = target.call{value: value}(data);
        require(success, "Timelock: underlying transaction reverted");
    }

    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------
    /// ----------------- 721 and 1155 Compatability ------------------
    /// ---------------------------------------------------------------
    /// ---------------------------------------------------------------

    /// @dev See {IERC721Receiver-onERC721Received}.
    function onERC721Received(address, address, uint256, bytes memory)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }

    /**
     * @dev See {IERC1155Receiver-onERC1155Received}.
     */
    function onERC1155Received(address, address, uint256, uint256, bytes memory)
        external
        pure
        override
        returns (bytes4)
    {
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
    ) external pure override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    /// code snippet from https://github.com/safe-global/safe-smart-account/blob/main/contracts/handler/TokenCallbackHandler.sol

    /// @notice Handles ERC777 Token callback.
    /// return nothing (not standardized)
    function tokensReceived(
        address,
        address,
        address,
        uint256,
        bytes calldata,
        bytes calldata
    ) external pure {
        /// We implement this for completeness, doesn't really have any value
    }

    /// @dev Contract might receive/hold ETH as part of the maintenance process.
    receive() external payable {}
}
