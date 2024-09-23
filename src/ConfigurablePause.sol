pragma solidity 0.8.25;

/// naming: rename to pausable

/// @notice possible states for this contract to be in:
///     1. paused, pauseStartTime != 0, guardian == address(0)
///     2. unpaused, pauseStartTime == 0, guardian != address(0)
///     3. unpaused, pauseStartTime <= block.timestamp - pauseDuration, guardian == address(0)
contract ConfigurablePause {
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------
    /// ------------------- STORAGE VARIABLES -------------------
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------

    /// @notice pause start time, starts at 0 so contract is unpaused
    uint128 public pauseStartTime;

    /// @notice pause duration
    uint128 public pauseDuration;

    /// @notice address of the pause guardian
    address public pauseGuardian;

    /// ---------------------------------------------------------
    /// ---------------------------------------------------------
    /// ------------------ CONSTANT VARIABLES -------------------
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------

    /// @notice minimum pause duration
    uint256 public constant MIN_PAUSE_DURATION = 1 days;

    /// @notice maximum pause duration
    uint256 public constant MAX_PAUSE_DURATION = 30 days;

    /// @notice emitted when the pause guardian is updated
    /// @param oldPauseGuardian old pause guardian
    /// @param newPauseGuardian new pause guardian
    event PauseGuardianUpdated(
        address indexed oldPauseGuardian, address indexed newPauseGuardian
    );

    /// @notice event emitted when pause start time is updated
    /// @param newPauseStartTime new pause start time
    event PauseTimeUpdated(uint256 indexed newPauseStartTime);

    /// @notice event emitted when pause duration is updated
    /// @param oldPauseDuration old pause duration
    /// @param newPauseDuration new pause duration
    event PauseDurationUpdated(
        uint256 indexed oldPauseDuration, uint256 newPauseDuration
    );

    /// @dev Emitted when the pause is triggered by `account`.
    event Paused(address indexed account);

    /// @dev Modifier to make a function callable only when the contract is not paused.
    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
        _;
    }

    /// ------------- VIEW ONLY FUNCTIONS -------------

    /// @notice return the current pause status
    /// if pauseStartTime is 0, contract is not paused
    /// if pauseStartTime is not 0, contract could be paused in the pauseDuration window
    function paused() public view returns (bool) {
        return block.timestamp <= pauseStartTime + pauseDuration;
    }

    /// ------------- PAUSE FUNCTION -------------

    /// @notice pause the contracts, can only pause while the contracts are unpaused
    /// uses up the pause, and starts the pause timer
    /// calling removes the pause guardian
    function pause() public virtual whenNotPaused {
        /// if msg.sender == pause guardian, contract is not paused
        /// this implies that pause is not used
        require(
            msg.sender == pauseGuardian,
            "ConfigurablePauseGuardian: only pause guardian"
        );

        /// pause, set pauseStartTime to current block timestamp
        /// safe unchecked downcast because maximum would be 2^128 - 1 which is
        /// a very large number and very far in the future
        _setPauseTime(uint128(block.timestamp));

        address previousPauseGuardian = pauseGuardian;
        /// kick the pause guardian
        pauseGuardian = address(0);

        emit PauseGuardianUpdated(previousPauseGuardian, address(0));
        emit Paused(msg.sender);
    }

    /// ------------- INTERNAL/PRIVATE HELPERS -------------

    /// @notice helper function to update the pause duration
    /// should only be called when the contract is unpaused
    /// @param newPauseDuration new pause duration
    function _updatePauseDuration(uint128 newPauseDuration) internal {
        require(
            newPauseDuration >= MIN_PAUSE_DURATION
                && newPauseDuration <= MAX_PAUSE_DURATION,
            "ConfigurablePause: pause duration out of bounds"
        );

        /// if the contract was already paused, reset the pauseStartTime to 0
        /// so that this function cannot pause the contract again
        _setPauseTime(0);

        uint256 oldPauseDuration = pauseDuration;
        pauseDuration = newPauseDuration;

        emit PauseDurationUpdated(oldPauseDuration, pauseDuration);
    }

    /// @notice helper function to update the pause start time. used to pause the contract
    /// @param newPauseStartTime new pause start time
    function _setPauseTime(uint128 newPauseStartTime) internal {
        pauseStartTime = newPauseStartTime;

        emit PauseTimeUpdated(newPauseStartTime);
    }

    /// @dev when a new guardian is granted, the contract is automatically unpaused
    /// @notice grant pause guardian role to a new address
    /// this should be done after the previous pause guardian has been kicked,
    /// however there are no checks on this as only the owner will call this function
    /// and the owner is assumed to be non-malicious
    function _grantGuardian(address newPauseGuardian) internal {
        address previousPauseGuardian = pauseGuardian;
        pauseGuardian = newPauseGuardian;

        emit PauseGuardianUpdated(previousPauseGuardian, newPauseGuardian);
    }
}
