pragma solidity 0.8.25;

/// @notice pause contract that has a duration for each pause period.
/// This contract has a pause duration and a pause start time.
/// Invariants:
///  - When the pause start time is non zero, the contract is able to return paused as true.
///  - Once the block timestamp is greater than the pause start time + pause duration, the
///  contract is automatically unpaused.
///  - Block timestamp gte pause start time && block timestamp lte pause start time + pause
///  duration, then the contract is paused
contract ConfigurablePause {
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------
    /// ------------------ SINGLE STORAGE SLOT ------------------
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------

    /// @notice pause start time, starts at 0 so contract is unpaused
    uint128 public pauseStartTime;

    /// @notice pause duration
    uint128 public pauseDuration;

    uint256 public constant MAX_PAUSE_DURATION = 30 days;

    /// @notice event emitted when pause start time is updated
    /// @param newPauseStartTime new pause start time
    event PauseTimeUpdated(uint256 indexed newPauseStartTime);

    /// @notice event emitted when pause duration is updated
    /// @param oldPauseDuration old pause duration
    /// @param newPauseDuration new pause duration
    event PauseDurationUpdated(
        uint256 oldPauseDuration,
        uint256 newPauseDuration
    );

    /// @dev Emitted when the pause is triggered by `account`.
    event Paused(address account);

    /// @dev Emitted when the pause is lifted by `account`.
    event Unpaused(address account);

    /// @dev Modifier to make a function callable only when the contract is not paused.
    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    /// @notice return the current pause status
    /// if pauseStartTime is 0, contract is not paused
    /// if pauseStartTime is not 0, contract could be paused in the pauseDuration window
    function paused() public view returns (bool) {
        return
            pauseStartTime == 0
                ? false
                : block.timestamp <= pauseStartTime + pauseDuration;
    }

    /// ------------- INTERNAL HELPERS -------------

    /// @notice helper function to update the pause duration once the contract is paused
    /// @param newPauseDuration new pause duration
    function _updatePauseDuration(uint128 newPauseDuration) internal virtual {
        require(
            newPauseDuration <= MAX_PAUSE_DURATION,
            "ConfigurablePause: pause duration too long"
        );
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

    /// @dev Reverts with error: "Pausable: paused"
    /// Throws if the contract is paused.
    function _requireNotPaused() private view {
        require(!paused(), "Pausable: paused");
    }
}
