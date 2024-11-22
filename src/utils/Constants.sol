pragma solidity 0.8.25;

/// @dev timestamp indicating that an operation is done
uint256 constant _DONE_TIMESTAMP = uint256(1);

/// @dev minimum delay for timelocked operations
uint256 constant MIN_DELAY = 1 days;

/// @dev maximum delay for timelocked operations
uint256 constant MAX_DELAY = 30 days;

/// @dev maximum number of timelocked operations scheduled at the same time
/// @dev this is to prevent the contract from running out of gas when the pause
/// function is called
uint256 constant MAX_PROPOSAL_COUNT = 100;
