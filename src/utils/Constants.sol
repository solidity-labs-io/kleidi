pragma solidity 0.8.25;

// timestamp indicating that an operation is done
uint256 constant _DONE_TIMESTAMP = uint256(1);

// minimum delay for timelocked operations
// there is no minimum timelock duration enforced when creating a timelock,
// however it is recommended to set a timelock duration of at least a few hours as an end user
uint256 constant MIN_DELAY = 1 days;

// maximum delay for timelocked operations
uint256 constant MAX_DELAY = 30 days;

// maximum number of timelocked operations scheduled at the same time
// this is to prevent the contract from running out of gas when the pause
// function is called
uint256 constant MAX_PROPOSAL_COUNT = 100;
