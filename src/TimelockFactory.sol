// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Timelock} from "src/Timelock.sol";
import {calculateCreate2Address} from "src/utils/Create2Helper.sol";

struct DeploymentParams {
    uint256 minDelay;
    uint256 expirationPeriod;
    address pauser;
    uint128 pauseDuration;
    address[] contractAddresses;
    bytes4[] selector;
    uint16[] startIndex;
    uint16[] endIndex;
    bytes[] data;
    bytes32 salt;
}

/// @notice simple factory contract that creates timelocks
contract TimelockFactory {
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------
    /// -------------------- STORAGE VARIABLE -------------------
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------

    /// @notice mapping of timelock address to whether factory created
    mapping(address timelock => bool created) public factoryCreated;

    /// ---------------------------------------------------------
    /// ---------------------------------------------------------
    /// ------------------------- EVENT -------------------------
    /// ---------------------------------------------------------
    /// ---------------------------------------------------------

    /// @notice Emitted when a call is scheduled as part of operation `id`.
    /// @param timelock address of the newly created timelock
    /// @param creationTime of the new timelock
    /// @param sender that called the contract to create the timelock
    event TimelockCreated(
        address indexed timelock, uint256 creationTime, address sender
    );

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
    /// @param salt for create2 opcode
    function createTimelock(
        address _safe,
        uint256 _minDelay,
        uint256 _expirationPeriod,
        address _pauser,
        uint128 _pauseDuration,
        address[] memory contractAddresses,
        bytes4[] memory selector,
        uint16[] memory startIndex,
        uint16[] memory endIndex,
        bytes[] memory data,
        bytes32 salt
    ) public returns (address timelock) {
        timelock = address(
            new Timelock{salt: salt}(
                _safe,
                _minDelay,
                _expirationPeriod,
                _pauser,
                _pauseDuration,
                contractAddresses,
                selector,
                startIndex,
                endIndex,
                data
            )
        );

        factoryCreated[timelock] = true;

        emit TimelockCreated(timelock, block.timestamp, msg.sender);
    }

    function createTimelock(address safe, DeploymentParams memory params)
        external
        returns (address timelock)
    {
        return createTimelock(
            safe,
            params.minDelay,
            params.expirationPeriod,
            params.pauser,
            params.pauseDuration,
            params.contractAddresses,
            params.selector,
            params.startIndex,
            params.endIndex,
            params.data,
            params.salt
        );
    }

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
    /// @param salt for create2 opcode
    function calculateAddress(
        address _safe,
        uint256 _minDelay,
        uint256 _expirationPeriod,
        address _pauser,
        uint128 _pauseDuration,
        address[] memory contractAddresses,
        bytes4[] memory selector,
        uint16[] memory startIndex,
        uint16[] memory endIndex,
        bytes[] memory data,
        bytes32 salt
    ) external view returns (address) {
        return calculateCreate2Address(
            address(this),
            type(Timelock).creationCode,
            abi.encode(
                _safe,
                _minDelay,
                _expirationPeriod,
                _pauser,
                _pauseDuration,
                contractAddresses,
                selector,
                startIndex,
                endIndex,
                data
            ),
            salt
        );
    }
}
