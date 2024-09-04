// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Timelock} from "src/Timelock.sol";
import {calculateCreate2Address} from "src/utils/Create2Helper.sol";

struct DeploymentParams {
    uint256 minDelay;
    uint256 expirationPeriod;
    address pauser;
    uint128 pauseDuration;
    address[] hotSigners;
    address[] contractAddresses;
    bytes4[] selectors;
    uint16[] startIndexes;
    uint16[] endIndexes;
    bytes[] datas;
    bool[] isSelfAddressCheck;
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

    /// @notice Creates a timelock for a given safe and deployment parameters
    function createTimelock(address safe, DeploymentParams memory params)
        external
        returns (address timelock)
    {
        timelock = address(
            new Timelock{
                salt: keccak256(abi.encodePacked(params.salt, msg.sender))
            }(
                safe,
                params.minDelay,
                params.expirationPeriod,
                params.pauser,
                params.pauseDuration,
                params.hotSigners
            )
        );

        factoryCreated[timelock] = true;

        emit TimelockCreated(timelock, block.timestamp, msg.sender);
    }

    function timelockCreationCode() external pure returns (bytes memory) {
        return type(Timelock).creationCode;
    }
}
