pragma solidity ^0.8.0;

import {Timelock} from "src/Timelock.sol";

contract MockReentrancyExecutor {
    receive() external payable {
        Timelock(payable(msg.sender)).execute(address(this), 0, "", bytes32(0));
    }
}
