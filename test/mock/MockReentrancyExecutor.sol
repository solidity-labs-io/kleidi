pragma solidity 0.8.25;

import {Timelock} from "src/Timelock.sol";

contract MockReentrancyExecutor {
    bool public executeBatch;

    function setExecuteBatch(bool _executeBatch) external {
        executeBatch = _executeBatch;
    }

    receive() external payable {
        if (!executeBatch) {
            Timelock(payable(msg.sender)).execute(
                address(this), 0, "", bytes32(0)
            );
        } else {
            address[] memory targets = new address[](1);
            targets[0] = address(this);

            uint256[] memory values = new uint256[](1);
            values[0] = 0;

            bytes[] memory datas = new bytes[](1);
            datas[0] = "";

            Timelock(payable(msg.sender)).executeBatch(
                targets, values, datas, bytes32(0)
            );
        }
    }
}
