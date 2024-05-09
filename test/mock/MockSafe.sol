pragma solidity 0.8.25;

import {Enum} from "@safe/common/Enum.sol";

contract MockSafe {
    address[] public owners;

    bool public execTransactionModuleSuccess;

    function setExecTransactionModuleSuccess(bool _success) public {
        execTransactionModuleSuccess = _success;
    }

    function setOwners(address[] memory _owners) public {
        owners = _owners;
    }

    function isOwner(address user) public view returns (bool) {
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == user) {
                return true;
            }
        }

        return false;
    }

    function getOwners() public view returns (address[] memory) {
        return owners;
    }

    /// used to execute arbitrary code, mainly queuing actions in the timelock
    function arbitraryExecution(address target, bytes memory data) public {
        (bool success, bytes memory returnData) = target.call{value: 0}(data);
        require(success, string(returnData));
    }

    /// no-op, used to unit test recovery spell
    function execTransactionFromModule(
        address,
        uint256,
        bytes memory,
        Enum.Operation
    ) public virtual returns (bool success) {
        success = execTransactionModuleSuccess;
    }
}
