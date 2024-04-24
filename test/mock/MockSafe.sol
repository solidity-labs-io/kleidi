pragma solidity ^0.8.0;

contract MockSafe {
    address[] public owners;

    function setOwners(address[] memory _owners) public {
        owners = _owners;
    }

    function getOwners() public view returns (address[] memory) {
        return owners;
    }

    /// used to execute arbitrary code, mainly queuing actions in the timelock
    function arbitraryExecution(address target, bytes memory data) public {
        (bool success, bytes memory returnData) = target.call{value: 0}(data);
        require(success, string(returnData));
    }
}
