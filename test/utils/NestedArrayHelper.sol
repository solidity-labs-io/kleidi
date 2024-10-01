pragma solidity 0.8.25;

function generateCalldatas(
    bytes[][] memory calldatas,
    bytes memory data,
    uint256 index
) pure returns (bytes[][] memory) {
    bytes[] memory dataArray = new bytes[](1);
    dataArray[0] = data;
    calldatas[index] = dataArray;
    return calldatas;
}
