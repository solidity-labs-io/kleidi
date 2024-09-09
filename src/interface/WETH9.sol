pragma solidity >=0.5.0;

interface WETH9 {
    function deposit() external;
    function withdraw(uint256 wad) external;
}
