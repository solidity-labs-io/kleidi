pragma solidity 0.8.25;

contract MockTwoParams {
    mapping(address owner => mapping(address token => uint256 amount)) _balance;

    function deposit(address token, address to, uint256 amount) external {
        _balance[token][to] += amount;

        /// token.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(address token, address to, uint256 amount) external {
        to;
        /// shhhhh

        _balance[token][msg.sender] -= amount;

        /// token.transfer(to, amount);
    }
}
