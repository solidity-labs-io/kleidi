pragma solidity 0.8.25;

contract MockLending {
    mapping(address owner => uint256 amount) _balance;

    function deposit(address to, uint256 amount) external {
        _balance[to] += amount;

        /// token.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(address to, uint256 amount) external {
        to;
        /// shhhhh

        _balance[msg.sender] -= amount;

        /// token.transfer(to, amount);
    }
}
