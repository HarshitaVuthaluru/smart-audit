// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");

        (bool success,) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] -= amount;
    }

    receive() external payable {}
}