// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    // Deposit Ether
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable to reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Unchecked external call
    function sendEther(address payable recipient, uint256 amount) external {
        recipient.call{value: amount}("");
    }

    // Dangerous use of tx.origin
    function emergencyWithdraw() external {
        require(tx.origin == msg.sender, "Not authorized");

        payable(msg.sender).transfer(address(this).balance);
    }

    // Weak access control
    function changeBalance(address user, uint256 newBalance) external {
        balances[user] = newBalance;
    }

    receive() external payable {}
}