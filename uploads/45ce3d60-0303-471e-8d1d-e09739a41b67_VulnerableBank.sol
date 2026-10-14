// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableBank {

    mapping(address => uint256) public balances;
    address public owner;
    uint256 public unlockTime;

    constructor() {
        owner = msg.sender;
        unlockTime = block.timestamp + 1 days;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Reentrancy Vulnerability
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Access Control Vulnerability
    function changeOwner(address newOwner) external {
        owner = newOwner;
    }

    // Timestamp Dependence
    function withdrawAfterUnlock() external {
        require(block.timestamp >= unlockTime, "Still locked");

        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;

        payable(msg.sender).transfer(amount);
    }

    // Integer Overflow (unchecked)
    function reward(address user, uint256 amount) external {
        unchecked {
            balances[user] += amount;
        }
    }

    // Dangerous Selfdestruct
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    // Denial of Service
    function distribute(address[] calldata users) external payable {
        uint256 share = msg.value / users.length;

        for(uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(share);
        }
    }

    receive() external payable {}
}