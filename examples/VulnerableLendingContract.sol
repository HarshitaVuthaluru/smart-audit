// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableLendingContract {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: state update after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    // Utility function to check contract balance
    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}