// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardPool {

    mapping(address => uint256) public reward;

    function addReward(uint256 amount) external {
        reward[msg.sender] += amount;
    }

    function claim(uint256 amount) external {
        require(reward[msg.sender] >= amount);

        reward[msg.sender] -= amount;

        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}