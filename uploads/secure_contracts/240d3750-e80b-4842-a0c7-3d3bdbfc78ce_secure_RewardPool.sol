pragma solidity ^0.8.20;

contract RewardPool {

    mapping(address => uint256) public reward;

    function addReward(uint256 amount) external {
        require(amount > 0, "Amount must be greater than zero");
        
        reward[msg.sender] += amount;
    }

    function claim(uint256 amount) external {
        // Reentrancy check
        uint256 _amount = amount;

        require(_amount <= reward[msg.sender], "Insufficient funds for claim");

        reward[msg.sender] -= _amount;

        payable(msg.sender).transfer(_amount);
    }

    receive() external payable {}
}