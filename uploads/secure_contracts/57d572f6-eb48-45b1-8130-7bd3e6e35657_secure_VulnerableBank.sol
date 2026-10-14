pragma solidity ^0.8.20;

contract SafeBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        balances[msg.sender] -= amount;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address not allowed");
        owner = newOwner;
    }

    // Emergency withdrawal should be restricted and controlled
    // by a proper mechanism, not accessible to everyone.
    function emergencyWithdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }

    // Set balance functionality is dangerous without authorization checks
    function setBalance(address user, uint256 amount) external onlyOwner {
        balances[user] = amount;
    }

    function destroy() external onlyOwner {
        selfdestruct(payable(msg.sender));
    }

    // Randomness generation should use a verifiable Chainlink VRF or commit-reveal flow
    function random(uint256 seed) external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(seed)));
    }

    // Unsafe send functionality should be avoided
    function unsafeSend(address payable to, uint256 amount) external onlyOwner {
        (bool success,) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}