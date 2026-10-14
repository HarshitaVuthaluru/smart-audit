pragma solidity ^0.8.20;

contract SecureMixedTest {

    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Prevent reentrancy using a boolean flag
        bool _sent = false;

        (bool success,) = msg.sender.call{value: amount}("");
        if (success) {
            _sent = true;
        }

        require(_sent, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        owner = newOwner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }

    function random() external view returns(uint256){
        // Avoid using block.timestamp and msg.sender for randomness. This is a placeholder.
        return uint256(
            keccak256(
                abi.encodePacked(
                    block.difficulty,
                    block.prevrandao,
                    msg.sig
                )
            )
        );
    }

    receive() external payable {}
}