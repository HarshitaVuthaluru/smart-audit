pragma solidity ^0.8.20;

contract ReentrancyVault {
    mapping(address => uint256) public balances;
    bool private _reentrantLock;

    modifier noReentrant() {
        require(!_reentrantLock, "Reentrancy detected");
        _reentrantLock = true;
        _;
        _reentrantLock = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external noReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");

        balances[msg.sender] -= amount;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }

    receive() external payable {}
}