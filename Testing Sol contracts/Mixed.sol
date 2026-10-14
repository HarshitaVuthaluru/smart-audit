// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MixedTest {

    address public owner;

    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        (bool success,) = msg.sender.call{value: amount}("");

        require(success);

        balances[msg.sender] -= amount;
    }

    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    function random() external view returns(uint256){
        return uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.prevrandao,
                    msg.sender
                )
            )
        );
    }

    receive() external payable {}
}