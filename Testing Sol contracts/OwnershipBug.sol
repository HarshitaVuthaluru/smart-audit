// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OwnershipBug {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}