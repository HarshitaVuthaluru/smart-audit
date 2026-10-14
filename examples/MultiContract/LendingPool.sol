// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IPriceOracle.sol";
import "./Token.sol";

contract LendingPool {
    struct UserDeposit {
        uint256 amount;
        uint256 lastUpdateTime;
    }
    
    mapping(address => mapping(address => UserDeposit)) public userDeposits; // token => user => deposit
    mapping(address => uint256) public totalDeposits; // token => total deposits
    mapping(address => uint256) public collateralFactors; // token => collateral factor (0-100%)
    
    IPriceOracle public priceOracle;
    address public owner;
    
    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount);
    event Borrow(address indexed user, address indexed token, uint256 amount);
    event Repay(address indexed user, address indexed token, uint256 amount);
    event Liquidate(address indexed user, address indexed repayToken, address indexed collateralToken, uint256 amount);
    
    constructor(address _priceOracle) {
        priceOracle = IPriceOracle(_priceOracle);
        owner = msg.sender;
    }
    
    function deposit(address token, uint256 amount) external {
        Token(token).transferFrom(msg.sender, address(this), amount);
        
        UserDeposit storage userDeposit = userDeposits[token][msg.sender];
        userDeposit.amount += amount;
        userDeposit.lastUpdateTime = block.timestamp;
        
        totalDeposits[token] += amount;
        
        emit Deposit(msg.sender, token, amount);
    }
    
    function withdraw(address token, uint256 amount) external {
        UserDeposit storage userDeposit = userDeposits[token][msg.sender];
        require(userDeposit.amount >= amount, "Insufficient deposit");
        
        // Vulnerable: No health check when withdrawing collateral
        userDeposit.amount -= amount;
        userDeposit.lastUpdateTime = block.timestamp;
        
        totalDeposits[token] -= amount;
        
        Token(token).transfer(msg.sender, amount);
        
        emit Withdraw(msg.sender, token, amount);
    }
    
    function borrow(address token, uint256 amount) external {
        require(totalDeposits[token] >= amount, "Insufficient liquidity");
        require(isHealthy(msg.sender, token, amount), "Unhealthy position");
        
        // Vulnerable: Uses price oracle without manipulation checks
        uint256 tokenPrice = priceOracle.getPrice(token);
        require(tokenPrice > 0, "Invalid token price");
        
        // Transfer tokens to borrower
        Token(token).transfer(msg.sender, amount);
        
        emit Borrow(msg.sender, token, amount);
    }
    
    function isHealthy(address user, address borrowToken, uint256 borrowAmount) public view returns (bool) {
        uint256 borrowValue = borrowAmount * priceOracle.getPrice(borrowToken) / 1e18;
        uint256 totalCollateralValue = 0;
        
        // This is a simplified calculation; a real system would check all collaterals and borrows
        return totalCollateralValue >= borrowValue;
    }
    
    function setCollateralFactor(address token, uint256 factor) external onlyOwner {
        require(factor <= 100, "Factor must be <= 100%");
        collateralFactors[token] = factor;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}