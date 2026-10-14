// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IPriceOracle.sol";
import "./IDEXPair.sol";

contract PriceOracle is IPriceOracle {
    address public owner;
    mapping(address => uint256) public prices;
    mapping(address => address) public tokenPairs;
    
    constructor() {
        owner = msg.sender;
    }
    
    function getPrice(address token) external view override returns (uint256) {
        // If we have a direct price, return it
        if (prices[token] > 0) {
            return prices[token];
        }
        
        // Otherwise check if we can get a price from the liquidity pool
        address pair = tokenPairs[token];
        if (pair != address(0)) {
            return getPriceFromPair(token, pair);
        }
        
        // Fallback: return 0 if no price is available
        return 0;
    }
    
    function getPriceFromPair(address token, address pair) internal view returns (uint256) {
        IDEXPair dexPair = IDEXPair(pair);
        (uint256 reserve0, uint256 reserve1) = dexPair.getReserves();
        
        // Vulnerable: No manipulation checks
        address token0 = dexPair.token0();
        
        // Calculate price based on reserves
        if (token == token0) {
            return reserve1 * 1e18 / reserve0;
        } else {
            return reserve0 * 1e18 / reserve1;
        }
    }
    
    function updatePrice(address token, uint256 newPrice) external override {
        // Vulnerable: No access control, anyone can update prices
        prices[token] = newPrice;
    }
    
    function setTokenPair(address token, address pair) external {
        // Vulnerable: No access control
        tokenPairs[token] = pair;
    }
}