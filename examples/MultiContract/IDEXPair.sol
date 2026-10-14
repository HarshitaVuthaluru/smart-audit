// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IDEXPair {
    function getReserves() external view returns (uint256 reserve0, uint256 reserve1);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function mint(address to) external returns (uint256 liquidity);
    function burn(address to) external returns (uint256 amount0, uint256 amount1);
}