// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "forge-std/Test.sol";

contract BaseTestWithBalanceLog is Test {
    // Change this to the target token to get token balance of
    // Keep it address 0 if its ETH that is gotten at the end of the exploit
    address fundingToken = address(0);

    struct ChainInfo {
        string name;
        string symbol;
    }

    mapping(uint256 => ChainInfo) private chainIdToInfo;

    constructor() {
        chainIdToInfo[1] = ChainInfo("MAINNET", "ETH");
        chainIdToInfo[238] = ChainInfo("BLAST", "ETH");
        chainIdToInfo[10] = ChainInfo("OPTIMISM", "ETH");
        chainIdToInfo[250] = ChainInfo("FANTOM", "FTM");
        chainIdToInfo[42_161] = ChainInfo("ARBITRUM", "ETH");
        chainIdToInfo[56] = ChainInfo("BSC", "BNB");
        chainIdToInfo[1285] = ChainInfo("MOONRIVER", "MOVR");
        chainIdToInfo[100] = ChainInfo("GNOSIS", "XDAI");
        chainIdToInfo[43_114] = ChainInfo("AVALANCHE", "AVAX");
        chainIdToInfo[137] = ChainInfo("POLYGON", "MATIC");
        chainIdToInfo[42_220] = ChainInfo("CELO", "CELO");
        chainIdToInfo[8453] = ChainInfo("BASE", "ETH");
    }

    function getChainInfo(
        uint256 chainId
    ) internal view returns (string memory, string memory) {
        ChainInfo storage info = chainIdToInfo[chainId];
        return (info.name, info.symbol);
    }

    function getChainSymbol(
        uint256 chainId
    ) internal view returns (string memory symbol) {
        (, symbol) = getChainInfo(chainId);
        // Return ETH as default if chainID is not registered in mapping
        if (bytes(symbol).length == 0) {
            symbol = "ETH";
        }
    }

    function getFundingBal() internal returns (uint256) {
        return fundingToken == address(0)
            ? address(this).balance
            : TokenHelper.getTokenBalance(fundingToken, address(this));
    }

    function getFundingDecimals() internal returns (uint8) {
        return fundingToken == address(0) ? 18 : TokenHelper.getTokenDecimals(fundingToken);
    }

    function getBaseCurrencySymbol() internal returns (string memory) {
        string memory chainSymbol = getChainSymbol(block.chainid);
        return fundingToken == address(0) ? chainSymbol : TokenHelper.getTokenSymbol(fundingToken);
    }

    modifier balanceLog() {
        // Ensure test contract has some initial ETH (enough to run tests)
        if (fundingToken == address(0)) {
            // Deal 0 ETH for logging initial balance, but keep existing ETH
            uint256 existingBalance = address(this).balance;
            vm.deal(address(this), 0);
            logBalance("Before");
            // Restore original balance plus some extra for test operations
            vm.deal(address(this), existingBalance + 10 ether);
        } else {
            logBalance("Before");
        }

        _;

        logBalance("After");
    }

    function logBalance(
        string memory stage
    ) private {
        emit log_named_decimal_uint(
            string(abi.encodePacked("Attacker ", getBaseCurrencySymbol(), " Balance ", stage, " exploit")),
            getFundingBal(),
            getFundingDecimals()
        );
    }
}

library TokenHelper {
    function callTokenFunction(
        address tokenAddress,
        bytes memory data,
        bool staticCall
    ) private returns (bytes memory) {
        (bool success, bytes memory result) = staticCall ? tokenAddress.staticcall(data) : tokenAddress.call(data);
        require(success, "Failed to call token function");
        return result;
    }

    function getTokenBalance(address tokenAddress, address targetAddress) internal returns (uint256) {
        bytes memory result =
            callTokenFunction(tokenAddress, abi.encodeWithSignature("balanceOf(address)", targetAddress), true);
        return abi.decode(result, (uint256));
    }

    function getTokenDecimals(
        address tokenAddress
    ) internal returns (uint8) {
        bytes memory result = callTokenFunction(tokenAddress, abi.encodeWithSignature("decimals()"), true);
        return abi.decode(result, (uint8));
    }

    function getTokenSymbol(
        address tokenAddress
    ) internal returns (string memory) {
        bytes memory result = callTokenFunction(tokenAddress, abi.encodeWithSignature("symbol()"), true);
        return abi.decode(result, (string));
    }

    function approveToken(address token, address spender, uint256 spendAmount) internal returns (bool) {
        bytes memory result =
            callTokenFunction(token, abi.encodeWithSignature("approve(address,uint256)", spender, spendAmount), false);
        return abi.decode(result, (bool));
    }

    function transferToken(address token, address receiver, uint256 amount) internal returns (bool) {
        bytes memory result =
            callTokenFunction(token, abi.encodeWithSignature("transfer(address,uint256)", receiver, amount), false);
        return abi.decode(result, (bool));
    }
}