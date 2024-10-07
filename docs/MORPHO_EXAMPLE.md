
user wants to whitelist three USDC morpho markets

morpo has a single contract where all operations flow through a single function for deposit, and they flow through a single function on withdraw

the function signature is as follows:

```solidity
    struct MarketParams {
        address loanToken;
        address collateralToken;
        address oracle;
        address irm;
        uint256 lltv;
    }

    function supply(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        bytes memory data
    ) external returns (uint256 assetsSupplied, uint256 sharesSupplied);

    selector 0x928182123
    allowed market params: [1, 2]
    calldatachecks : [[startIndex: 4, endIndex: 164], [startIndex: 228, endIndex: 260]]
    allowed onBehalf: [timelock]
```

the withdraw function is similar:
    
    ```solidity
        function withdraw(
            MarketParams memory marketParams,
            uint256 assets,
            uint256 shares,
            address to,
            bytes memory data
        ) external returns (uint256 assetsWithdrawn, uint256 sharesWithdrawn);

    selector 0x872387fe
    calldatachecks: [[startIndex: 228, endIndex: 260]]
    allowed to: [timelock]
    ```

1. call approve on usdc to approve morpo to spend the usdc
2. call supply on morpho to deposit usdc
3. call withdraw on morpho to withdraw usdc back to the timelock

calldata to whitelist for market 1:

1. selector 0x095ea7b3 on USDC with parameter 1 as the timelock address, parameter 2 is the value and is unchecked. start index is 16 and end index is 36 because an address is 20 bytes and the first 12 bytes are garbage data that are unused

2. selector 0x928182123 on morpho with parameter 1 as the market params, parameter 4 as the timelock address, the remaining parameters are unchecked

3. selector 0x872387fe on morpho with parameter 4 as the timelock address, this makes all withdrawals be sent to the timelock, the remaining parameters are unchecked

calldata to whitelist for market 2:

1. selector 0x928182123 on morpho with parameter 1 as the 2nd market params

calldata to whitelist for market 3:

1. selector 0x928182123 on morpho with parameter 1 as the 3rd market params
