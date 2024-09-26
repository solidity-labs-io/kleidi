# Calldata Whitelisting

Kleidi supports whitelisting calldata for specific functions. Users can whitelist multilple values for any function. This is useful when you want to restrict the calldata to a specific set of values.

The following are the ways to whitelist calldata for a function:

1. Direct calldata checking. This means that the calldata is checked for a specific value or set of values for the given indexes.
2. Calldata wildcard, meaning no checks are performed for that function.

## Morpho Example

Take the Morpho Blue smart contracts as an example. The contract is monolithic and has one function to supply across all markets.

The function signature is as follows:

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
```

This means that to supply to any market, the same function is called with different calldata parameters. This is where the array of calldata checks is used.

```solidity
    struct Index {
        uint16 startIndex;
        uint16 endIndex;
        EnumerableSet.Bytes32Set dataHashes;
    }

    contract address => bytes4 function selector => Index[] calldataChecks;
```

There is a mapping that stores the smart contract address to the function selector to the array of calldata checks. This is used to check the calldata passed by the hot signers to call the allowed functions and ensure the calls comply with the rules. A function selector on a contract address can have multiple AND checks. AND check implies that all of these checks should pass. All of these AND checks will have non overlapping start index to end index range amongst each other. For a specific pair of start and end index there can be only one AND check, but the pair can have multiple hashes stored in `dataHashes` set. If the calldata matches with any of the data hashes the check would pass. This is referred as OR check.

Overall, for whitelisting a function on a contract there can be multiple AND checks that can be added for different parts of the calldata and each AND check can have multiple OR checks.