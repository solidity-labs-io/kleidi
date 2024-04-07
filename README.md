# Safe Transaction Time Restriction

This contract allows a Gnosis Safe the ability to restrict the time window in which a transaction can be executed. It is useful, for example, to prevent a user from withdrawing funds from a contract during a certain time window. For DAO's it can set operating hours for a treasury multisig, and for a user, it can prevent a user from withdrawing funds from a personal multisig during certain hours.

## Architecture

This contract is a singleton contract. Once deployed, to be able to use this contract you should call the `addTimeRange` function to add a time range in which transactions are allowed.

```solidity
    /// @param dayOfWeek day of the week to allow transactions
    /// - valid range [1, 7]
    /// @param startHour start hour of the allowed time range
    /// - valid range: [0, 23]
    /// @param endHour end hour of the allowed time range
    /// - valid range: [0, 23]
    function addTimeRange(
        uint8 dayOfWeek,
        uint8 startHour,
        uint8 endHour
    ) external;
```

- Day of the week must be between 1 and 7, where 1 is Monday and 7 is Sunday.
- Start hour and end hour must be between 0 and 23.
- Start hour must be less than end hour.
- The time range is inclusive, meaning that if a transaction is submitted at the start hour or end hour, it will be allowed.
- The time range is in GMT time, so this should be factored in when creating settings.
- Each day can only have a single range of times. It is not possible currently to have multiple ranges per day.

## Usage

In order to configure this contract to work with a Gnosis Safe, the following steps should be taken:

1. Set the guard for the Gnosis Safe to the address of the Time Restriction contract.
2. Call the `addTimeRange` function with the days and time ranges in which transactions will be allowed.
3. Now the Gnosis Safe will only allow transactions to be executed within the time ranges specified.
4. To edit the time range, call the `editTimeRange` function with the new time range. This will replace the existing time range for that day. This function cannot be called if the day does not have a time range already set.
5. Remove all time ranges by calling the `disableGuard()` function. This will allow all transactions to be executed regardless of time submitted.

## Edge Cases

- If no time ranges are added, all transactions are allowed.
- To remove all time ranges, the `disableGuard()` function can be called. Once called, all transactions are allowed, regardless of time submitted.
- If a transaction is submitted on chain outside of the allowed time ranges, it will revert.

### Build

```shell
forge build
```

### Test

```shell
forge test -vvv
```

### Coverage

```shell
forge coverage --report summary --report lcov
```
