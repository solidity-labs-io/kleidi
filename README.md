# DeFi Self Custody Protocol

The DeFi Self Custody Protocol is a collection of smart contracts that can be used to create a fully self-custody system for DeFi users. The protocol is opinionated and is designed to be used with Gnosis Safe multisigs, a timelock, guard contract, and dark spells. It enables users to access DeFi yields and protocols, pull funds in case of emergency, and recover funds in case of lost keys either through social recovery or predefined backups.

## Design Principles

- **Security**: The protocol is designed by the world class Smart Contract engineering team at Solidity Labs. It has had components formally verified, and has been audited twice with no critical or high issues discovered. It is designed to be used with Gnosis Safe multisigs, which are battle-tested and have secured tens of billions of dollars in assets. See our internal audit log [here]().
- **Flexibility**: The protocol is designed to be flexible and can be used in a variety of ways. It can be used by DAOs, individuals, and other entities. Dark spells allow users the ability to create custom recovery logic or flows to protect their assets from seizure.
- **Self Reliance**: This smart contract system is designed to enable a self custody system that does not require trusted third parties. Funds can be securely managed by a single user in this system setup. Users can recover their funds without needing to rely on a trusted third party, though they can choose to use a social recovery system if they wish.
- **Wrench Resistant**: One of the guiding principles of this system is to be resistant to $5 wrench attacks. Even if an attacker is able to coerce a user into signing a transaction the system of dark spells, time restrictions and guardians slows down an attacker trying to steal funds. With a 30 day timelock as the delay on new transactions, an attacker would need to kidnap a user for a month and have this remain undetected for a month in order to steal funds.
- **Defense in Depth**: The system is designed with multiple layers of security. Restrictions on times when transactions can be queued limit activity to certain days and times of the week. The timelock prevents transactions from being executed immediately. Dark spells can be used to create custom recovery logic for a multisig. The dark spell could either completely rotate the multisig signer set, or contain more complex logic to recover funds in case of lost keys.

# Safe Transaction Time Restriction

This contract allows a Gnosis Safe the ability to restrict the time window in which a transaction can be executed. It is useful, for example, to prevent a user from withdrawing funds from a contract during a certain time window. For DAO's it can set operating hours for a treasury multisig, and for a user, it can prevent a user from withdrawing funds from a personal multisig during certain hours.

## Architecture
![](Architecture.png)

Each system component works together to ensure a user cannot be coerced into signing actions they do not want to take. 

- **Time Restriction Contract**: This contract restricts the time window in which a transaction can be executed. Additionally, it stops owners from being rotated out of the multisig (except by modules), stops additional modules from being added or removed during a transaction, and prevents the guard from being disabled by a transaction. With these checks in place, it is impossible to remove the guard, rotate signers, or add new modules to the multisig without a timelocked transaction passing.
- **Timelock Contract**: This contract is a delay mechanism for transactions. It requires a delay before a transaction can be executed. This delay can be set to any time period between 1 and 30 days. This delay prevents an attacker from immediately executing a transaction after coercing a user into signing a transaction. The timelock can whitelist contract calls and calldata, this allows safe signers to execute interactions with other smart contracts as long as the contract, function signature, and certain parts of the calldata are whitelisted.
- **Dark Spells**: Dark spells are custom recovery mechanisms that can be used to recover funds in case of lost keys. They can be used to rotate the signers of a multisig, or to create other custom recovery logic. This allows users to craft custom recovery flows that can be used to recover funds in case of lost keys. Dark spells can be used to create a recovery mechanism that is resistant to $5 wrench attacks, and can be used to recover funds in case of lost keys. A social recovery dark spell could allow the recovery members to rotate the signers of the multisig after a predefined timelock. This would allow the multisig owner to cancel the dark spell if they still had access to their keys, but would allow the recovery members to rotate the signers if the multisig owner lost their keys.

## Interface

- Day of the week must be between 1 and 7, where 1 is Monday and 7 is Sunday.
- Start hour and end hour must be between 0 and 23.
- Start hour must be less than end hour.
- The time range is inclusive, meaning that if a transaction is submitted at the start hour or end hour, it will be allowed.
- The time range is in GMT time, so this should be factored in when creating settings.
- Each day can only have a single range of times. It is not possible currently to have multiple ranges per day.

## Usage

In order to configure this contract to work with a Gnosis Safe, use the following steps:

1. Deploy a timelock contract with the desired delay, guardian, pause duration, whitelisted targets, calldatas, with the users' Gnosis Safe as the owner.
2. Queue a transaction in the Gnosis Safe to perform the following actions:
   - initialize configuration with the timelock address, and allowed time ranges and their corresponding allowed days
   - add the guard to the Safe
   - add the Timelock as a Safe module
3. Execute the queued transaction. This will set the timelock as a module of the Safe, and the Safe will now only allow transactions to be executed within the time ranges specified.
4. To edit the time range, call the `editTimeRange` function with the new time range. This will replace the existing time range for that day. This function cannot be called if the day does not have a time range already set.
5. Remove all time ranges by calling the `disableGuard()` function. This will allow all transactions to be executed regardless of time submitted.

## Edge Cases

- If no time ranges are added, all transactions are allowed.
- To remove all time ranges, the `disableGuard()` function can be called. Once called, all transactions are allowed, regardless of time submitted.
- If a transaction is submitted on chain outside of the allowed time ranges, it will revert.
- If the timelock is removed as a module from the Safe before the TimeRestricted guard is disabled, there will be no way to rotate the signers of the Safe, add new modules, or remove modules. This is because the TimeRestricted guard will prevent these actions from being executed.


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
