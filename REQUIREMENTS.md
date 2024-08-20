# Overview

The user must never remove the timelock from the safe as a module. If they do, the user will never be able to rotate their signers, change quorum, or upgrade their safe logic contract, except with a recovery spell or other module that is authorized.

The only way to safely remove the timelock as a module on the safe is to first remove the guard, then remove the timelock as a module. This way, the user can still rotate their signers, change quorum, and upgrade their safe logic contract.

## Deployment

All deployments must be done through the [InstanceDeployer.sol](src/InstanceDeployer.sol) contract. If a user attempts to deploy the contracts directly, it should be assumed that the system is unsafe due to the timelock being able to be initialized without checks. Additionally, unsafe modules could be added to the Timelock.

## Guard

The Guard contract prevents the Safe contract from directly modifying its own parameters. Instead, it requires the Timelock to make changes to the Safe contract. This is to prevent the Safe contract from instantly rotating signers, changing quorum or upgrading its implementation contract.

## Recovery Spells

Recovery spells are modules that are authorized to make changes to the Safe contract without the Timelock. These are used to recover the Safe contract in the event that the safe signers permanently go offline. If the time delay on a recovery spell is shorter than the timelock, the recovery spell can kick the safe owners without the current safe owners being able to veto this change. This is why it is important to have a longer time delay on the recovery spells than on the timelock.

## Timelock

The timelock calldata whitelisting feature can be abused and set to malicious targets, or targets such as DEX's that allow swapping of tokens. If malicious targets and calldatas are whitelisted, the timelock can have all of its funds drained immediately.

## Onchain Policy Engine

The timelock calldata whitelisting feature acts as an onchain policy engine, enforcing that transactions the hot signers send are guaranteed to match the whitelisted calldata. This is a powerful feature that can be used to enforce that the hot signers can never lose funds or sign messages that can drain the wallet. This speeds the process of interacting with DeFi protocols for power users who want the ability to quickly interact with DeFi protocols without the cognitive overhead of checking calldata byte-by-byte.

## Gnosis Safe

The Gnosis Safe should only be created through the [InstanceDeployer.sol](src/InstanceDeployer.sol) contract. If it is created through another means, it will not be able to be properly initialized automatically using the InstanceDeployer.