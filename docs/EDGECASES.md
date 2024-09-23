# System Edge Cases

## Malicious Hot Signer

If a user's hot signer key is compromised, funds are sent to the timelock address on another chain where the wallet has yet to be created, and a malicious user creates a wallet with the same address as the timelock, the malicious user can drain the timelock. They can call InstanceDeployer and create a new Instance, passing their own calldata, which will allow them to drain all funds from the timelock.

# Wrapped vs Raw Ether

The timelock does not have any checks on sending Raw Ether to whitelisted protocols. If an incorrect contract address is whitelisted and a corresponding function that accepts ETH in a malicious manner is also whitelisted, the timelock could potentially be drained of all its ETH. This can be mitigated by wrapping the ETH in the timelock into WETH. It is recommended to use WETH for all ETH transactions in the timelock and to whitelist the WETH deposit function. This enables all hot signers to wrap any ETH in the timelock to WETH, but not unwrap it.

Value is not checked for hot signer calls, which means if a protocol allows excess value to be sent and not refunded, and that protocol is whitelisted, the timelock's eth can be drained. This can be mitigated by wrapping the ETH in the timelock into WETH and not allowing unwrapping by the hot signers.

## Recovery Spells and Front Running

If an attacker finds a counterfactual timelock address on a chain where it has not been deployed yet. They can front-run and deploy a safe to that chain without using the Instance Deployer. However, they cannot call `createSystemInstance` on the Instance Deployer as they do not have the hot signer private key to deploy the timelock. This means that the recovery spells are safe from front-running attacks because once the safe is deployed by the attacker, a recovery spell can be created, but it cannot be used because it is not a module in the safe yet. It can only become a module in the safe once the system is deployed from the InstanceDeployer, at which point the recovery spell becomes a module in the safe.

Recovery spells cannot be deployed unless a safe is deployed first.

Order of operations for deployment (unexpected):

1. Deploy safe
2. Deploy recovery spell
3. Deploy system instance

Alternative order of operations for deployment (expected):

1. Deploy system instance
2. Deploy recovery spell

# Malicious Collusion

If both the guardian and recovery signers are malicious, they could collude to take over the system. The guardian could pause the system and the recovery signers could execute a recovery spell to drain the timelock, which the cold signers could not counter. This can be mitigated by having a trusted guardian and recovery signers and neither having knowledge of the other, so in case one defects, funds are still safe. Alternatively, a user could opt to only have a guardian or recovery signers, but not both.

# Proposal Lifecycle

This section will explore the lifecycle of the proposal from scheduling to execution and describe all of the system states along the way.

## Assumptions

All system contracts are deployed across chains using the Arachnid Create2 deployer contract. This means the timelock factory, guard, multicall3, and safe addresses will be the same across all chains. If this is not true, then the system will not work as expected.


## Deployer Parameters
- hot signers must be the same across all chains and the hot signer in the deployment list must not be compromised. A compromised hot signer can take over and drain a new timelock it deploys.

## Timelock Parameters
- The Timelock Factory uses the message sender to calculate the address of the timelock. This means the timelock address will be the same across all chains as the TimelockFactory is called by the InstanceDeployer.

## Deployment Parameters
- The following parameters can affect the deployment address of the system:
  - gnosis safe owners
  - gnosis safe quorum
  - timelock delay
  - timelock expiration period
  - pause guardian
  - pause duration
  - hot signers
  - salt
If the aforemented parameters are changed, the address of the deployed contracts will change.

- The following parameters do not affect the deployment address of the system:
  - recovery spells (this would create a circular dependency if it was used to calculate the address, meaning no recovery spells could be provided during construction)
  - whitelisted targets, selectors and calldatas

This means if the aforementioned parameters are changed, the changes should not affect the address of the deployed contracts.

## Future Standards

This wallet does not support future token standards that may be developed. This system is intentionally immutable and new protocols and token standards can only be supported by creating a new system instance with the updated contracts.

### Malicious Recovery Spell Scenario

If the time delay on a recovery spell is shorter than the timelock, the recovery spell can kick the safe owners without the current safe owners being able to veto this change. This is why it is important to have a longer time delay on the recovery spells than on the timelock.

### Malicious Safe Signer Takeover Scenario

Conversely, if the Safe keys are compromised, and the recovery spell time delay is longer than the timelock, then the attacker can rotate the keys on the Safe through a timelocked transaction and remove the recovery spell as a module. However, if the guardian is set, and the pause duration is longer than the recovery spell period, the guardian can pause the timelock, cancelling all malicious proposals, which stops them from being executed, and then the recovery spell can execute and rotate signing keys.

## Guardian

Given the following scenario:

1. Cold signers are compromised
2. Guardian and social recovery module are set
3. Recovery spell delay is shorter than guardian pause duration

The guardian can pause the timelock, cancelling all malicious proposals, which stops them from being executed, and then the recovery spell can execute and rotate signing keys.

### Malicious Recovery Spell Scenario with Guardian

If the guardian is set, and a recovery spell is malicious, the guardian cannot veto this change. This is why it is important to have a longer time delay on the recovery spells than the timelock.

### Malicious Safe Signer Takeover Scenario with Guardian

If the Safe keys are compromised, and the guardian is set, and the guardian can be reached before a malicious proposal becomes executable, and a recovery spell exists whose time delay is shorter than the guardian pause duration, the guardian can pause the timelock, cancelling all malicious proposals, which stops them from being executed, and then the recovery spell can execute and rotate signing keys.

## Timelock

The timelock calldata whitelisting feature can be abused and set to malicious targets, or targets such as DEX's that allow swapping of tokens. If malicious targets and calldatas are whitelisted, the timelock can have all of its funds drained immediately.

It is recommended to have the timelock delay be shorter than the recovery spell delay so that the timelock can cancel malicious recovery spells.

## Onchain Policy Engine

The timelock calldata whitelisting feature acts as an onchain policy engine, enforcing that transactions the hot signers send are guaranteed to match the whitelisted calldata. This is a powerful feature that can be used to enforce that the hot signers can never lose funds or sign messages that can drain the wallet. This speeds the process of interacting with DeFi protocols for power users who want the ability to quickly interact with DeFi protocols without the cognitive overhead of checking calldata byte-by-byte.
