# System Edge Cases

If a user's hot signer key is compromised, funds are sent to the timelock address on another chain where the wallet has yet to be created, and a malicious user creates a wallet with the same address as the timelock, the malicious user can drain the timelock. They can call InstanceDeployer and create a new Instance, passing their own calldata, which will allow them to drain all funds from the timelock.

Value is not checked for hot signer calls, which means if a protocol allows excess value to be sent and not refunded, and that protocol is whitelisted, the timelock's eth can be drained. This can be mitigated by wrapping the ETH in the timelock into WETH.

# Wrapped vs Raw Ether

The timelock does not have any checks on sending Raw Ether to whitelisted protocols. If an incorrect contract address is whitelisted and a corresponding function that accepts ETH in a malicious manner is also whitelisted, the timelock could potentially be drained of all its ETH. This can be mitigated by wrapping the ETH in the timelock into WETH. It is recommended to use WETH for all ETH transactions in the timelock and to whitelist the WETH deposit function. This enables all hot signers to wrap any ETH in the timelock to WETH, but not unwrap it.

# Proposal Lifecycle

This section will explore the lifecycle of the proposal from scheduling to execution and describe all of the system states along the way.

## timestamps and _liveProposals

The two variables timestamps and _liveProposals are closely related. When a proposal has been proposed, the proposal timestamp is set to the current block timestamp plus the delay. The proposal id is then added to the _liveProposals enumerable set.

### Scheduled
- **timestamps[id]**: block.timestamp + delay
- **_liveProposals**: contains id

### Executed
- **timestamps[id]**: 1
- **_liveProposals**: does not contain id

### Canceled
- **timestamps[id]**: 0
- **_liveProposals**: does not contain id

### Expired & Not Cleaned Up
- **timestamps[id]**: block.timestamp + delay
- **_liveProposals**: does contain id

### Expired & Cleaned Up
- **timestamps[id]**: block.timestamp + delay
- **_liveProposals**: does not contain id
