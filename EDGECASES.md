# System Edge Cases

If a user's hot signer key is compromised, funds are sent to the timelock address on another chain where the wallet has yet to be created, and a malicious user creates a wallet with the same address as the timelock, the malicious user can drain the timelock. They can call InstanceDeployer and create a new Instance, passing their own calldata, which will allow them to drain all funds from the timelock.

Value is not checked for hot signer calls, which means if a protocol allows excess value to be sent and not refunded, and that protocol is whitelisted, the timelock's eth can be drained. This can be mitigated by wrapping the ETH in the timelock into WETH.