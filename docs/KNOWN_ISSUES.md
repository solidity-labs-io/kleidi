# Known Issues

The following are known issues with the Kleidi system:
- if the cold signers are malicious or compromised, they can execute transactions to compromise the system if neither recovery spells or the guardian are used
- if the hot signers are malicious or compromised, they can deploy a compromised system instance on a new chain with compromised recovery spells and malicious calldata checks that allow funds to be stolen
- if DEX's are whitelisted, this opens up the ability for the hot signers to steal funds from the system via high slippage and front and back running
- if a malicious protocol is whitelisted, this opens up the ability for hot signers to inadvernantly lose funds
- if a non-malicious but improperly configured protocol is whitelisted, this opens up the ability for hot signers to inadvernantly lose funds by using a protocol incorrectly
- fee on transfer tokens may make the actual amount of tokens sent to destinations less or more than expected, this finding is out of scope for the system
- the system only works on EVM compatible chains, does not work on chains that have not undergone the Shanghai EVM upgrade
- the system only works with contracts that have a known ABI, it does not work with contracts that have dynamic ABIs
- the return value of token transfers are unchecked, however the call to the token contract is checked, the timelock has no accounting mechanisms
- salt in the DeploymentParams struct is not used in the call to createSystemInstance, this is a known issue, but is not a security concern. The same system instance with the same parameters can only be deployed once.
