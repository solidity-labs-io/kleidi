# Addresses

This system version relies on Safe release [1.3.0](https://github.com/safe-global/safe-smart-account/blob/bf943f80fec5ac647159d26161446ac5d716a294/CHANGELOG.md#version-130-libs0). The following addresses are used in the system across all chains:

```MULTICALL3: 0xcA11bde05977b3631167028862bE2a173976CA11```

```SAFE_LOGIC: 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552```

```GNOSIS_SAFE_PROXY_FACTORY: 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2```

All system contracts will be deployed using the Create2 Factory embedded within Foundry. The system addresses will be the same across all chains to ensure addresses for user contracts match up across all chains, allowing deterministic and counterfactual deployments.
