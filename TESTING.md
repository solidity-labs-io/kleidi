# Test List

- cross chain deployment, same contract addresses, different whitelisted calldata and addresses

## Scenario Test

- [ ] deploy safe with timelock, guard, and recovery spell, safe owners enact malicious proposal, guardian pauses, recovery spell rotates signers, new transactions are sent
- [ ] hot signers move funds from one DeFi protocol to another
- [ ] hot signers get revoked by the Safe
- [ ] privilege escalation impossible by hot signers
- [ ] mutative functions cannot be called while paused

# Formal Verification

- [ ] pausing cancels all in flight proposals
- [ ] not possible to have more than one admin
- [ ] not possible to create new roles => implies no other roles outside of admin and hot signers can have any addresses in their list
- [ ] timelock duration is always less than or equal to the maximum timelock duration, and always greater than or equal to the minimum timelock duration