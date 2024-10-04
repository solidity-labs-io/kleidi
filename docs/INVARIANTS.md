# System Invariants

## Timelock Variables

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

## Timelock Parameters

The timelock can never have whitelisted calldata to the safe or the timelock itself. This is to prevent the hot signers from being able to execute arbitrary transactions on the safe or itself.

## Timelock Calldata

All calldata checks must be isolated to predefined calldata segments, for example given calldata with three parameters:

 0xffffeecc000000000000000112818929111111000000000000000112818929111111000000000000000112818929111111

  0xffffeecc


```
                    1.                              2.                             3.
       000000000000000112818929111111
                                     000000000000000112818929111111
                                                                   000000000000000112818929111111
                    
                    A                               B                              C
                    D                               E                              F
                 a || d           &&             b || e             &&          c || f
```

example hot signer call to function

parameter 1 was A, Parameter 2 was E, parameter 3 was G

checks must be applied in a way such that they do not overlap with each other. It is important that the calldata checks are isolated to specific segments of the calldata to ensure no duplicate checks are allowed.

A given function on a contract can have multiple calldata checks for different indexes, but they must not share the same start or end indexes or overlap.

## Recovery Spells

Recovery spells are modules that are authorized to make changes to the Safe contract without the Timelock. These are used to recover the Safe contract in the event that the safe signers permanently go offline.

The following must always be true for any recovery spell created through the factory:

- The recovery threshold must be greater than or equal to 0 and less than or equal to the number of new owners.
- The threshold must be greater than or equal to 1 and less than or equal to the number of new owners.
- The new owners are all non zero addresses.
- There are no duplicate new owners.
- There is at least one new owner.
- The recovery delay is less than or equal to one year.
- The recovery spell can not be created if the safe contract has not been deployed.