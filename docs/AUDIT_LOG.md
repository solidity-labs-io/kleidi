# Audit Log

**08/26/24** - While writing the Certora specifications for the pause functionality, it was discovered that the pause duration could be extended after a pause, thus re-pausing an already unpaused contract. This issue was remediated in commit [f3752cb5793f0b8ae83d02a74867967b9d87ca56](https://github.com/solidity-labs-io/safe-time-guard/pull/17/commits/f3752cb5793f0b8ae83d02a74867967b9d87ca56).

**09/17/24** - Function `addCalldataCheck` can be removed from the contract to save bytecode space.
`updateDelay` should not be able to cause live proposals to extend or delay their current execution time.
`updateExpirationPeriod` can cause an executable proposal to become unexecutable, and conversely cause a non executable proposal to become executable. This is expected behavior.
`updatePauseDuration` can only be called while the contract is not paused, therefore it cannot re-pause the contract.

Timelock contract had its Access Controls checked to ensure only authorized users can call certain functions. A unit test was added to ensure that hot signers could not create new roles. Making the Timelock upgradeable was discussed at a surface level. This would necessitate adding a padding variable at the start of the contract for the implementation address.

-------------------------------------------------------
|           Function            |       Access        |
|-------------------------------|---------------------|
|       schedule                |      safe           |
|       scheduleBatch           |      safe           |     
|       cancel                  |      safe           |  
|       pause                   |      pauser         |  
|       revokeHotSigner         |      safe           |        
|       executeWhitelisted      |      hot signer     |                
|       executeWhitelistedBatch |      hot signer     |                     
|       setGuardian             |      timelock       |       
|       addCalldataCheck        |      timelock       |            
|       addCalldataChecks       |      timelock       |             
|       removeCalldataCheck     |      timelock       |               
|       removeAllCalldataChecks |      timelock       |                   
|       updateDelay             |      timelock       |       
|       updateExpirationPeriod  |      timelock       |                  
|       updatePauseDuration     |      timelock       |               
|       execute                 |      open           |
|       executeBatch            |      open           |     
|       cleanup                 |      open           |
|       grantRole               |      timelock(admin)|
|       revokeRole              |      timelock(admin)|
|       renounceRole            |      hot signer     |

Contracts `Guard`, `InstanceDeployer` had all of their lines of code reviewed.

Timelock specification was reviewed and re-run with a minor [specification change](https://prover.certora.com/output/651303/d811372eab754157862d4db4937f6500?anonymousKey=24e38bec8ccd5467acec7d2b311a76b092227624) to ensure the `setLength` function in the formal specification was correct. The specification was found to be correct in its `setLength` function because the induction base case in the constructor with concrete values failed, and the remaining cases failed the vaccuity check, which means they always were false for any input. This confirms that this function worked as expected.

**09/18/24** - RecoverySpell contract was found to have issues with the way it calculated the number of calls. If the recovery spell only had a single signer, it would try to add that signer two times, which would fail and cause the recovery to not work. It was also found that owners in the recovery spell could be the 0 address, so a check was added in the factory to prevent this.

**09/22/24** - The RecoverySpell contract was found to have an issue with how it recovered signatures, making it vulnerable to signature malleability. This was fixed by using the OZ ecrecover library which checks for manipulated signatures. Events that were not being indexed were also fixed to be indexed to make it easier for the front end to search and filter events.

**09/23/24** - Calldatacheck logic in Timelock contract was found to have issue where a duplicate AND check can be added for the same start and end indexes for a selector. It would make it impossible for a hot signer to take actions for the given protocol. Also, it was found that overlapping index ranges could be added which should not be possible. Also, the removal of a single OR check is not possible, first all the OR checks have to be removed and then re add the needed checks, which should not be the case.

**09/24/24** - The Timelock contract was found to have an issue where an empty check could be added by passing an empty array of checks to the addCallDataCheck functions. This empty check would be impossible to fulfill on its own, meaning other checks would need to be added to that same index to make it possible to pass that given index check as a hot signer. Also, the Timelock factory contract had its mapping of deployed contracts removed to cut down on its bytecode size.

**09/30/24** - The selfAddressCheck logic was removed from the timelock to simplify the contract.
