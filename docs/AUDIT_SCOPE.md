# Audit Scope

The following contracts are in scope for the audit:

- [x] [src/ConfigurablePause.sol](../src/ConfigurablePause.sol)
- [x] [src/Timelock.sol](../src/Timelock.sol)
- [x] [src/TimelockFactory.sol](../src/TimelockFactory.sol)
- [x] [src/Guard.sol](../src/Guard.sol)
- [x] [src/views/AddressCalculation.sol](../src/views/AddressCalculation.sol)
- [x] [src/utils/Create2Helper.sol](../src/utils/Create2Helper.sol)
- [x] [src/utils/Constants.sol](../src/utils/Constants.sol)
- [x] [src/InstanceDeployer.sol](../src/InstanceDeployer.sol)
- [x] [src/RecoverySpell.sol](../src/RecoverySpell.sol)
- [x] [src/RecoverySpellFactory.sol](../src/RecoverySpellFactory.sol)
- [x] [src/deploy/SystemDeploy.s.sol](../src/deploy/SystemDeploy.s.sol)
- [x] [src/BytesHelper.sol](../src/BytesHelper.sol) Function `getFirstWord` is out of scope in this file.

## Lines of Code

```
cloc src/RecoverySpell.sol src/RecoverySpellFactory.sol src/ConfigurablePause.sol src/Timelock.sol src/TimelockFactory.sol src/Guard.sol src/views/AddressCalculation.sol src/utils/* src/BytesHelper.sol src/deploy/SystemDeploy.s.sol src/InstanceDeployer.sol 
```

Output:
```
      12 text files.
      12 unique files.                              
       0 files ignored.

github.com/AlDanial/cloc v 1.94  T=0.03 s (454.4 files/s, 109961.9 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Solidity                        12            378            916           1610
-------------------------------------------------------------------------------
SUM:                            12            378            916           1610
-------------------------------------------------------------------------------
```

## Out of Scope

The following findings are out of scope for the audit:
- any items or known issues in the documentation are out of scope
- any items or edgecases described in the codebase itself are out of scope
- any items found in the Recon audit are out of scope
