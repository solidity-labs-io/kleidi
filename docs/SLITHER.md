# Slither Detectors

command:
```bash
slither src/Timelock.sol --solc-remaps '@openzeppelin-contracts/=lib/openzeppelin-contracts/ @safe/=lib/safe-smart-account/contracts/ @src/=src/ @interface/=src/interface/'
```


output:

```
Timelock._execute(address,uint256,bytes) (src/Timelock.sol#980-985) sends eth to arbitrary user
	Dangerous calls:
	- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#functions-that-send-ether-to-arbitrary-destinations
Comment: This is intended behavior, this function can only be accessed by privileged users.

INFO:Detectors:
IERC165 is re-used:
	- IERC165 (lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol#15-25)
	- IERC165 (lib/safe-smart-account/contracts/interfaces/IERC165.sol#5-15)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#name-reused
Comment: These are library files, and the OZ implementation is correctly imported into the Timelock file.


INFO:Detectors:
Reentrancy in Timelock.execute(address,uint256,bytes,bytes32) (src/Timelock.sol#601-621):
	External calls:
	- _execute(target,value,payload) (src/Timelock.sol#614)
		- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
	State variables written after the call(s):
	- _afterCall(id) (src/Timelock.sol#620)
		- timestamps[id] = _DONE_TIMESTAMP (src/Timelock.sol#973)
	Timelock.timestamps (src/Timelock.sol#118) can be used in cross function reentrancies:
	- Timelock._afterCall(bytes32) (src/Timelock.sol#968-974)
	- Timelock._schedule(bytes32,uint256) (src/Timelock.sol#958-964)
	- Timelock.cancel(bytes32) (src/Timelock.sol#669-677)
    Comment: the cancel function could not be called in cross function reentrancy because it has to be able to remove the operation from the _liveProposals set, which has already happened in the execute function. Thus reentry to the cancel function is not possible.
	- Timelock.isOperation(bytes32) (src/Timelock.sol#407-409)
	- Timelock.isOperationDone(bytes32) (src/Timelock.sol#422-424)
	- Timelock.isOperationExpired(bytes32) (src/Timelock.sol#428-437)
	- Timelock.isOperationReady(bytes32) (src/Timelock.sol#414-419)
    Comment: view only reentrancy is technically possible here, but since there are no external protocols or systems that rely on the timestamp, this is not a vulnerability.
	- Timelock.pause() (src/Timelock.sol#699-712)
Comment: the pause function could not cause cross function reentrancy because at the point pause is called, the operation will already be removed from the _liveProposals set. Thus reentry to the pause function is not possible.
	- Timelock.timestamps (src/Timelock.sol#118)

Reentrancy in Timelock.executeBatch(address[],uint256[],bytes[],bytes32) (src/Timelock.sol#633-662):
	External calls:
	- _execute(targets[i],values[i],payload) (src/Timelock.sol#654)
		- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
	State variables written after the call(s):
	- _afterCall(id) (src/Timelock.sol#661)
		- timestamps[id] = _DONE_TIMESTAMP (src/Timelock.sol#973)
	Timelock.timestamps (src/Timelock.sol#118) can be used in cross function reentrancies:
	- Timelock._afterCall(bytes32) (src/Timelock.sol#968-974)
	- Timelock._schedule(bytes32,uint256) (src/Timelock.sol#958-964)
	- Timelock.cancel(bytes32) (src/Timelock.sol#669-677)
	- Timelock.isOperation(bytes32) (src/Timelock.sol#407-409)
	- Timelock.isOperationDone(bytes32) (src/Timelock.sol#422-424)
	- Timelock.isOperationExpired(bytes32) (src/Timelock.sol#428-437)
	- Timelock.isOperationReady(bytes32) (src/Timelock.sol#414-419)
	- Timelock.pause() (src/Timelock.sol#699-712)
	- Timelock.timestamps (src/Timelock.sol#118)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities
Comment: same as `execute` function

INFO:Detectors:
Timelock.isOperationDone(bytes32) (src/Timelock.sol#422-424) uses a dangerous strict equality:
	- timestamps[id] == _DONE_TIMESTAMP (src/Timelock.sol#423)
ConfigurablePauseGuardian.paused() (src/ConfigurablePauseGuardian.sol#76-80) uses a dangerous strict equality:
	- pauseStartTime == 0 (src/ConfigurablePauseGuardian.sol#77-79)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#dangerous-strict-equalities
Comment: The strict equality is used to check if the operation is done or not or if the contract is paused or not. This is not a vulnerability and is expected behavior. There is no way for the `timestamps` to be set to any value other than 1 when executed, or the current block timestamp on proposal. The pauseStartTime is set to 0 when the contract is not paused, and the pauseStartTime is set to the current block timestamp when the contract is paused. Thus the strict equality is safe to use in this context.

INFO:Detectors:
AccessControlEnumerable._grantRole(bytes32,address) (lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol#64-70) ignores return value by _roleMembers[role].add(account) (lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol#67)
AccessControlEnumerable._revokeRole(bytes32,address) (lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol#75-81) ignores return value by _roleMembers[role].remove(account) (lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol#78)
Timelock._addCalldataCheck(address,bytes4,uint16,uint16,bytes[],bool[]) (src/Timelock.sol#994-1083) ignores return value by indexes[indexLength].dataHashes.add(dataHash) (src/Timelock.sol#1073)
Timelock._removeCalldataCheck(address,bytes4,uint256) (src/Timelock.sol#1124-1167) ignores return value by indexCheck.dataHashes.remove(removedDataHashes[i]) (src/Timelock.sol#1146)
Timelock._removeCalldataCheck(address,bytes4,uint256) (src/Timelock.sol#1124-1167) ignores return value by indexCheck.dataHashes.add(dataHashes[i_scope_0]) (src/Timelock.sol#1154)
Timelock._removeCalldataCheck(address,bytes4,uint256) (src/Timelock.sol#1124-1167) ignores return value by lastIndexCheck.dataHashes.remove(dataHashes[i_scope_0]) (src/Timelock.sol#1155)
Timelock._removeAllCalldataChecks(address,bytes4) (src/Timelock.sol#1176-1210) ignores return value by removedCalldataCheck.dataHashes.remove(dataHashes[i]) (src/Timelock.sol#1202)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#unused-return
INFO:Detectors:
Timelock.constructor(address,uint256,uint256,address,uint128,address[])._safe (src/Timelock.sol#280) lacks a zero-check on :
		- safe = _safe (src/Timelock.sol#287)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation
Comment: This is intended behavior, the `_safe` variable is set to the address of the Safe contract, which is a required parameter for the Timelock contract to function. The Safe bytecode check is performed in the InstanceDeployer, so a safe with Address(0) cannot be deployed.

INFO:Detectors:
Safe.checkNSignatures(bytes32,bytes,bytes,uint256) (lib/safe-smart-account/contracts/Safe.sol#274-334) has external calls inside a loop: require(bool,string)(ISignatureValidator(currentOwner).isValidSignature(data,contractSignature) == EIP1271_MAGIC_VALUE,GS024) (lib/safe-smart-account/contracts/Safe.sol#315)
Timelock._execute(address,uint256,bytes) (src/Timelock.sol#980-985) has external calls inside a loop: (success) = target.call{value: value}(data) (src/Timelock.sol#983)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation/#calls-inside-a-loop
INFO:Detectors:
Reentrancy in Safe.execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes) (lib/safe-smart-account/contracts/Safe.sol#139-221):
	External calls:
	- Guard(guard).checkTransaction(to,value,data,operation,safeTxGas,baseGas,gasPrice,gasToken,refundReceiver,signatures,msg.sender) (lib/safe-smart-account/contracts/Safe.sol#177-192)
	External calls sending eth:
	- payment = handlePayment(gasUsed,baseGas,gasPrice,gasToken,refundReceiver) (lib/safe-smart-account/contracts/Safe.sol#211)
		- require(bool,string)(receiver.send(payment),GS011) (lib/safe-smart-account/contracts/Safe.sol#243)
	Event emitted after the call(s):
	- ExecutionFailure(txHash,payment) (lib/safe-smart-account/contracts/Safe.sol#214)
	- ExecutionSuccess(txHash,payment) (lib/safe-smart-account/contracts/Safe.sol#213)
Reentrancy in Timelock.execute(address,uint256,bytes,bytes32) (src/Timelock.sol#601-621):
	External calls:
	- _execute(target,value,payload) (src/Timelock.sol#614)
		- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
	Event emitted after the call(s):
	- CallExecuted(id,0,target,value,payload) (src/Timelock.sol#615)
Reentrancy in Timelock.executeBatch(address[],uint256[],bytes[],bytes32) (src/Timelock.sol#633-662):
	External calls:
	- _execute(targets[i],values[i],payload) (src/Timelock.sol#654)
		- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
	Event emitted after the call(s):
	- CallExecuted(id,i,targets[i],values[i],payload) (src/Timelock.sol#655)
Reentrancy in Timelock.executeWhitelisted(address,uint256,bytes) (src/Timelock.sol#727-738):
	External calls:
	- _execute(target,value,payload) (src/Timelock.sol#735)
		- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
	Event emitted after the call(s):
	- CallExecuted(bytes32(0),0,target,value,payload) (src/Timelock.sol#737)
Reentrancy in Timelock.executeWhitelistedBatch(address[],uint256[],bytes[]) (src/Timelock.sol#745-767):
	External calls:
	- _execute(target,value,payload) (src/Timelock.sol#763)
		- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
	Event emitted after the call(s):
	- CallExecuted(bytes32(0),i,target,value,payload) (src/Timelock.sol#765)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-3
INFO:Detectors:
ConfigurablePauseGuardian.pauseUsed() (src/ConfigurablePauseGuardian.sol#69-71) uses timestamp for comparisons
	Dangerous comparisons:
	- pauseStartTime != 0 (src/ConfigurablePauseGuardian.sol#70)
ConfigurablePauseGuardian.paused() (src/ConfigurablePauseGuardian.sol#76-80) uses timestamp for comparisons
	Dangerous comparisons:
	- pauseStartTime == 0 (src/ConfigurablePauseGuardian.sol#77-79)
	- block.timestamp <= pauseStartTime + pauseDuration (src/ConfigurablePauseGuardian.sol#77-79)
Timelock.isOperation(bytes32) (src/Timelock.sol#407-409) uses timestamp for comparisons
	Dangerous comparisons:
	- timestamps[id] > 0 (src/Timelock.sol#408)
Timelock.isOperationReady(bytes32) (src/Timelock.sol#414-419) uses timestamp for comparisons
	Dangerous comparisons:
	- timestamp > _DONE_TIMESTAMP && timestamp <= block.timestamp && timestamp + expirationPeriod > block.timestamp (src/Timelock.sol#417-418)
Timelock.isOperationDone(bytes32) (src/Timelock.sol#422-424) uses timestamp for comparisons
	Dangerous comparisons:
	- timestamps[id] == _DONE_TIMESTAMP (src/Timelock.sol#423)
Timelock.isOperationExpired(bytes32) (src/Timelock.sol#428-437) uses timestamp for comparisons
	Dangerous comparisons:
	- require(bool,string)(timestamp != 0,Timelock: operation non-existent) (src/Timelock.sol#433)
	- require(bool,string)(timestamp != 1,Timelock: operation already executed) (src/Timelock.sol#434)
	- block.timestamp >= timestamp + expirationPeriod (src/Timelock.sol#436)
Timelock.cancel(bytes32) (src/Timelock.sol#669-677) uses timestamp for comparisons
	Dangerous comparisons:
	- require(bool,string)(isOperation(id) && _liveProposals.remove(id),Timelock: operation does not exist) (src/Timelock.sol#670-673)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#block-timestamp
INFO:Detectors:
EnumerableSet.values(EnumerableSet.Bytes32Set) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#219-229) uses assembly
	- INLINE ASM (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#224-226)
EnumerableSet.values(EnumerableSet.AddressSet) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#293-303) uses assembly
	- INLINE ASM (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#298-300)
EnumerableSet.values(EnumerableSet.UintSet) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#367-377) uses assembly
	- INLINE ASM (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#372-374)
Safe.checkNSignatures(bytes32,bytes,bytes,uint256) (lib/safe-smart-account/contracts/Safe.sol#274-334) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/Safe.sol#303-305)
	- INLINE ASM (lib/safe-smart-account/contracts/Safe.sol#311-314)
Safe.getChainId() (lib/safe-smart-account/contracts/Safe.sol#352-359) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/Safe.sol#355-357)
Executor.execute(address,uint256,bytes,Enum.Operation,uint256) (lib/safe-smart-account/contracts/base/Executor.sol#21-39) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/Executor.sol#30-32)
	- INLINE ASM (lib/safe-smart-account/contracts/base/Executor.sol#35-37)
FallbackManager.internalSetFallbackHandler(address) (lib/safe-smart-account/contracts/base/FallbackManager.sol#20-41) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/FallbackManager.sol#38-40)
FallbackManager.fallback() (lib/safe-smart-account/contracts/base/FallbackManager.sol#61-81) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/FallbackManager.sol#64-80)
GuardManager.setGuard(address) (lib/safe-smart-account/contracts/base/GuardManager.sol#53-63) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/GuardManager.sol#59-61)
GuardManager.getGuard() (lib/safe-smart-account/contracts/base/GuardManager.sol#72-78) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/GuardManager.sol#75-77)
ModuleManager.execTransactionFromModuleReturnData(address,uint256,bytes,Enum.Operation) (lib/safe-smart-account/contracts/base/ModuleManager.sol#104-125) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/ModuleManager.sol#112-124)
ModuleManager.getModulesPaginated(address,uint256) (lib/safe-smart-account/contracts/base/ModuleManager.sol#144-175) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/ModuleManager.sol#172-174)
ModuleManager.isContract(address) (lib/safe-smart-account/contracts/base/ModuleManager.sol#183-190) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/base/ModuleManager.sol#186-188)
SecuredTokenTransfer.transferToken(address,address,uint256) (lib/safe-smart-account/contracts/common/SecuredTokenTransfer.sol#18-37) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/common/SecuredTokenTransfer.sol#22-36)
SignatureDecoder.signatureSplit(bytes,uint256) (lib/safe-smart-account/contracts/common/SignatureDecoder.sol#21-35) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/common/SignatureDecoder.sol#23-34)
StorageAccessible.getStorageAt(uint256,uint256) (lib/safe-smart-account/contracts/common/StorageAccessible.sol#17-27) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/common/StorageAccessible.sol#21-24)
StorageAccessible.simulateAndRevert(address,bytes) (lib/safe-smart-account/contracts/common/StorageAccessible.sol#40-50) uses assembly
	- INLINE ASM (lib/safe-smart-account/contracts/common/StorageAccessible.sol#42-49)
BytesHelper.getFunctionSignature(bytes) (src/BytesHelper.sol#7-17) uses assembly
	- INLINE ASM (src/BytesHelper.sol#14-16)
BytesHelper.getFirstWord(bytes) (src/BytesHelper.sol#21-31) uses assembly
	- INLINE ASM (src/BytesHelper.sol#28-30)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#assembly-usage
INFO:Detectors:
Different versions of Solidity are used:
	- Version used: ['0.8.25', '>=0.7.0<0.9.0', '^0.8.0', '^0.8.20']
	- 0.8.25 (src/BytesHelper.sol#1)
	- 0.8.25 (src/ConfigurablePauseGuardian.sol#1)
	- 0.8.25 (src/Timelock.sol#3)
	- 0.8.25 (src/utils/Constants.sol#3)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/Safe.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/Executor.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/FallbackManager.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/GuardManager.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/ModuleManager.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/OwnerManager.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/Enum.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/NativeCurrencyPaymentFallback.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/SecuredTokenTransfer.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/SelfAuthorized.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/SignatureDecoder.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/Singleton.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/StorageAccessible.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/external/SafeMath.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/interfaces/IERC165.sol#2)
	- >=0.7.0<0.9.0 (lib/safe-smart-account/contracts/interfaces/ISignatureValidator.sol#2)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/access/AccessControl.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/access/IAccessControl.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/access/extensions/IAccessControlEnumerable.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/utils/Context.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol#4)
	- ^0.8.20 (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#5)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used
INFO:Detectors:
Timelock.pause() (src/Timelock.sol#699-712) has costly operations inside a loop:
	- delete timestamps[id] (src/Timelock.sol#707)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#costly-operations-inside-a-loop
Comment: This is expected behavior. The loop is only iterating over the operations that are currently live, and the delete and remove operation is necessary to remove the operation from the live operations set.

INFO:Detectors:
Context._contextSuffixLength() (lib/openzeppelin-contracts/contracts/utils/Context.sol#25-27) is never used and should be removed
Context._msgData() (lib/openzeppelin-contracts/contracts/utils/Context.sol#21-23) is never used and should be removed
EnumerableSet.add(EnumerableSet.UintSet,uint256) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#317-319) is never used and should be removed
EnumerableSet.at(EnumerableSet.UintSet,uint256) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#355-357) is never used and should be removed
EnumerableSet.contains(EnumerableSet.AddressSet,address) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#260-262) is never used and should be removed
EnumerableSet.contains(EnumerableSet.UintSet,uint256) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#334-336) is never used and should be removed
EnumerableSet.length(EnumerableSet.Bytes32Set) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#193-195) is never used and should be removed
EnumerableSet.length(EnumerableSet.UintSet) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#341-343) is never used and should be removed
EnumerableSet.remove(EnumerableSet.UintSet,uint256) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#327-329) is never used and should be removed
EnumerableSet.values(EnumerableSet.UintSet) (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#367-377) is never used and should be removed
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#dead-code
INFO:Detectors:
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/access/AccessControl.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/access/IAccessControl.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/access/extensions/IAccessControlEnumerable.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC1155/IERC1155Receiver.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/utils/Context.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol#4) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version^0.8.20 (lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol#5) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/Safe.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/Executor.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/FallbackManager.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/GuardManager.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/ModuleManager.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/base/OwnerManager.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/Enum.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/NativeCurrencyPaymentFallback.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/SecuredTokenTransfer.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/SelfAuthorized.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/SignatureDecoder.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/Singleton.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/common/StorageAccessible.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/external/SafeMath.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/interfaces/IERC165.sol#2) is too complex
Pragma version>=0.7.0<0.9.0 (lib/safe-smart-account/contracts/interfaces/ISignatureValidator.sol#2) is too complex
Pragma version0.8.25 (src/BytesHelper.sol#1) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version0.8.25 (src/ConfigurablePauseGuardian.sol#1) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Pragma version0.8.25 (src/Timelock.sol#3) necessitates a version too recent to be trusted. Consider deploying with 0.8.18.
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity
Comment: Fixed by locking to Solidity version 0.8.25.

INFO:Detectors:
Low level call in Timelock._execute(address,uint256,bytes) (src/Timelock.sol#980-985):
	- (success) = target.call{value: value}(data) (src/Timelock.sol#983)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls
INFO:Detectors:
Parameter Safe.setup(address[],uint256,address,bytes,address,address,uint256,address)._owners (lib/safe-smart-account/contracts/Safe.sol#96) is not in mixedCase
Parameter Safe.setup(address[],uint256,address,bytes,address,address,uint256,address)._threshold (lib/safe-smart-account/contracts/Safe.sol#97) is not in mixedCase
Parameter Safe.encodeTransactionData(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,uint256)._nonce (lib/safe-smart-account/contracts/Safe.sol#393) is not in mixedCase
Parameter Safe.getTransactionHash(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,uint256)._nonce (lib/safe-smart-account/contracts/Safe.sol#437) is not in mixedCase
Parameter OwnerManager.setupOwners(address[],uint256)._owners (lib/safe-smart-account/contracts/base/OwnerManager.sol#28) is not in mixedCase
Parameter OwnerManager.setupOwners(address[],uint256)._threshold (lib/safe-smart-account/contracts/base/OwnerManager.sol#28) is not in mixedCase
Parameter OwnerManager.addOwnerWithThreshold(address,uint256)._threshold (lib/safe-smart-account/contracts/base/OwnerManager.sol#58) is not in mixedCase
Parameter OwnerManager.removeOwner(address,address,uint256)._threshold (lib/safe-smart-account/contracts/base/OwnerManager.sol#78) is not in mixedCase
Parameter OwnerManager.changeThreshold(uint256)._threshold (lib/safe-smart-account/contracts/base/OwnerManager.sol#119) is not in mixedCase
Variable Timelock.ADDRESS_THIS_HASH (src/Timelock.sol#95-96) is not in mixedCase
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#conformance-to-solidity-naming-conventions
Comment: The ADDRESS_THIS_HASH variable is considered a constant value.

INFO:Detectors:
Reentrancy in Safe.execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes) (lib/safe-smart-account/contracts/Safe.sol#139-221):
	External calls:
	- payment = handlePayment(gasUsed,baseGas,gasPrice,gasToken,refundReceiver) (lib/safe-smart-account/contracts/Safe.sol#211)
		- require(bool,string)(receiver.send(payment),GS011) (lib/safe-smart-account/contracts/Safe.sol#243)
	Event emitted after the call(s):
	- ExecutionFailure(txHash,payment) (lib/safe-smart-account/contracts/Safe.sol#214)
	- ExecutionSuccess(txHash,payment) (lib/safe-smart-account/contracts/Safe.sol#213)
Reentrancy in Safe.setup(address[],uint256,address,bytes,address,address,uint256,address) (lib/safe-smart-account/contracts/Safe.sol#95-117):
	External calls:
	- handlePayment(payment,0,1,paymentToken,paymentReceiver) (lib/safe-smart-account/contracts/Safe.sol#114)
		- require(bool,string)(receiver.send(payment),GS011) (lib/safe-smart-account/contracts/Safe.sol#243)
	Event emitted after the call(s):
	- SafeSetup(msg.sender,_owners,_threshold,to,fallbackHandler) (lib/safe-smart-account/contracts/Safe.sol#116)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-4
INFO:Detectors:
BaseGuard (lib/safe-smart-account/contracts/base/GuardManager.sol#26-32) does not implement functions:
	- Guard.checkAfterExecution(bytes32,bool) (lib/safe-smart-account/contracts/base/GuardManager.sol#23)
	- Guard.checkTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes,address) (lib/safe-smart-account/contracts/base/GuardManager.sol#9-21)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#unimplemented-functions

```