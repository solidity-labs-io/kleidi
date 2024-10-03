import "ITimelock.spec";

using Timelock as t;

function timelockAddress() returns address {
    return currentContract;
}

function contains(bytes32 key) returns bool {
    return _positionOf(key) > 0;
}

function _positionOf(bytes32 key) returns uint256 {
    return positionOf(key);
}

function at_(uint256 index) returns bytes32 {
    return atIndex(index);
}

function setLength() returns uint256 {
    return t._liveProposals._inner._values.length;
}

    /*//////////////////////////////////////////////////////////////
                                    Timelock
    //////////////////////////////////////////////////////////////*/

/// check that CVL allows direct storage lookup
invariant setLengthInvariant()
    setLength() == getAllProposals().length;

/// this will tell us definitively if direct storage lookups are allowed
invariant timestampInvariant(bytes32 proposalId)
    t.timestamps[proposalId] == timestamps(proposalId);

invariant minDelayInvariant()
    minDelay() >= oneDay() && minDelay() <= oneMonth();

invariant expirationPeriod()
    expirationPeriod() >= oneDay();

invariant singleAdmin(env e)
    getRoleMemberCount(DEFAULT_ADMIN_ROLE()) == 1;

invariant onlyTwoRoles(bytes32 role)
    (role != HOT_SIGNER_ROLE() && role != DEFAULT_ADMIN_ROLE()) => getRoleMemberCount(role) == 0
        filtered {
            f -> f.selector != sig:grantRole(bytes32,address).selector
        }

invariant timestampNotExecutedGtMinDelay(env e, bytes32 proposalId)
    (t.timestamps[proposalId] > 1) => (to_mathint(t.timestamps[proposalId]) >= e.block.timestamp + minDelay())
        filtered {
            f -> f.selector != sig:updateDelay(uint256).selector
        } {
        preserved {
            require e.block.timestamp > 1;
            requireInvariant minDelayInvariant();
        }
        preserved schedule(address target, uint256 value, bytes data, bytes32 salt, uint256 delay) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
        }
        preserved scheduleBatch(address[] target, uint256[] value, bytes[] data, bytes32 salt, uint256 delay) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
        }

    }

/// if the operation is expired, timestamp should be gt 1
/// if timestamp is gt 1, that does not necessarily mean the operation is expired
invariant operationExpired(env e, bytes32 proposalId)
    isOperationExpired(e, proposalId) => t.timestamps[proposalId] > 1 {
        preserved {
            require e.block.timestamp > 1;
        }
    }

invariant consistencyIndex(uint256 index)
    index < setLength() =>
     _positionOf(at_(index)) == require_uint256(index + 1)
    {
        preserved {
            requireInvariant consistencyIndex(require_uint256(setLength() - 1));
        }
    }

invariant operationInSet(env e, bytes32 proposalId, uint256 index)
    ((!isOperationExpired(e, proposalId)) && t.timestamps[proposalId] > 1) =>
     (
        _positionOf(proposalId) > 0 && at_(_positionOf(proposalId)) == proposalId
      )
        filtered {
            f -> f.selector != sig:scheduleBatch(address[],uint256[],bytes[],bytes32,uint256).selector &&
                f.selector != sig:executeBatch(address[],uint256[],bytes[],bytes32).selector &&
                f.selector != sig:schedule(address,uint256,bytes,bytes32,uint256).selector &&
                f.selector != sig:execute(address,uint256,bytes,bytes32).selector
        } {
        preserved {
            require e.block.timestamp > 1;
            requireInvariant consistencyIndex(index);
            requireInvariant consistencyIndex(_positionOf(proposalId));
            requireInvariant minDelayInvariant();
            requireInvariant timestampNotExecutedGtMinDelay(e, proposalId);
        }
        preserved cancel(bytes32 cancelProposalId) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
            require cancelProposalId == proposalId;
        }
        preserved cleanup(bytes32 cleanupProposalId) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
            require cleanupProposalId == proposalId;
        }
      }

/// check that executed operations are removed from the enumerable set
/// except for when calling cleanup
invariant executedOperationNotInSet(bytes32 proposalId)
    !contains(proposalId) => t.timestamps[proposalId] <= 1 
    filtered {
        f -> f.selector != sig:cleanup(bytes32).selector
    } {
        preserved {
            require setLength() < uintMax();
        }
    }

/// check that operations in the set are not executed
invariant operationInSetImpliesNotExecuted(bytes32 proposalId)
    t.timestamps[proposalId] > 1 => contains(proposalId)
    filtered {
        f -> f.selector != sig:cleanup(bytes32).selector
    } {
        preserved {
            require setLength() < uintMax();
        }
    }

invariant pauseImpliesEmptySet(env e)
    paused(e) => getAllProposals().length == 0 {
        preserved {
            require e.block.timestamp > 1 && e.block.timestamp <= assert_uint256(timestampMax() - oneMonth());
            requireInvariant minDelayInvariant();
            requireInvariant expirationPeriod();
            require to_mathint(pauseDuration()) >= to_mathint(oneDay()) &&
             to_mathint(pauseDuration()) <= to_mathint(oneMonth());
        }
        preserved updatePauseDuration(uint128 newPauseDuration) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
            require e.block.timestamp > assert_uint256(MAX_PAUSE_DURATION()) && e.block.timestamp <= assert_uint256(timestampMax() - oneMonth());
            require to_mathint(pauseDuration()) >= to_mathint(oneDay()) &&
             to_mathint(pauseDuration()) <= to_mathint(oneMonth());
        }
        preserved cancel(bytes32 cancelProposalId) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
        }
        preserved cleanup(bytes32 cleanupProposalId) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
        }
        preserved schedule(address target, uint256 value, bytes data, bytes32 salt, uint256 delay) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
        }
        preserved scheduleBatch(address[] target, uint256[] value, bytes[] data, bytes32 salt, uint256 delay) with (env e1) {
            require e1.block.timestamp == e.block.timestamp;
        }
    }

/// cancel decreases proposal length by one
rule cancelEffects(env e, bytes32 proposalId) {
    mathint len = getAllProposals().length;

    cancel(e, proposalId);

    /// verify all state transitions
    assert to_mathint(getAllProposals().length) == len - 1, "proposal length should decrease by one";
    assert !isOperation(proposalId), "proposal should not be an operation";
    assert t.timestamps[proposalId] == 0, "proposal timestamp should be 0";
}

/// cleanup decreases proposal length by one
rule cleanupEffects(env e, bytes32 proposalId) {
    mathint len = getAllProposals().length;
    mathint timestamp = t.timestamps[proposalId];

    cleanup(e, proposalId);

    /// verify all state transitions
    assert to_mathint(getAllProposals().length) == len - 1, "proposal length should decrease by one";
    assert to_mathint(t.timestamps[proposalId]) == timestamp, "proposal timestamp should not change";
    assert isOperationExpired(e, proposalId), "proposal should be expired in order to call cleanup";
}

/// revokeHotSigner revokes the role from signer
rule revokeHotSigner(env e, address signer) {
    revokeHotSigner(e, signer);

    assert !hasRole(HOT_SIGNER_ROLE(), signer), "signer should not have hot signer role";
}

/// post execute, proposal timestamp is set to 1
rule executeSetsTimestamp(env e, address target,  uint256 value, bytes data, bytes32 salt) {
    bytes32 proposalId = hashOperation(target, value, data, salt);

    execute(e, target, value, data, salt);

    /// verify all state transitions
    assert t.timestamps[proposalId] == 1, "proposal timestamp should be 1";
    assert isOperationDone(e, proposalId), "proposal should be marked as executed";
    assert !contains(proposalId), "proposal should not be in the set post execution";
}

rule executeBatchSetsTimestamp(env e, address[] target, uint256[] value, bytes[] data, bytes32 salt) {
    bytes32 proposalId = hashOperationBatch(target, value, data, salt);

    executeBatch(e, target, value, data, salt);

    /// verify all state transitions
    assert t.timestamps[proposalId] == 1, "proposal timestamp should be 1";
    assert isOperationDone(e, proposalId), "proposal should be marked as executed";
    assert !contains(proposalId), "proposal should not be in the set post execution";
}

rule timestampChange(env e, method f, calldataarg args, bytes32 proposalId) {
    uint256 timestampBefore = t.timestamps[proposalId];

    f(e, args);

    uint256 timestampAfter = t.timestamps[proposalId];

    assert (timestampAfter > timestampBefore) => (
        f.selector == sig:schedule(address,uint256,bytes,bytes32,uint256).selector ||
        f.selector == sig:scheduleBatch(address[],uint256[],bytes[],bytes32,uint256).selector
    ), "only schedule should increase timestamp";

    assert (timestampBefore != 0 && timestampAfter == 0) => (
        f.selector == sig:cancel(bytes32).selector ||
        f.selector == sig:pause().selector
    ), "only cancel or pause should set the timestamp to 0";

    assert (timestampBefore > timestampAfter && timestampAfter == doneTimestamp()) => (
        f.selector == sig:execute(address,uint256,bytes,bytes32).selector ||
        f.selector == sig:executeBatch(address[],uint256[],bytes[],bytes32).selector
    ), "only execute and executeBatch should set the timestamp to 1";
}

rule setChange(env e, method f, calldataarg args, bytes32 proposalId) {
    bytes32[] proposalsBefore = getAllProposals();

    f(e, args);

    bytes32[] proposalsAfter = getAllProposals();

    assert proposalsAfter.length > proposalsBefore.length  => (
        f.selector == sig:schedule(address,uint256,bytes,bytes32,uint256).selector ||
        f.selector == sig:scheduleBatch(address[],uint256[],bytes[],bytes32,uint256).selector
    ), "only schedule should increase proposal set";

    assert proposalsBefore.length > proposalsAfter.length => (
        f.selector == sig:cleanup(bytes32).selector ||
        f.selector == sig:cancel(bytes32).selector ||
        f.selector == sig:pause().selector ||
        f.selector == sig:execute(address,uint256,bytes,bytes32).selector ||
        f.selector == sig:executeBatch(address[],uint256[],bytes[],bytes32).selector
    ), "only cleanup, pause, cancel, execute and executeBatch should remove from proposal set";
}

    /*//////////////////////////////////////////////////////////////
                                    Pause
    //////////////////////////////////////////////////////////////*/

invariant pauseDuration()
    to_mathint(pauseDuration()) >= to_mathint(oneDay()) &&
    to_mathint(pauseDuration()) <= to_mathint(oneMonth());

rule pausingCancelsAllInflightProposals(env e) {
    require getAllProposals().length > 0;

    pause(e);

    assert getAllProposals().length == 0, "proposals not cancelled post pause";
}

rule pausingRevokesGuardian(env e) {
    require pauseGuardian() != 0;
    require e.block.timestamp <= timestampMax() && e.block.timestamp > 0;

    pause(e);

    assert pauseGuardian() == 0, "pause guardian not revoked";
    assert to_mathint(pauseStartTime()) == to_mathint(e.block.timestamp), "pause start time not set";
    assert paused(e), "contract not paused";
    assert pauseStartTime() != 0, "contract not paused";
}

    /*//////////////////////////////////////////////////////////////
                                    Calldata
    //////////////////////////////////////////////////////////////*/

invariant noSelfWhitelisting(bytes4 selector)
    t._calldataList[timelockAddress()][selector].length == 0;

invariant noZeroAddressWhitelisting(bytes4 selector)
    t._calldataList[0][selector].length == 0;

invariant noEmptySelectorWhitelisting(address contract)
    t._calldataList[contract][to_bytes4(0)].length == 0;

invariant noSafeWhitelisting(bytes4 selector)
    t._calldataList[safe()][selector].length == 0;

invariant calldataIndexesInvariant(address contract, bytes4 selector, uint256 index)
    (t._calldataList[contract][selector].length > index) =>
    (
        t._calldataList[contract][selector][index].startIndex >= 4 &&
        t._calldataList[contract][selector][index].endIndex >= t._calldataList[contract][selector][index].startIndex
    ) {
        preserved {
            if (t._calldataList[contract][selector].length >= 1) {
                requireInvariant calldataIndexesInvariant(contract, selector, assert_uint256(t._calldataList[contract][selector].length - 1));
            }
        }
    }

invariant singleCheckIfWildcard(address contract, bytes4 selector, uint256 index)
    (t._calldataList[contract][selector].length > index && 
    t._calldataList[contract][selector][index].endIndex == t._calldataList[contract][selector][index].startIndex) =>
    (
       t._calldataList[contract][selector][index].startIndex == 4 &&
       t._calldataList[contract][selector].length == 1
    ) {
        preserved {
            if (t._calldataList[contract][selector].length >= 1) {
                requireInvariant singleCheckIfWildcard(contract, selector, assert_uint256(t._calldataList[contract][selector].length - 1));
            }
        }
    }

invariant isolatedChecks(address contract, bytes4 selector, uint256 index1, uint256 index2)
    ((index1 != index2) && (index1 < getCalldataChecks(contract, selector).length &&
     index2 < getCalldataChecks(contract, selector).length)) =>
    (getCalldataChecks(contract, selector)[index1].endIndex < getCalldataChecks(contract, selector)[index2].startIndex ||
     getCalldataChecks(contract, selector)[index1].startIndex > getCalldataChecks(contract, selector)[index2].endIndex)
        filtered {
            f -> f.selector != sig:addCalldataChecks(address[],bytes4[],uint16[],uint16[],bytes[][]).selector &&
            f.selector != sig:initialize(address[],bytes4[],uint16[],uint16[],bytes[][]).selector
      } {
        preserved {
            require getCalldataChecks(contract, selector).length < uintMax();
            if (t._calldataList[contract][selector].length >= 1) {
                requireInvariant isolatedChecks(contract, selector, index1, assert_uint256(t._calldataList[contract][selector].length - 1));
                requireInvariant isolatedChecks(contract, selector, index2, assert_uint256(t._calldataList[contract][selector].length - 1));
            }
        }
        preserved addCalldataCheck(address c1 ,bytes4 s1,uint16 startIndex, uint16 endIndex, bytes[] datas) with (env e1) {
            require getCalldataChecks(c1, s1).length < uintMax();
            if (t._calldataList[c1][s1].length >= 1) {
                requireInvariant isolatedChecks(c1, s1, index1, assert_uint256(t._calldataList[c1][s1].length - 1));
                requireInvariant isolatedChecks(c1, s1, index2, assert_uint256(t._calldataList[c1][s1].length - 1));
            }
        }
    }

invariant noEmptyChecks(address contract, bytes4 selector, uint256 index)
    (getCalldataChecks(contract, selector).length > index
    && getCalldataChecks(contract, selector)[index].endIndex != 4) =>
      getCalldataChecks(contract, selector)[index].dataHashes.length > 0 
      filtered {
            f -> f.selector != sig:addCalldataChecks(address[],bytes4[],uint16[],uint16[],bytes[][]).selector &&
            f.selector != sig:initialize(address[],bytes4[],uint16[],uint16[],bytes[][]).selector
      }{
        preserved {
            require getCalldataChecks(contract, selector).length < uintMax();
            if (t._calldataList[contract][selector].length >= 1) {
                requireInvariant noEmptyChecks(contract, selector, assert_uint256(t._calldataList[contract][selector].length - 1));
            }
        }
        preserved addCalldataCheck(address c1 ,bytes4 s1,uint16 startIndex, uint16 endIndex, bytes[] datas) with (env e1) {
            require t._calldataList[contract][selector][index].dataHashes._inner._values.length < uintMax();
            require getCalldataChecks(c1, s1).length < uintMax();
            if (t._calldataList[c1][s1].length >= 1) {
                requireInvariant noEmptyChecks(c1, s1, assert_uint256(t._calldataList[c1][s1].length - 1));
            }
        }
    }

/// removeCalldataCheck removes 1 calldata check
rule removeCalldataCheck(env e, address target, bytes4 selector, uint256 index) {
    mathint len = t._calldataList[target][selector].length;

    removeCalldataCheck(e, target, selector, index);

    /// verify all state transitions
    assert to_mathint(t._calldataList[target][selector].length) == len - 1, "calldata list should be empty";
}

/// addCalldataCheck add 1 calldata check
rule addCalldataCheck(env e, address target, bytes4 selector, uint16 startIndex, uint16 endIndex, bytes[] data) {
    mathint len = t._calldataList[target][selector].length;
    uint256 uint256Len = t._calldataList[target][selector].length;
    /// initial number of OR checks at the index where a new check might be added
    uint256 numberValues = t._calldataList[target][selector][uint256Len].dataHashes._inner._values.length;
    require numberValues + data.length <= to_mathint(uintMax());

    addCalldataCheck(e, target, selector, startIndex, endIndex, data);

    /// verify all state transitions
    mathint afterLen = t._calldataList[target][selector].length;
    /// length will not update if start index and end index matches with already existing check
    assert afterLen == len || afterLen == len + 1, "zero or one calldata check should be added";
    assert startIndex >= 4, "start index should be greater than 3";
    uint256 afterNumberValues = t._calldataList[target][selector][uint256Len].dataHashes._inner._values.length;
    assert endIndex >= startIndex, "end index should be greater than equal to start index";
    assert afterNumberValues == assert_uint256(data.length + numberValues) || afterNumberValues == numberValues, "All OR data should be added for the check";
}

/// addCalldataCheck add 1 calldata check
rule addWildcardCheck(env e, address target, bytes4 selector, uint16 startIndex, uint16 endIndex, bytes[] data) {
    require startIndex == endIndex;

    mathint len = t._calldataList[target][selector].length;

    addCalldataCheck(e, target, selector, startIndex, endIndex, data);

    /// verify all state transitions
    assert to_mathint(t._calldataList[target][selector].length) == len + 1, "one calldata check should be added";
    assert startIndex == 4, "indexes should be 4 for wildcard";
    assert len == 0, "wildcard check can only be added if no checks";
}

/// removeAllCalldataChecks removes all calldata checks
rule removeAllCalldataChecks(env e, address[] targets, bytes4[] selectors) {
    require targets.length == 3 && selectors.length == 3;

    removeAllCalldataChecks(e, targets, selectors);

    /// verify all state transitions
    assert to_mathint(t._calldataList[targets[0]][selectors[0]].length) == 0, "calldata list should be empty";
    assert to_mathint(t._calldataList[targets[1]][selectors[1]].length) == 0, "calldata list should be empty";
    assert to_mathint(t._calldataList[targets[2]][selectors[2]].length) == 0, "calldata list should be empty";
}
