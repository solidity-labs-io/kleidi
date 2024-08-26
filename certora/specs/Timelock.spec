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

/// check that CVL allows direct storage lookup
invariant setLengthInvariant()
    setLength() == getAllProposals().length;

/// this will tell us definitively if direct storage lookups are allowed
invariant timestampInvariant(bytes32 proposalId)
    t.timestamps[proposalId] == timestamps(proposalId);

invariant noSelfWhitelisting(bytes4 selector)
    t._calldataList[timelockAddress()][selector].length == 0;

invariant noSafeWhitelisting(bytes4 selector)
    t._calldataList[safe()][selector].length == 0;

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

/// removeCalldataCheck removes all calldata checks
rule removeCalldataCheck(env e, address target, bytes4 selector, uint256 index) {
    mathint len = t._calldataList[target][selector].length;

    removeCalldataCheck(e, target, selector, index);

    /// verify all state transitions
    assert to_mathint(t._calldataList[target][selector].length) == len - 1, "calldata list should be empty";
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
