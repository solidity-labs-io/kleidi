import "ITimelock.spec";

using Timelock as t;

function timelockAddress() returns address {
    return currentContract;
}

invariant noSelfWhitelisting(bytes4 selector)
    t._calldataList[timelockAddress()][selector].length == 0;

invariant noSafeWhitelisting(bytes4 selector)
    t._calldataList[safe()][selector].length == 0;

invariant minDelay()
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

/// cancel decreases proposal length by one
rule cancelEffects(env e, bytes32 proposalId) {
    /// filter out impossible state
    require e.block.timestamp <= timestampMax() && e.block.timestamp > 0;

    mathint len = getAllProposals().length;

    cancel(e, proposalId);

    /// verify all state transitions
    assert to_mathint(getAllProposals().length) == len - 1, "proposal length should decrease by one";
    assert !isOperation(proposalId), "proposal should not be an operation";
    assert t.timestamps[proposalId] == 0, "proposal timestamp should be 0";
}

/// cleanup decreases proposal length by one
rule cleanupEffects(env e, bytes32 proposalId) {
    /// filter out impossible state
    require e.block.timestamp <= timestampMax() && e.block.timestamp > 0;

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

/// removeAllCalldataChecks removes all calldata checks
rule removeAllCalldataChecks(env e, address target, bytes4 selector, uint256 index) {
    /// filter out impossible state
    require e.block.timestamp <= timestampMax() && e.block.timestamp > 0;

    mathint len = t._calldataList[target][selector].length;

    removeCalldataCheck(e, target, selector, index);

    /// verify all state transitions
    assert to_mathint(t._calldataList[target][selector].length) == len - 1, "calldata list should be empty";

}

/// post execute, proposal timestamp is set to 1