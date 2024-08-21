import "ITimelock.spec";

using Timelock as t;

function timelockAddress() returns address {
    return currentContract;
}

invariant noSelfWhitelisting(bytes4 selector)
    t._calldataList[timelockAddress()][selector].length == 0;

invariant minDelay()
    minDelay() >= oneDay() && minDelay() <= oneMonth();

invariant expirationPeriod()
    expirationPeriod() >= oneDay();

invariant oneAdminMax(env e)
    getRoleMemberCount(DEFAULT_ADMIN_ROLE()) == 1
        filtered {
            f -> f.selector != sig:grantRole(bytes32,address).selector &&
                f.selector != sig:revokeRole(bytes32,address).selector &&
                f.selector != sig:renounceRole(bytes32,address).selector
        }

invariant onlyTwoRoles(bytes32 role)
    getRoleMemberCount(role) == 0
        filtered {
            f -> f.selector != sig:grantRole(bytes32,address).selector
        }
        {
        preserved {
            require (role != HOT_SIGNER_ROLE() && role != DEFAULT_ADMIN_ROLE());
        }
    }

rule executeWhitelisted(env e, address target, uint256 value, bytes data, bytes4 selector) {
    requireInvariant noSelfWhitelisting(selector);

    executeWhitelisted(e, target, value, data);

    assert target != timelockAddress(), "target is timelock";
}

rule onlyTwoRolesExist(method f, env e, bytes32 role)
filtered {
    f -> f.selector != sig:grantRole(bytes32,address).selector
} {
    require role != HOT_SIGNER_ROLE() && role != DEFAULT_ADMIN_ROLE();

    calldataarg args;

    f(e, args);

    assert getRoleMemberCount(role) == 0, "new role should not exist";
}
