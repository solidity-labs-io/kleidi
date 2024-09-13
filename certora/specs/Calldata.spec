import "ITimelock.spec";

using Timelock as t;

function timelockAddress() returns address {
    return currentContract;
}

invariant noSelfWhitelisting(bytes4 selector)
    t._calldataList[timelockAddress()][selector].length == 0;

invariant noSafeWhitelisting(bytes4 selector)
    t._calldataList[safe()][selector].length == 0;

invariant calldataIndexesInvariant(address contract, bytes4 selector, uint256 index)
    (t._calldataList[contract][selector].length > index) =>
    (
        t._calldataList[contract][selector][index].startIndex >= 4 &&
        t._calldataList[contract][selector][index].endIndex >= t._calldataList[contract][selector][index].startIndex
    )
        filtered {
            f -> f.selector != sig:removeCalldataCheck(address,bytes4,uint256).selector
        }

invariant singleCheckIfWildcard(address contract, bytes4 selector, uint256 index)
    (t._calldataList[contract][selector].length > index && 
    t._calldataList[contract][selector][index].endIndex == t._calldataList[contract][selector][index].startIndex) =>
    (
       t._calldataList[contract][selector][index].startIndex == 4 &&
       t._calldataList[contract][selector].length == 1
    )
        filtered {
            f -> f.selector != sig:removeCalldataCheck(address,bytes4,uint256).selector
        }

/// removeCalldataCheck removes 1 calldata check
rule removeCalldataCheck(env e, address target, bytes4 selector, uint256 index) {
    mathint len = t._calldataList[target][selector].length;

    removeCalldataCheck(e, target, selector, index);

    /// verify all state transitions
    assert to_mathint(t._calldataList[target][selector].length) == len - 1, "calldata list should be empty";
}

/// addCalldataCheck add 1 calldata check
rule addCalldataCheck(env e, address target, bytes4 selector, uint16 startIndex, uint16 endIndex, bytes[] data, bool[] isSelfAddressCheck) {
    mathint len = t._calldataList[target][selector].length;
    uint256 uint256Len = t._calldataList[target][selector].length;

    addCalldataCheck(e, target, selector, startIndex, endIndex, data, isSelfAddressCheck);

    /// verify all state transitions
    assert to_mathint(t._calldataList[target][selector].length) == len + 1, "one calldata check should be added";
    assert startIndex >= 4, "start index should be greater than 3";
    assert endIndex >= startIndex, "end index should be greater than equal to start index";
    assert t._calldataList[target][selector][uint256Len].dataHashes._inner._values.length == data.length, "All OR data should be added for the check";
}

/// addCalldataCheck add 1 calldata check
rule addWildcardCheck(env e, address target, bytes4 selector, uint16 startIndex, uint16 endIndex, bytes[] data, bool[] isSelfAddressCheck) {
    require startIndex == endIndex;

    mathint len = t._calldataList[target][selector].length;

    addCalldataCheck(e, target, selector, startIndex, endIndex, data, isSelfAddressCheck);

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
