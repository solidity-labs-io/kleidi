methods {
    function removeCalldataCheck(address,bytes4,uint256) external                    ;
    function getRoleMemberCount(bytes32)           external returns (uint256) envfree;
    function DEFAULT_ADMIN_ROLE()                  external returns (bytes32) envfree;
    function expirationPeriod()                    external returns (uint256) envfree;
    function isOperationReady(bytes32)             external returns (bool)           ;
    function HOT_SIGNER_ROLE()                     external returns (bytes32) envfree;
    function getAllProposals()                     external returns (bytes32[]) envfree;
    function pauseStartTime()                      external returns (uint128) envfree;
    function pauseDuration()                       external returns (uint128) envfree;
    function pauseGuardian()                       external returns (address) envfree;
    function isOperation(bytes32)                  external returns (bool)    envfree;
    function minDelay()                            external returns (uint256) envfree;
    function pauseUsed()                           external returns (bool)    envfree;
    function paused()                              external returns (bool)           ;
    function pause()                               external returns (bool)           ;
    function safe()                                external returns (address) envfree;
    function hasRole(bytes32,address)              external returns (bool)    envfree;
    function checkCalldata(address,bytes)          external                   envfree;
    function revokeHotSigner(address)              external                          ;
    function cleanup(bytes32)                      external                          ;
    function cancel(bytes32)                       external                          ;
}

definition oneDay() returns uint256 = 84600;
definition oneMonth() returns uint256 = 2592000;
definition timestampMax() returns uint256 = 2 ^ 128 - 1;
