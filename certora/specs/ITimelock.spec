methods {
    function addCalldataCheck(address,bytes4,uint16,uint16,bytes[]) external  ;
    function addCalldataChecks(address[],bytes4[],uint16[],uint16[],bytes[][]) external;
    function removeCalldataCheck(address,bytes4,uint256) external                    ;
    function removeAllCalldataChecks(address[],bytes4[]) external                    ;
    function getCalldataChecks(address,bytes4) external returns (Timelock.IndexData[]) envfree;
    function getRoleMemberCount(bytes32)           external returns (uint256) envfree;
    function DEFAULT_ADMIN_ROLE()                  external returns (bytes32) envfree;
    function expirationPeriod()                    external returns (uint256) envfree;
    function isOperationReady(bytes32)             external returns (bool)           ;
    function HOT_SIGNER_ROLE()                     external returns (bytes32) envfree;
    function MAX_PAUSE_DURATION()                  external returns (uint256) envfree;
    function getAllProposals()                     external returns (bytes32[]) envfree;
    function pauseStartTime()                      external returns (uint128) envfree;
    function pauseDuration()                       external returns (uint128) envfree;
    function pauseGuardian()                       external returns (address) envfree;
    function isOperation(bytes32)                  external returns (bool)    envfree;
    function timestamps(bytes32)                   external returns (uint256) envfree;
    function minDelay()                            external returns (uint256) envfree;
    function paused()                              external returns (bool)           ;
    function pause()                               external returns (bool)           ;
    function safe()                                external returns (address) envfree;
    function hasRole(bytes32,address)              external returns (bool)    envfree;
    function checkCalldata(address,bytes)          external                   envfree;
    function revokeHotSigner(address)              external                          ;
    function cleanup(bytes32)                      external                          ;
    function cancel(bytes32)                       external                          ;
    function atIndex(uint256)                      external returns (bytes32) envfree;
    function positionOf(bytes32)                   external returns (uint256) envfree;

    /// proposal creation and execution
    function hashOperationBatch(address[],uint256[],bytes[],bytes32) external returns (bytes32) envfree;
    function hashOperation(address,uint256,bytes,bytes32)            external returns (bytes32) envfree;

    function scheduleBatch(address[],uint256[],bytes[],bytes32,uint256) external     ;
    function executeBatch(address[],uint256[],bytes[],bytes32) external              ;

    function schedule(address,uint256,bytes,bytes32,uint256) external                ;
    function execute(address,uint256,bytes,bytes32) external                         ;
}

definition oneDay() returns uint256 = 84600;
definition oneMonth() returns uint256 = 2592000;
definition timestampMax() returns uint256 = 2 ^ 128 - 1;
definition doneTimestamp() returns uint256 = 1;
definition uintMax() returns uint256 = 2 ^ 256 - 1;
