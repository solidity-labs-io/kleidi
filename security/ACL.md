# Access Controls

View all modifiers 

command:
```
slither src/Timelock.sol --print modifiers --solc-remaps '@openzeppelin-contracts/=lib/openzeppelin-contracts/ @safe/=lib/safe-smart-account/contracts/ @src/=src/ @interface/=src/interface/'
```

output:
```
Contract Timelock
+-------------------------------------+-------------------------------+---------------------+
|               Function              |           Modifiers           |     State Change    |
+-------------------------------------+-------------------------------+---------------------+
|           onERC721Received          |               []              | pure                |
|          onERC1155Received          |               []              | pure                |
|        onERC1155BatchReceived       |               []              | view                |
|          supportsInterface          |               []              | view                |
|          supportsInterface          |               []              | view                |
|            getRoleMember            |               []              | view                |
|          getRoleMemberCount         |               []              | view                |
|            getRoleMembers           |               []              | view                |
|              _grantRole             |               []              |                     |
|             _revokeRole             |               []              |                     |
|          supportsInterface          |               []              | view                |
|               hasRole               |               []              | view                |
|              _checkRole             |               []              |                     |
|              _checkRole             |               []              |                     |
|             getRoleAdmin            |               []              | view                |
|              grantRole              |  ['getRoleAdmin', 'onlyRole'] | yes                 |
|              revokeRole             |  ['getRoleAdmin', 'onlyRole'] | yes                 |
|             renounceRole            |               []              | yes                 |
|            _setRoleAdmin            |               []              |                     |
|              _grantRole             |               []              |                     |
|             _revokeRole             |               []              |                     |
|          supportsInterface          |               []              | view                |
|               hasRole               |               []              | view                |
|             getRoleAdmin            |               []              | view                |
|              grantRole              |               []              | yes                 |
|              revokeRole             |               []              | yes                 |
|             renounceRole            |               []              | yes                 |
|              _msgSender             |               []              | view                |
|               _msgData              |               []              | view                |
|         _contextSuffixLength        |               []              | view                |
|            getRoleMember            |               []              | view                |
|          getRoleMemberCount         |               []              | view                |
|              pauseUsed              |               []              | view                |
|                paused               |               []              | view                |
|                pause                |       ['whenNotPaused']       | yes                 |
|         _updatePauseDuration        |               []              |                     |
|            _setPauseTime            |               []              |                     |
|            _grantGuardian           |               []              |                     |
|             constructor             |               []              |                     |
|              initialize             |               []              | yes                 |
|           getAllProposals           |               []              | view                |
|               atIndex               |               []              | view                |
|              positionOf             |               []              | view                |
|          supportsInterface          |               []              | view                |
|             isOperation             |               []              | view                |
|           isOperationReady          |               []              | view                |
|           isOperationDone           |               []              | view                |
|          isOperationExpired         |               []              | view                |
|            hashOperation            |               []              | view                |
|          hashOperationBatch         |               []              | view                |
|          getCalldataChecks          |               []              | view                |
|            checkCalldata            |               []              | view                |
|               schedule              | ['onlySafe', 'whenNotPaused'] | yes                 |
|            scheduleBatch            | ['onlySafe', 'whenNotPaused'] | yes                 |
|               execute               |       ['whenNotPaused']       | yes                 |
|             executeBatch            |       ['whenNotPaused']       | yes                 |
|                cancel               | ['onlySafe', 'whenNotPaused'] | yes                 |
|               cleanup               |       ['whenNotPaused']       | yes                 |
|                pause                |       ['whenNotPaused']       | yes                 |
|          executeWhitelisted         | ['onlyRole', 'whenNotPaused'] | yes                 |
|       executeWhitelistedBatch       | ['onlyRole', 'whenNotPaused'] | yes                 |
|              grantRole              |  ['getRoleAdmin', 'onlyRole'] | yes                 |
|              revokeRole             |  ['getRoleAdmin', 'onlyRole'] | yes                 |
|             renounceRole            |               []              | yes                 |
|           revokeHotSigner           |          ['onlySafe']         | yes                 |
|             setGuardian             |        ['onlyTimelock']       | yes                 |
|          addCalldataChecks          |        ['onlyTimelock']       | yes                 |
|           addCalldataCheck          |        ['onlyTimelock']       | yes                 |
|         removeCalldataCheck         |        ['onlyTimelock']       | yes                 |
|       removeAllCalldataChecks       |        ['onlyTimelock']       | yes                 |
|             updateDelay             |        ['onlyTimelock']       | yes                 |
|        updateExpirationPeriod       |        ['onlyTimelock']       | yes                 |
|         updatePauseDuration         |        ['onlyTimelock']       | yes                 |
|              _schedule              |               []              |                     |
|              _afterCall             |               []              |                     |
|               _execute              |               []              |                     |
|          _addCalldataCheck          |               []              |                     |
|          _addCalldataChecks         |               []              |                     |
|         _removeCalldataCheck        |               []              |                     |
|       _removeAllCalldataChecks      |               []              |                     |
|            tokensReceived           |               []              | pure                |
|               receive               |               []              | yes - logs          |
+-------------------------------------+-------------------------------+---------------------+
```

Functions starting with an underscore are internal or private functions and cannot be called from outside the contract.
