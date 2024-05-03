pragma solidity ^0.8.0;

import {TimeRestricted} from "@src/TimeRestricted.sol";

contract MockTimeRestricted is TimeRestricted {
    address private constant SENTINEL_MODULES = address(0x1);

    function getTloadValue(uint256 slot) public view returns (uint256 value) {
        assembly {
            value := tload(slot)
        }
    }

    function tstoreOwnerAddressesLength(uint256 value) public {
        uint256 slot = OWNER_LENGTH_SLOT;
        assembly {
            tstore(slot, value)
        }
    }

    function tstoreModuleAddressesLength(uint256 value) public {
        _tstoreValueDirect(MODULE_LENGTH_SLOT, value);
    }

    function tstoreLoadAddresses(address[] memory values) public {
        for (uint256 i = 0; i < values.length; i++) {
            _tstoreValueModule(uint256(uint160(values[i])), 1);
        }
    }

    function getSentinelModuleCount() public returns (uint256) {
        _traverseModules(
            SENTINEL_MODULES,
            0,
            _checktTstoreValueModule,
            _checktStoreValueDirect
        );

        return getTloadValue(MODULE_LENGTH_SLOT);
    }
}
