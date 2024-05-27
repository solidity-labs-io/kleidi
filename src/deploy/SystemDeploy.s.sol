pragma solidity ^0.8.0;

import {MultisigProposal} from
    "@forge-proposal-simulator/src/proposals/MultisigProposal.sol";
import {Addresses} from "@forge-proposal-simulator/addresses/Addresses.sol";

import {TimelockFactory} from "src/TimelockFactory.sol";
import {TimeRestricted} from "src/TimeRestricted.sol";
import {Timelock} from "src/Timelock.sol";

/// @notice system deployment contract
/// all contracts are permissionless and take no constructor params
/// so there is nothing to validate
/// DO_PRINT=false DO_BUILD=false DO_RUN=false DO_DEPLOY=true DO_VALIDATE=true forge script src/deploy/SystemDeploy.s.sol:SystemDeploy --fork-url base -vvvvv
contract SystemDeploy is MultisigProposal {
    /// set addresses object in msig proposal
    constructor() {
        addresses = new Addresses("./Addresses.json");
    }

    function name() public view override returns (string memory) {
        return "SYS_DEPLOY";
    }

    function description() public view override returns (string memory) {
        return "Deploy TimelockFactory and TimeRestricted contracts";
    }

    function deploy() public override {
        if (!addresses.isAddressSet("TIMELOCK_FACTORY")) {
            TimelockFactory factory = new TimelockFactory();
            addresses.addAddress("TIMELOCK_FACTORY", address(factory), true);
        }
        if (!addresses.isAddressSet("TIME_RESTRICTED")) {
            TimeRestricted timeRestricted = new TimeRestricted();
            addresses.addAddress(
                "TIME_RESTRICTED", address(timeRestricted), true
            );
        }
    }

    function validate() public view override {
        if (addresses.isAddressSet("TIMELOCK_FACTORY")) {
            address factory = addresses.getAddress("TIMELOCK_FACTORY");
            assertEq(
                keccak256(factory.code),
                keccak256(type(TimelockFactory).runtimeCode),
                "Incorrect TimelockFactory Bytecode"
            );

            address restricted = addresses.getAddress("TIME_RESTRICTED");
            assertEq(
                keccak256(restricted.code),
                keccak256(type(TimeRestricted).runtimeCode),
                "Incorrect TimeRestricted Bytecode"
            );
        }
    }
}
