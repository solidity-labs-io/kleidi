pragma solidity 0.8.25;

import {RecoverySpell} from "@src/RecoverySpell.sol";
import {calculateCreate2Address} from "src/utils/Create2Helper.sol";

/// @notice factory contract to create new RecoverySpell contracts
/// Contract addresses can be determined in advance with different
/// parameters, salts and parameters.
///
/// Edge Cases:
///    If the safe address has no bytecode, or is incorrectly
///    specified, then the recovery spell address will be calculated
///    correctly, but it will not actually map to the corresponding
///    contract.
///
/// Contract Paramters:
///   - salt: a random number used to create the contract address
///   - owners: the new owners of the contract
///   - safe: the address of the safe to recover
///   - threshold: the number of owners required to execute transactions on
//    the new safe
///   - recoveryThreshold: the number of owners required to execute recovery
///   transactions on the new safe. If 0, no private keys are needed to recover
///   the safe.
///   - delay: the time required before the recovery transaction can be executed
///   on the new safe. can be 0 to execute immediately

contract RecoverySpellFactory {
    /// @notice emitted when a new recovery spell is created
    /// @param recoverySpell the address of the new recovery spell
    /// @param safe the address of the safe that is being recovered
    /// with the spell
    event RecoverySpellCreated(
        address indexed recoverySpell, address indexed safe
    );

    /// @notice create a new RecoverySpell contract using CREATE2
    /// @param salt the salt used to create the contract
    /// @param owners the owners of the contract
    /// @param safe to recover with the spell
    /// @param threshold of owners required to execute transactions
    /// @param recoveryThreshold of owners required to execute recovery transactions
    /// @param delay time required before the recovery transaction can be executed
    function createRecoverySpell(
        bytes32 salt,
        address[] memory owners,
        address safe,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay
    ) external returns (RecoverySpell recovery) {
        _paramChecks(owners, threshold, recoveryThreshold, delay);
        /// no checks on parameters as all valid recovery spells are
        /// deployed from the factory which will not allow a recovery
        /// spell to be created that does not have valid parameters
        require(safe.code.length != 0, "RecoverySpell: safe non-existent");

        /// duplicate owner check
        for (uint256 i = 0; i < owners.length; i++) {
            /// not touching memory, we only use the stack and transient storage
            /// so we can use memory-safe for the assembly block
            address owner = owners[i];
            bool found;
            assembly ("memory-safe") {
                found := tload(owner)
                /// save a write to transient storage if the owner is found
                if eq(found, 0) { tstore(owner, 1) }
            }

            require(!found, "RecoverySpell: Duplicate owner");
        }

        recovery = new RecoverySpell{salt: salt}(
            owners, safe, threshold, recoveryThreshold, delay
        );

        emit RecoverySpellCreated(address(recovery), address(safe));
    }

    /// @notice calculate the address of a new RecoverySpell contract
    /// @param salt the salt used to create the contract
    /// @param safe to recover with the spell
    /// @param owners the owners of the contract
    /// @param threshold of owners required to execute transactions
    /// @param delay time required before the recovery transaction can be executed
    function calculateAddress(
        bytes32 salt,
        address[] memory owners,
        address safe,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay
    ) external view returns (address predictedAddress) {
        _paramChecks(owners, threshold, recoveryThreshold, delay);

        /// duplicate owner check
        for (uint256 i = 0; i < owners.length; i++) {
            for (uint256 j = i + 1; j < owners.length; j++) {
                require(
                    owners[i] != owners[j], "RecoverySpell: Duplicate owner"
                );
            }
        }

        predictedAddress = calculateCreate2Address(
            address(this),
            type(RecoverySpell).creationCode,
            abi.encode(owners, safe, threshold, recoveryThreshold, delay),
            salt
        );
    }

    /// @notice check the parameters of the RecoverySpell contract
    /// @param owners the owners of the contract
    /// @param threshold of owners required to execute transactions
    /// @param recoveryThreshold of owners required to execute recovery transactions
    /// @param delay time required before the recovery transaction can be executed
    function _paramChecks(
        address[] memory owners,
        uint256 threshold,
        uint256 recoveryThreshold,
        uint256 delay
    ) private pure {
        require(
            threshold <= owners.length,
            "RecoverySpell: Threshold must be lte number of owners"
        );
        require(
            recoveryThreshold <= owners.length,
            "RecoverySpell: Recovery threshold must be lte number of owners"
        );

        require(threshold != 0, "RecoverySpell: Threshold must be gt 0");
        require(delay <= 365 days, "RecoverySpell: Delay must be lte a year");
        for (uint256 i = 0; i < owners.length; i++) {
            require(owners[i] != address(0), "RecoverySpell: Owner cannot be 0");
        }
    }
}
