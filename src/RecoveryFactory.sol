pragma solidity 0.8.25;

import {RecoverySpell} from "@src/RecoverySpell.sol";

/// @notice factory contract to create new RecoverySpell contracts
/// Contract addresses can be determined in advance with different
/// parameters, salts and parameters.
/// Edge cases:
///    If the safe address has no bytecode, or is incorrectly
///    specified, then the dark spell address will be calculated
///    correctly, but it will not actually map to the corresponding
///    contract.
contract RecoveryFactory {
    event RecoverySpellCreated(address indexed recoverySpell);

    /// @notice create a new RecoverySpell contract using CREATE2
    /// @param salt the salt used to create the contract
    /// @param owners the owners of the contract
    /// @param safe to recover with the spell
    /// @param threshold of owners required to execute transactions
    /// @param delay time required before the recovery transaction can be executed
    function createRecoverySpell(
        bytes32 salt,
        address[] memory owners,
        address safe,
        uint256 threshold,
        uint256 delay
    ) external returns (RecoverySpell recovery) {
        _paramChecks(owners, threshold, delay);

        recovery = new RecoverySpell{salt: salt}(owners, safe, threshold, delay);

        emit RecoverySpellCreated(address(recovery));
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
        uint256 delay
    ) public view returns (address predictedAddress) {
        _paramChecks(owners, threshold, delay);

        predictedAddress = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            salt,
                            keccak256(
                                abi.encodePacked(
                                    type(RecoverySpell).creationCode,
                                    abi.encode(owners, safe, threshold, delay)
                                )
                            )
                        )
                    )
                )
            )
        );
    }

    /// @param owners the owners of the contract
    /// @param threshold of owners required to execute transactions
    /// @param delay time required before the recovery transaction can be executed
    function _paramChecks(
        address[] memory owners,
        uint256 threshold,
        uint256 delay
    ) private pure {
        require(
            threshold <= owners.length,
            "RecoverySpell: Threshold must be lte number of owners"
        );
        require(threshold != 0, "RecoverySpell: Threshold must be gt 0");
        require(delay <= 20 days, "RecoverySpell: Delay must be lte 20 days");

        /// do not allow array of owners that contains duplicates
        for (uint256 i = 0; i < owners.length; i++) {
            for (uint256 j = i + 1; j < owners.length; j++) {
                require(
                    owners[i] != owners[j], "RecoverySpell: Duplicate owner"
                );
            }
        }
    }
}
