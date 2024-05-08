pragma solidity 0.8.25;

import {RecoverySpell} from "@src/RecoverySpell.sol";

/// @notice factory contract to create new RecoverySpell contracts
/// Contract addresses can be determined in advance with different
/// parameters, salts and parameters.
contract RecoveryFactory {
    event RecoverySpellCreated(address indexed recoverySpell);

    /// @notice create a new RecoverySpell contract
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
        address predictedAddress =
            calculateAddress(salt, owners, safe, threshold, delay);

        recovery = new RecoverySpell{salt: salt}(owners, safe, threshold, delay);
        require(address(recovery) == predictedAddress);

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
        require(
            threshold <= owners.length,
            "RecoverySpell: Threshold must be lte number of owners"
        );
        require(threshold != 0, "RecoverySpell: Threshold must be gt 0");
        require(
            delay >= 1 days && delay <= 20 days,
            "RecoverySpell: Delay must be between 1 and 20 days"
        );

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
}
