// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

function calculateCreate2Address(
    address creator,
    bytes memory creationCode,
    bytes memory constructorParams,
    bytes32 salt
) pure returns (address) {
    return address(
        uint160(
            uint256(
                keccak256(
                    abi.encodePacked(
                        bytes1(0xff),
                        creator,
                        salt,
                        keccak256(
                            abi.encodePacked(creationCode, constructorParams)
                        )
                    )
                )
            )
        )
    );
}
