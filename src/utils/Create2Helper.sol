pragma solidity 0.8.25;

struct Create2Params {
    address creator;
    bytes creationCode;
    bytes constructorParams;
    bytes32 salt;
}

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

function calculateCreate2Address(Create2Params memory params)
    pure
    returns (address)
{
    return address(
        uint160(
            uint256(
                keccak256(
                    abi.encodePacked(
                        bytes1(0xff),
                        params.creator,
                        params.salt,
                        keccak256(
                            abi.encodePacked(
                                params.creationCode, params.constructorParams
                            )
                        )
                    )
                )
            )
        )
    );
}
