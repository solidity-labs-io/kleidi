pragma solidity 0.8.25;

library BytesHelper {
    /// @notice function to grab the first 4 bytes of calldata payload
    /// returns the function selector
    /// @param toSlice the calldata payload
    function getFunctionSignature(
        bytes memory toSlice
    ) public pure returns (bytes4 functionSignature) {
        if (toSlice.length < 4) {
            return bytes4(0);
        }

        assembly {
            functionSignature := mload(add(toSlice, 0x20))
        }
    }
    /// @notice function to grab the first 32 bytes of returned memory
    /// @param toSlice the calldata payload
    function getFirstWord(
        bytes memory toSlice
    ) public pure returns (uint256 value) {
        if (toSlice.length < 32) {
            return 0;
        }

        assembly {
            value := mload(add(toSlice, 0x20))
        }
    }

    /// @notice function to grab a slice of bytes out of a byte string
    /// returns the slice
    /// @param toSlice the byte string to slice
    /// @param start the start index of the slice
    /// @param end the end index of the slice
    function sliceBytes(
        bytes memory toSlice,
        uint256 start,
        uint256 end
    ) public pure returns (bytes memory) {
        require(
            start <= toSlice.length,
            "Start index is greater than the length of the byte string"
        );
        require(
            end <= toSlice.length,
            "End index is greater than the length of the byte string"
        );
        require(start < end, "Start index not less than end index");

        bytes memory sliced = new bytes(end - start);

        unchecked {
            for (uint256 i = 0; i < end; i++) {
                sliced[i] = toSlice[i + start];
            }
        }

        return sliced;
    }

    /// @notice function to get the hash of a slice of bytes
    function getSlicedBytesHash(
        bytes memory toSlice,
        uint256 start,
        uint256 end
    ) public pure returns (bytes32) {
        return keccak256(sliceBytes(toSlice, start, end));
    }

    /// @notice function to get the hash of a byte string
    /// returns the hash, for use in calldata checks, prettifies syntax
    function getBytesHash(bytes memory toHash) public pure returns (bytes32) {
        return keccak256(toHash);
    }
}
