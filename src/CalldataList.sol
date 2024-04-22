pragma solidity 0.8.25;

import {BytesHelper} from "src/BytesHelper.sol";

/// @notice calldata helper contract that stores calldata checks
/// allows whitelisting of specific calldata parameters for specific functions.
/// This enables the contract to check that the calldata conforms to the expected values.
/// While allowing flexibility in the calldata structure.
contract CalldataList {
    using BytesHelper for bytes;

    /// @notice event emitted when a new calldata check is added
    /// @param contractAddress the address of the contract that the calldata check is added to
    /// @param selector the function selector of the function that the calldata check is added to
    /// @param startIndex the start index of the calldata
    /// @param endIndex the end index of the calldata
    /// @param data the calldata that is stored
    event CalldataAdded(
        address indexed contractAddress,
        bytes4 indexed selector,
        uint16 startIndex,
        uint16 endIndex,
        bytes data
    );

    /// @notice event emitted when a calldata check is removed
    /// @param contractAddress the address of the contract that the calldata check is removed from
    /// @param selector the function selector of the function that the calldata check is removed from
    /// @param startIndex the start index of the calldata
    /// @param endIndex the end index of the calldata
    /// @param data the calldata that is removed
    event CalldataRemoved(
        address indexed contractAddress,
        bytes4 indexed selector,
        uint16 startIndex,
        uint16 endIndex,
        bytes data
    );

    /// @notice struct used to store the start and end index of the calldata
    /// and the calldata itself.
    /// Once the calldata is stored, it can be used to check if the calldata
    /// conforms to the expected values.
    struct Index {
        uint16 startIndex;
        uint16 endIndex;
        bytes data;
    }

    /// @notice struct used to store the calldata checks and the maximum
    /// amount of native tokens to be sent in a single call to a contract
    struct CallRestriction {
        Index[] calldataChecks;
        uint256 maxValue;
    }

    /// @notice mapping of contract address to function selector to Index struct
    mapping(address contractAddress => mapping(bytes4 selector => CallRestriction calldataChecks))
        public calldataList;

    /// @notice check if the calldata conforms to the expected values
    /// extracts indexes and checks that the data within the indexes
    /// matches the expected data
    /// @param contractAddress the address of the contract that the calldata check is applied to
    /// @param value the amount of native asset sent with the call
    /// @param data the calldata to check
    function checkCalldata(
        address contractAddress,
        uint256 value,
        bytes memory data
    ) public view {
        bytes4 selector = data.getFunctionSignature();

        Index[] storage calldataChecks = calldataList[contractAddress][selector]
            .calldataChecks;

        require(calldataChecks.length > 0, "No calldata checks found");
        require(
            value <= calldataList[contractAddress][selector].maxValue,
            "Value exceeds maximum value"
        );

        unchecked {
            for (uint256 i = 0; i < calldataChecks.length; i++) {
                Index storage calldataCheck = calldataChecks[i];

                require(
                    data.getSlicedBytesHash(
                        calldataCheck.startIndex,
                        calldataCheck.endIndex
                    ) == calldataCheck.data.getBytesHash(),
                    "Calldata does not match expected values"
                );
            }
        }
    }

    /// @notice add a calldata check
    /// @param contractAddress the address of the contract that the calldata check is added to
    /// @param selector the function selector of the function that the calldata check is added to
    /// @param startIndex the start index of the calldata
    /// @param endIndex the end index of the calldata
    /// @param data the calldata that is stored
    function _addCalldataCheck(
        address contractAddress,
        bytes4 selector,
        uint16 startIndex,
        uint16 endIndex,
        bytes memory data
    ) internal {
        require(startIndex >= 4, "Start index must be greater than 3");
        require(
            contractAddress != address(this),
            "Contract address cannot be this"
        );

        calldataList[contractAddress][selector].calldataChecks.push(
            Index(startIndex, endIndex, data)
        );

        emit CalldataAdded(
            contractAddress,
            selector,
            startIndex,
            endIndex,
            data
        );
    }

    /// @notice add a calldata check
    /// @param contractAddresses the address of the contract that the calldata check is added to
    /// @param selectors the function selector of the function that the calldata check is added to
    /// @param startIndexes the start indexes of the calldata
    /// @param endIndexes the end indexes of the calldata
    /// @param datas the calldata that is stored
    function _addCalldataChecks(
        address[] memory contractAddresses,
        bytes4[] memory selectors,
        uint16[] memory startIndexes,
        uint16[] memory endIndexes,
        bytes[] memory datas
    ) internal {
        require(
            contractAddresses.length == selectors.length &&
                selectors.length == startIndexes.length &&
                startIndexes.length == endIndexes.length &&
                endIndexes.length == datas.length,
            "Array lengths must be equal"
        );

        for (uint256 i = 0; i < contractAddresses.length; i++) {
            _addCalldataCheck(
                contractAddresses[i],
                selectors[i],
                startIndexes[i],
                endIndexes[i],
                datas[i]
            );
        }
    }

    /// @notice remove a calldata check by index
    /// @param contractAddress the address of the contract that the calldata check is removed from
    /// @param selector the function selector of the function that the calldata check is removed from
    /// @param index the index of the calldata check to remove
    function _removeCalldataCheck(
        address contractAddress,
        bytes4 selector,
        uint256 index
    ) internal {
        Index[] storage calldataChecks = calldataList[contractAddress][selector]
            .calldataChecks;
        uint16 startIndex = calldataChecks[index].startIndex;
        uint16 endIndex = calldataChecks[index].endIndex;
        bytes memory data = calldataChecks[index].data;

        calldataChecks[index] = calldataChecks[calldataChecks.length - 1];
        calldataChecks.pop();

        emit CalldataRemoved(
            contractAddress,
            selector,
            startIndex,
            endIndex,
            data
        );
    }

    function _removeAllCalldataChecks(
        address contractAddress,
        bytes4 selector
    ) internal {
        Index[] storage calldataChecks = calldataList[contractAddress][selector]
            .calldataChecks;

        require(calldataChecks.length > 0, "No calldata checks to remove");

        /// delete all calldata in the list for the given contract and selector
        while (calldataChecks.length != 0) {
            emit CalldataRemoved(
                contractAddress,
                selector,
                calldataChecks[0].startIndex,
                calldataChecks[0].endIndex,
                calldataChecks[0].data
            );
            calldataChecks.pop();
        }

        /// delete the calldata list for the given contract and selector
        delete calldataList[contractAddress][selector];
    }

    /// @notice remove a calldata check by calldata
    /// @param contractAddress the address of the contract that the calldata check is removed from
    /// @param selector the function selector of the function that the calldata check is removed from
    /// @param startIndex the start index of the calldata
    /// @param endIndex the end index of the calldata
    /// @param data the calldata that is removed
    function _removeCalldataCheck(
        address contractAddress,
        bytes4 selector,
        uint16 startIndex,
        uint16 endIndex,
        bytes memory data
    ) internal {
        Index[] storage calldataChecks = calldataList[contractAddress][selector]
            .calldataChecks;

        for (uint256 i = 0; i < calldataChecks.length; i++) {
            if (
                calldataChecks[i].startIndex == startIndex &&
                calldataChecks[i].endIndex == endIndex &&
                keccak256(calldataChecks[i].data) == keccak256(data)
            ) {
                calldataChecks[i] = calldataChecks[calldataChecks.length - 1];
                calldataChecks.pop();

                emit CalldataRemoved(
                    contractAddress,
                    selector,
                    startIndex,
                    endIndex,
                    data
                );

                return;
            }
        }

        revert("Calldata check not found");
    }
}
