pragma solidity 0.8.25;

import {BytesHelper} from "src/BytesHelper.sol";

/// @notice calldata helper contract that stores calldata checks
/// allows whitelisting of specific calldata parameters for specific functions.
/// This enables the contract to check that the calldata conforms to the expected values.
/// While allowing flexibility in the calldata structure.
/// This is an abstract contract because it does not offer any public functions,
/// and must be inherited by another contract to be used.
abstract contract CalldataList {
    using BytesHelper for bytes;

    /// @notice event emitted when a new calldata check is added
    /// @param contractAddress the address of the contract that the calldata check is added to
    /// @param selector the function selector of the function that the calldata check is added to
    /// @param startIndex the start index of the calldata
    /// @param endIndex the end index of the calldata
    /// @param dataHash the hash of the calldata that is stored
    event CalldataAdded(
        address indexed contractAddress,
        bytes4 indexed selector,
        uint16 startIndex,
        uint16 endIndex,
        bytes32 dataHash
    );

    /// @notice event emitted when a calldata check is removed
    /// @param contractAddress the address of the contract that the calldata check is removed from
    /// @param selector the function selector of the function that the calldata check is removed from
    /// @param startIndex the start index of the calldata
    /// @param endIndex the end index of the calldata
    /// @param dataHash the hash of the calldata that is stored
    event CalldataRemoved(
        address indexed contractAddress,
        bytes4 indexed selector,
        uint16 startIndex,
        uint16 endIndex,
        bytes32 dataHash
    );

    /// @notice struct used to store the start and end index of the calldata
    /// and the calldata itself.
    /// Once the calldata is stored, it can be used to check if the calldata
    /// conforms to the expected values.
    struct Index {
        uint16 startIndex;
        uint16 endIndex;
        bytes32 dataHash;
    }

    /// @notice mapping of contract address to function selector to array of Index structs
    mapping(
        address contractAddress
            => mapping(bytes4 selector => Index[] calldataChecks)
    ) private _calldataList;

    /// @notice get the calldata checks for a specific contract and function selector
    function getCalldataChecks(address contractAddress, bytes4 selector)
        public
        view
        returns (Index[] memory)
    {
        return _calldataList[contractAddress][selector];
    }

    /// @notice check if the calldata conforms to the expected values
    /// extracts indexes and checks that the data within the indexes
    /// matches the expected data
    /// @param contractAddress the address of the contract that the calldata check is applied to
    /// @param data the calldata to check
    function checkCalldata(address contractAddress, bytes memory data)
        public
        view
    {
        bytes4 selector = data.getFunctionSignature();

        Index[] storage calldataChecks =
            _calldataList[contractAddress][selector];

        require(
            calldataChecks.length > 0, "CalldataList: No calldata checks found"
        );

        for (uint256 i = 0; i < calldataChecks.length; i++) {
            Index storage calldataCheck = calldataChecks[i];

            require(
                data.getSlicedBytesHash(
                    calldataCheck.startIndex, calldataCheck.endIndex
                ) == calldataCheck.dataHash,
                "CalldataList: Calldata does not match expected value"
            );
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
        require(
            startIndex >= 4, "CalldataList: Start index must be greater than 3"
        );
        require(
            endIndex > startIndex,
            "CalldataList: End index must be greater than start index"
        );
        require(
            contractAddress != address(this),
            "CalldataList: Contract address cannot be this"
        );
        bytes32 dataHash = keccak256(data);

        _calldataList[contractAddress][selector].push(
            Index(startIndex, endIndex, dataHash)
        );

        emit CalldataAdded(
            contractAddress, selector, startIndex, endIndex, dataHash
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
            contractAddresses.length == selectors.length
                && selectors.length == startIndexes.length
                && startIndexes.length == endIndexes.length
                && endIndexes.length == datas.length,
            "CalldataList: Array lengths must be equal"
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
        Index[] storage calldataChecks =
            _calldataList[contractAddress][selector];
        /// if no calldata checks are found, this check will fail because
        /// calldataChecks.length will be 0, and no uint value can be lt 0
        require(
            index < calldataChecks.length,
            "CalldataList: Calldata index out of bounds"
        );

        uint16 startIndex = calldataChecks[index].startIndex;
        uint16 endIndex = calldataChecks[index].endIndex;
        bytes32 dataHash = calldataChecks[index].dataHash;

        calldataChecks[index] = calldataChecks[calldataChecks.length - 1];
        calldataChecks.pop();

        emit CalldataRemoved(
            contractAddress, selector, startIndex, endIndex, dataHash
        );
    }

    /// @notice remove all calldata checks for a given contract and selector
    /// iterates over all checks for the given contract and selector and removes
    /// them from the array.
    /// @param contractAddress the address of the contract that the calldata
    /// checks are removed from
    /// @param selector the function selector of the function that the calldata
    /// checks are removed from
    function _removeAllCalldataChecks(address contractAddress, bytes4 selector)
        internal
    {
        Index[] storage calldataChecks =
            _calldataList[contractAddress][selector];

        require(
            calldataChecks.length > 0,
            "CalldataList: No calldata checks to remove"
        );

        /// delete all calldata in the list for the given contract and selector
        while (calldataChecks.length != 0) {
            emit CalldataRemoved(
                contractAddress,
                selector,
                calldataChecks[0].startIndex,
                calldataChecks[0].endIndex,
                calldataChecks[0].dataHash
            );
            calldataChecks.pop();
        }

        /// delete the calldata list for the given contract and selector
        delete _calldataList[contractAddress][selector];
    }
}
