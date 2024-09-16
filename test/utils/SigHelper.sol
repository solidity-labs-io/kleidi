pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

abstract contract SigHelper is Test {
    function signTx(bytes32 transactionHash, uint256 _pk)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, transactionHash);
        return abi.encodePacked(r, s, v);
    }

    function signTxAllOwners(
        bytes32 transactionHash,
        uint256 _pk1,
        uint256 _pk2,
        uint256 _pk3
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            signTx(transactionHash, _pk1),
            signTx(transactionHash, _pk2),
            signTx(transactionHash, _pk3)
        );
    }
}
