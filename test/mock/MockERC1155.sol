pragma solidity ^0.8.20;

import {ERC1155} from
    "@openzeppelin-contracts/contracts/token/ERC1155/ERC1155.sol";

contract MockERC1155 is ERC1155("URI") {
    function mint(address to, uint256 tokenId, uint256 amount) public {
        _mint(to, tokenId, amount, "");
    }

    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory values
    ) public {
        _mintBatch(to, ids, values, "");
    }
}
