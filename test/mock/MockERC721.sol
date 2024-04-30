pragma solidity 0.8.25;

import {ERC721} from "@openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";

contract MockERC721 is ERC721("Mock", "MOCK NFT") {
    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId) public {
        _safeMint(to, tokenId);
    }
}
