// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Vault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function legacyAuth() external view returns (bool) {
        return msg.sender == owner;
    }

    function forward(address implementation, bytes calldata data) external {
        (bool ok,) = implementation.delegatecall(data);
        require(ok);
    }
}
