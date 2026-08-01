// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Vault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function legacyAuth() external view returns (bool) {
        // tx.origin in a comment must not create a second candidate.
        return tx.origin == owner;
    }

    function forward(address implementation, bytes calldata data) external {
        (bool ok,) = implementation.delegatecall(data);
        require(ok);
    }
}
