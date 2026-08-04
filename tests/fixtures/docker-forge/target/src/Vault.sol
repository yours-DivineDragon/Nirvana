// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract Vault {
    mapping(address account => uint256 amount) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount != 0, "empty balance");
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
        balanceOf[msg.sender] = 0;
    }
}

