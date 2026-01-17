// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Counter
 * @notice Simple counter contract for testing multisig execution with calldata
 */
contract Counter {
    uint256 public count;

    function increment() external {
        count += 1;
    }

    function incrementBy(uint256 amount) external {
        count += amount;
    }

    function reset() external {
        count = 0;
    }
}
