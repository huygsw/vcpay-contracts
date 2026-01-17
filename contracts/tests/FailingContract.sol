// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FailingContract
 * @notice Contract that always reverts - for testing executeStrict error handling
 */
contract FailingContract {
    error AlwaysReverts();

    function alwaysFails() external pure {
        revert AlwaysReverts();
    }

    function failsWithMessage() external pure {
        revert("This function always fails");
    }
}
