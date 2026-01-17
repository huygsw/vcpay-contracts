// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMultisig {
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes calldata signatures
    ) external returns (bool, bytes memory);
}

contract Reenter {
    IMultisig public multisig;

    constructor(address _multisig) {
        multisig = IMultisig(_multisig);
    }

    receive() external payable {
        // attempt reentrancy (should fail due to guard)
        (bool ok,) = address(multisig).call(
            abi.encodeWithSignature("nonce()")
        );
        ok;
    }
}
