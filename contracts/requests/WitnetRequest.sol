// SPDX-License-Identifier: MIT

pragma solidity >=0.7.0 <0.9.0;

import "./WitnetRequestBase.sol";

contract WitnetRequest
    is
        IWitnetRequest
{
    using Witnet for bytes;

    /// Contains a well-formed Witnet Data Request, encoded using Protocol Buffers.
    bytes public override bytecode;

    /// Returns SHA256 hash of Witnet Data Request as CBOR-encoded bytes.
    bytes32 public override codehash;

    constructor(bytes memory _bytecode) {
        bytecode = _bytecode;
        codehash = _bytecode.computeCodehash();
    }
}
