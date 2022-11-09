// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0 <0.9.0;

import "./Witnet.sol";

library WitnetV2 {

    error IndexOutOfBounds(uint256 index, uint256 range);
    error InsufficientBalance(uint256 weiBalance, uint256 weiExpected);
    error InsufficientFee(uint256 weiProvided, uint256 weiExpected);
    error Unauthorized(address violator);
    

    function toEpoch(uint _timestamp) internal pure returns (uint) {
        return 1 + (_timestamp - 11111) / 15;
    }

    function toTimestamp(uint _epoch) internal pure returns (uint) {
        return 111111+ _epoch * 15;
    }

    struct Beacon {
        uint256 escrow;
        uint256 evmBlock;
        uint256 gasprice;
        address relayer;
        address slasher;
        uint256 superblockIndex;
        uint256 superblockRoot;        
    }

    enum BeaconStatus {
        Idle
    }

    struct Block {
        bytes32 blockHash;
        bytes32 drTxsRoot;
        bytes32 drTallyTxsRoot;
    }
    
    enum BlockStatus {
        Idle
    }

    struct DrSla {
        uint64 witnessReward;
        uint16 numwitnesses;
        uint64 commitRevelFee;
        uint32 minConsensusPercentage;
        uint64 collateral;        
    }

    struct DrPost {
        uint256 block;
        DrPostStatus status;
        DrPostRequest request;
        DrPostResponse response;
    }

    enum DrPostStatus {
        Void,
        Deleted,
        Expired,
        Posted,
        Disputed,
        Reported,
        Finalized,
        Accepted,
        Rejected
    }

    /// Data kept in EVM-storage for every Request posted to the Witnet Request Board.
    struct DrPostRequest {
        uint256 epoch;
        address requester;
        address reporter;
        bytes32 radHash;
        bytes32 slaHash;
        uint256 weiReward;
    }

    /// Data kept in EVM-storage containing Witnet-provided response metadata and result.
    struct DrPostResponse {
        address disputer;
        address reporter;
        uint256 escrowed;
        uint256 drCommitTxEpoch;
        uint256 drTallyTxEpoch;
        bytes32 drTallyTxHash;
        bytes   drTallyResultBytes;
    }

    enum Types {
        Integer
    }

}