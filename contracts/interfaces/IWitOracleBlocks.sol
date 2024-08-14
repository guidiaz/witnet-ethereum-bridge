// SPDX-License-Identifier: MIT

pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import "../libs/Witnet.sol";

interface IWitOracleBlocks {

    event Rollup(Witnet.Beacon head);

    function determineBeaconIndexFromTimestamp(uint256 timestamp) external pure returns (uint32);
    function determineEpochFromTimestamp(uint256 timestamp) external pure returns (uint64);

    function getBeaconByIndex(uint32 index) external view returns (Witnet.Beacon memory);
    function getLastKnownBeacon() external view returns (Witnet.Beacon memory);
    function getLastKnownBeaconIndex() external view returns (uint32);

    function rollupBeacons(Witnet.FastForward[] calldata ff) external returns (Witnet.Beacon memory);
}
