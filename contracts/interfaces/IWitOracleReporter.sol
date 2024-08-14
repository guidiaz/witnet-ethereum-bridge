// SPDX-License-Identifier: MIT

pragma solidity >=0.7.0 <0.9.0;

import "../libs/Witnet.sol";

/// @title The Witnet Request Board Reporter interface.
/// @author The Witnet Foundation.
interface IWitOracleReporter {

    /// @notice Estimates the actual earnings in WEI, that a reporter would get by reporting result to given query,
    /// @notice based on the gas price of the calling transaction. Data requesters should consider upgrading the reward on 
    /// @notice queries providing no actual earnings.
    function estimateReportEarnings(
            uint256[] calldata queryIds, 
            bytes calldata reportTxMsgData,
            uint256 reportTxGasPrice,
            uint256 nanoWitPrice
        ) external view returns (uint256, uint256);

    /// @notice Retrieves the Witnet Data Request bytecodes and SLAs of previously posted queries.
    /// @dev Returns empty buffer if the query does not exist.
    /// @param queryIds Query identifiers.
    function extractWitnetDataRequests(uint256[] calldata queryIds) 
        external view returns (bytes[] memory drBytecodes);

    function reportQueryResponse(Witnet.QueryResponseReport calldata report) external returns (uint256);
    function reportQueryResponseBatch(Witnet.QueryResponseReport[] calldata reports) external returns (uint256);
    function rollupQueryResponseProof(Witnet.FastForward[] calldata, Witnet.QueryResponseReport calldata, bytes32[] calldata) external;
    function rollupQueryReportProof(Witnet.FastForward[] calldata, Witnet.QueryReport calldata reports, bytes32[] calldata) external;
    function verifyQueryReportProof(Witnet.QueryReport calldata report, bytes32[] calldata) external view returns (bool);

    event BatchReportError(uint256 queryId, string reason);
}
