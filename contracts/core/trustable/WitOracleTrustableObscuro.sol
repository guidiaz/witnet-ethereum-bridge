// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0 <0.9.0;

import "../base/WitOracleBaseTrustable.sol";

/// @title Witnet Request Board "trustable" implementation contract.
/// @notice Contract to bridge requests to Witnet Decentralized Oracle Network.
/// @dev This contract enables posting requests that Witnet bridges will insert into the Witnet network.
/// The result of the requests will be posted back to this contract by the bridge nodes too.
/// @author The Witnet Foundation
contract WitOracleTrustableObscuro
    is 
        WitOracleBaseTrustable
{
    function class() virtual override public view returns (string memory) {
        return type(WitOracleBaseTrustable).name;
    }

    constructor(
            EvmImmutables memory _immutables,
            WitOracleRadonRegistry _registry,
            bytes32 _versionTag
        )
        WitOracleBase(
            _immutables,
            _registry
        )
        WitOracleBaseTrustable(_versionTag)
    {}

    // ================================================================================================================
    // --- Overrides 'IWitOracle' -------------------------------------------------------------------------------------

    /// @notice Gets the whole Query data contents, if any, no matter its current status.
    /// @dev Fails if or if `msg.sender` is not the actual requester.
    function getQuery(Witnet.QueryId _queryId)
        public view
        virtual override
        onlyRequester(_queryId)
        returns (Witnet.Query memory)
    {
        return super.getQuery(_queryId);
    }

    /// @notice Retrieves the whole `Witnet.QueryResponse` record referred to a previously posted Witnet Data Request.
    /// @dev Fails if the `_queryId` is not in 'Reported' status, or if `msg.sender` is not the actual requester.
    /// @param _queryId The unique query identifier
    function getQueryResponse(Witnet.QueryId _queryId)
        public view
        virtual override
        onlyRequester(_queryId)
        returns (Witnet.QueryResponse memory _response)
    {
        return super.getQueryResponse(_queryId);
    }

    function getQueryResult(Witnet.QueryId _queryId)
        virtual override
        public view
        onlyRequester(_queryId)
        returns (Witnet.DataResult memory)
    {
        return WitOracleBase.getQueryResult(_queryId);
    }

    function getQueryResultStatus(Witnet.QueryId _queryId)
        virtual override
        public view
        onlyRequester(_queryId)
        returns (Witnet.ResultStatus)
    {
        return super.getQueryResultStatus(_queryId);
    }

    function getQueryResultStatusDescription(Witnet.QueryId _queryId)
        virtual override
        public view
        onlyRequester(_queryId)
        returns (string memory)
    {
        return WitOracleBase.getQueryResultStatusDescription(_queryId);
    }
}
