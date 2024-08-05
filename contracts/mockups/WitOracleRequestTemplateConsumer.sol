// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./UsingWitOracleRequestTemplate.sol";
import "./WitOracleConsumer.sol";

abstract contract WitOracleRequestTemplateConsumer
    is
        UsingWitOracleRequestTemplate,
        WitOracleConsumer
{
    using WitnetCBOR for WitnetCBOR.CBOR;
    using WitnetCBOR for WitnetCBOR.CBOR[];
    
    /// @param _witOracleRequestTemplate Address of the WitOracleRequestTemplate from which actual data requests will get built.
    /// @param _baseFeeOverheadPercentage Percentage over base fee to pay as on every data request.
    /// @param _callbackGasLimit Maximum gas to be spent by the IWitOracleConsumer's callback methods.
    constructor(
            WitOracleRequestTemplate _witOracleRequestTemplate, 
            uint16 _baseFeeOverheadPercentage,
            uint24 _callbackGasLimit
        )
        UsingWitOracleRequestTemplate(_witOracleRequestTemplate, _baseFeeOverheadPercentage)
        WitOracleConsumer(_callbackGasLimit)
    {}

    /// @dev Estimate the minimum reward required for posting a data request (based on `tx.gasprice` and 
    /// @dev `__witOracleCallbackGasLimit`).
    function _witOracleEstimateBaseFee()
        virtual override(UsingWitOracle, WitOracleConsumer)
        internal view
        returns (uint256)
    {
        return WitOracleConsumer._witOracleEstimateBaseFee();
    }

    /// @dev Pulls a fresh update from the Wit/oracle blockchain based on some data request built out
    /// @dev of the underlying `witOracleRequestTemplate`, the default `__witOracleDefaultQuerySLA` data
    /// @dev security parameters and the immutable value of `__witOracleCallbackGasLimit`.
    /// @dev Returns the unique RAD hash of the just-built data request, and some unique query id. 
    /// @dev Reverts if the number of given parameters don't match as required by the underlying template's 
    /// @dev parameterized data sources (i.e. Radon Retrievals). 
    /// @param _queryEvmReward The exact EVM reward passed to the WitOracle bridge when pulling the data update.
    /// @param _witOracleRequestArgs Parameters passed to the `witOracleRequestTemplate` for building a new data request.
    function __witOraclePostQuery(
            uint256 _queryEvmReward,
            string[][] memory _witOracleRequestArgs
        )
        virtual override internal returns (bytes32, uint256)
    {
        return __witOraclePostQuery(
            _queryEvmReward, 
            __witOracleDefaultQuerySLA,
            _witOracleRequestArgs
        );
    }

    /// @dev Pulls a fresh update from the Wit/oracle blockchain based on some data request built out
    /// @dev of the underlying `witOracleRequestTemplate`, and the given `_querSLA` data security parameters,
    /// @dev and the immutable value of `__witOracleCallbackGasLimit`. 
    /// @dev Returns the unique RAD hash of the just-built data request, and some unique query id. 
    /// @dev Reverts if the number of given parameters don't match as required by the underlying template's 
    /// @dev parameterized data sources (i.e. Radon Retrievals). 
    /// @param _queryEvmReward The exact EVM reward passed to the WitOracle bridge when pulling the data update.
    /// @param _querySLA The required SLA data security params for the Wit/oracle blockchain to accomplish.
    /// @param _witOracleRequestArgs Parameters passed to the `witOracleRequestTemplate` for building a new data request.
    function __witOraclePostQuery(
            uint256 _queryEvmReward,
            Witnet.RadonSLA memory _querySLA,
            string[][] memory _witOracleRequestArgs
        )
        virtual override internal
        returns (
            bytes32 _queryRadHash, 
            uint256 _queryId
        )
    {
        _queryRadHash = __witOracleVerifyRadHash(_witOracleRequestArgs);
        _queryId = __witOracle.postRequestWithCallback{
            value: _queryEvmReward
        }(
            _queryRadHash,
            _querySLA,
            __witOracleCallbackGasLimit
        );
    }
}
