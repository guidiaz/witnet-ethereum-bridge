// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0 <0.9.0;

import "./interfaces/V2/IFeeds.sol";
import "./interfaces/V2/IWitnetFeeds.sol";
import "./interfaces/V2/IWitnetFeedsAdmin.sol";
import "./interfaces/V2/IWitnetFeedsEvents.sol";

abstract contract WitnetFeeds
    is 
        IFeeds,
        IWitnetFeeds,
        IWitnetFeedsAdmin,
        IWitnetFeedsEvents
{
    Witnet.RadonDataTypes immutable public override dataType;
    WitnetBytecodes immutable public override registry;
    WitnetRequestBoard immutable public override witnet;

    bytes32 immutable internal __prefix;

    constructor(
            WitnetRequestBoard _wrb,
            Witnet.RadonDataTypes _dataType,
            string memory _prefix
        )
    {
        witnet = _wrb;
        registry = witnet.registry();
        dataType = _dataType;
        __prefix = Witnet.toBytes32(bytes(_prefix));
    }

    function prefix() override public view returns (string memory) {
        return Witnet.toString(__prefix);
    }
}