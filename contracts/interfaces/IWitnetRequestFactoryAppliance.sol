// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IWitnetOracleAppliance.sol";
import "../WitnetRequestFactory.sol";

abstract contract IWitnetRequestFactoryAppliance
    is
        IWitnetOracleAppliance,
        IWitnetRequestFactoryEvents,
        IWitnetRequestRegistryEvents
{
    function factory() virtual external view returns (WitnetRequestFactory);
}
