// SPDX-License-Identifier: MIT

pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import "../WitnetRequest.sol";
import "../WitnetRequestTemplate.sol";

contract WitnetRequestFactoryData {

    bytes32 internal constant _WITNET_REQUEST_SLOTHASH =
        /* keccak256("io.witnet.data.request") */
        0xbf9e297db5f64cdb81cd821e7ad085f56008e0c6100f4ebf5e41ef6649322034;

    bytes32 internal constant _WITNET_REQUEST_FACTORY_SLOTHASH =
        /* keccak256("io.witnet.data.request.factory") */
        0xfaf45a8ecd300851b566566df52ca7611b7a56d24a3449b86f4e21c71638e642;

    bytes32 internal constant _WITNET_REQUEST_TEMPLATE_SLOTHASH =
        /* keccak256("io.witnet.data.request.template") */
        0x50402db987be01ecf619cd3fb022cf52f861d188e7b779dd032a62d082276afb;

    struct WitnetRequestFactoryStorage {
        address owner;
        address pendingOwner;
    }

    struct WitnetRequestStorage {
        /// Radon RAD hash.
        bytes32 radHash;
        // /// Array of string arguments passed upon initialization.
        // string[][] args;
    }

    struct WitnetRequestTemplateStorage {
        /// @notice Array of retrievals hashes passed upon construction.
        bytes32[] retrieveHashes;
        /// @notice Aggregator reduce hash.
        bytes16 aggregateReduceHash;
        /// @notice Tally reduce hash.
        bytes16 tallyReduceHash;
    }

    function __witnetRequestFactory()
        internal pure
        returns (WitnetRequestFactoryStorage storage ptr)
    {
        assembly {
            ptr.slot := _WITNET_REQUEST_FACTORY_SLOTHASH
        }
    }

    function __witnetRequest()
        internal pure
        returns (WitnetRequestStorage storage ptr)
    {
        assembly {
            ptr.slot := _WITNET_REQUEST_SLOTHASH
        }
    }

    function __witnetRequestTemplate()
        internal pure
        returns (WitnetRequestTemplateStorage storage ptr)
    {
        assembly {
            ptr.slot := _WITNET_REQUEST_TEMPLATE_SLOTHASH
        }
    }
}