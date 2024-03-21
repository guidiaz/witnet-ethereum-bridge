// SPDX-License-Identifier: MIT

pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import "../../UsingWitnet.sol";
import "../../WitnetRandomness.sol";
import "../../impls/WitnetUpgradableBase.sol";
import "../../patterns/Clonable.sol";

import "../../requests/WitnetRequest.sol";

/// @title WitnetRandomnessProxiable: A trustless randomness generator and registry, using the Witnet oracle. 
/// @author Witnet Foundation.
contract WitnetRandomnessProxiable
    is
        Clonable,
        UsingWitnet,
        WitnetRandomness,
        WitnetUpgradableBase
{
    using ERC165Checker for address;
    using Witnet for Witnet.Result;

    uint256 public override latestRandomizeBlock;
    WitnetRequest public immutable override witnetRandomnessRequest;

    bytes32 internal immutable __witnetRandomnessRadHash;
    bytes32 internal __witnetRandomnessSlaHash;
    
    mapping (uint256 => RandomizeData) internal __randomize_;
    struct RandomizeData {
        address from;
        uint256 prevBlock;
        uint256 nextBlock;
        uint256 witnetQueryId;
    }

    modifier onlyDelegateCalls override(Clonable, Upgradeable) {
        require(address(this) != base(), "WitnetRandomnessProxiable: not a delegate call");
        _;
    }

    function witnet()
        virtual override (IWitnetRandomness, UsingWitnet)
        public view returns (WitnetRequestBoard)
    {
        return UsingWitnet.witnet();
    }

    /// Include an address to specify the immutable WitnetRequestBoard entrypoint address.
    /// @param _wrb The WitnetRequestBoard immutable entrypoint address.
    constructor(
            WitnetRequestBoard _wrb,
            bytes32 _version
        )
        UsingWitnet(_wrb)
        WitnetUpgradableBase(
            false, 
            _version,
            "io.witnet.proxiable.randomness"
        )
    {
        require(
            address(_wrb) == address(0)
                || address(_wrb).supportsInterface(type(WitnetRequestBoard).interfaceId),
            "WitnetRandomnessProxiable: uncompliant request board"
        );
        WitnetBytecodes _registry = witnet().registry();
        WitnetRequestFactory _factory = witnet().factory();
        {
            // Build own Witnet Randomness Request:
            bytes32[] memory _retrievals = new bytes32[](1);
            _retrievals[0] = _registry.verifyRadonRetrieval(
                Witnet.RadonDataRequestMethods.RNG,
                "", // no schema
                "", // no authority
                "", // no path
                "", // no query
                "", // no body
                new string[2][](0), // no headers
                hex"80" // no retrieval script
            );
            Witnet.RadonFilter[] memory _filters;
            bytes32 _aggregator = _registry.verifyRadonReducer(Witnet.RadonReducer({
                opcode: Witnet.RadonReducerOpcodes.Mode,
                filters: _filters, // no filters
                script: hex"" // no aggregation script
            }));
            bytes32 _tally = _registry.verifyRadonReducer(Witnet.RadonReducer({
                opcode: Witnet.RadonReducerOpcodes.ConcatenateAndHash,
                filters: _filters, // no filters
                script: hex"" // no aggregation script
            }));
            WitnetRequestTemplate _template = WitnetRequestTemplate(_factory.buildRequestTemplate(
                _retrievals,
                _aggregator,
                _tally,
                0
            ));
            witnetRandomnessRequest = WitnetRequest(_template.buildRequest(new string[][](_retrievals.length)));
            __witnetRandomnessRadHash = witnetRandomnessRequest.radHash();
        }
        __initializeWitnetRandomnessSlaHash();
    }

    /// @notice Initializes a cloned instance. 
    /// @dev Every cloned instance can only get initialized once.
    function initializeClone(bytes memory _initData)
        virtual external
        initializer // => ensure a cloned instance can only be initialized once
        onlyDelegateCalls // => this method can only be called upon cloned instances
    {
        _initialize(_initData);
    }


    /// ===============================================================================================================
    /// --- 'WitnetRandomnessAdmin' implementation -------------------------------------------------------------------------

    function owner()
        virtual override (IWitnetRandomnessAdmin, Ownable)
        public view 
        returns (address)
    {
        return Ownable.owner();
    }
    
    function acceptOwnership()
        virtual override (IWitnetRandomnessAdmin, Ownable2Step)
        public
    {
        Ownable2Step.acceptOwnership();
    }

    function pendingOwner() 
        virtual override (IWitnetRandomnessAdmin, Ownable2Step)
        public view
        returns (address)
    {
        return Ownable2Step.pendingOwner();
    }
    
    function transferOwnership(address _newOwner)
        virtual override (IWitnetRandomnessAdmin, Ownable2Step)
        public 
        onlyOwner
    {
        Ownable.transferOwnership(_newOwner);
    }

    function settleWitnetRandomnessSLA(Witnet.RadonSLA memory _radonSLA)
        virtual override
        public
        onlyOwner
        returns (bytes32 _radonSlaHash)
    {
        _radonSlaHash = witnet().registry().verifyRadonSLA(_radonSLA);
        __witnetRandomnessSlaHash = _radonSlaHash;
    }
    
    /// ===============================================================================================================
    /// --- 'WitnetRandomness' implementation -------------------------------------------------------------------------

    /// Deploys and returns the address of a minimal proxy clone that replicates contract
    /// behaviour while using its own EVM storage.
    /// @dev This function should always provide a new address, no matter how many times 
    /// @dev is actually called from the same `msg.sender`.
    function clone()
        virtual override
        public
        wasInitialized
        returns (WitnetRandomness)
    {
        return _afterClone(_clone());
    }

    /// Deploys and returns the address of a minimal proxy clone that replicates contract 
    /// behaviour while using its own EVM storage.
    /// @dev This function uses the CREATE2 opcode and a `_salt` to deterministically deploy
    /// @dev the clone. Using the same `_salt` multiple time will revert, since
    /// @dev no contract can be deployed more than once at the same address.
    function cloneDeterministic(bytes32 _salt)
        virtual override
        public
        wasInitialized
        returns (WitnetRandomness)
    {
        return _afterClone(_cloneDeterministic(_salt));
    }

    /// Returns amount of wei required to be paid as a fee when requesting randomization with a 
    /// transaction gas price as the one given.
    function estimateRandomizeFee(uint256 _gasPrice)
        public view
        virtual override
        returns (uint256)
    {
        return witnet().estimateReward(_gasPrice);
    }

    /// Retrieves data of a randomization request that got successfully posted to the WRB within a given block.
    /// @dev Returns zero values if no randomness request was actually posted within a given block.
    /// @param _block Block number whose randomness request is being queried for.
    /// @return _from Address from which the latest randomness request was posted.
    /// @return _id Unique request identifier as provided by the WRB.
    /// @return _prevBlock Block number in which a randomness request got posted just before this one. 0 if none.
    /// @return _nextBlock Block number in which a randomness request got posted just after this one, 0 if none.
    function getRandomizeData(uint256 _block)
        external view
        virtual override
        returns (
            address _from,
            uint256 _id,
            uint256 _prevBlock,
            uint256 _nextBlock
        )
    {
        RandomizeData storage _data = __randomize_[_block];
        _id = _data.witnetQueryId;
        _from = _data.from;
        _prevBlock = _data.prevBlock;
        _nextBlock = _data.nextBlock;
    }

    /// Retrieves the randomness generated upon solving a request that was posted within a given block,
    /// if any, or to the _first_ request posted after that block, otherwise. Should the intended 
    /// request happen to be finalized with errors on the Witnet oracle network side, this function 
    /// will recursively try to return randomness from the next non-faulty randomization request found 
    /// in storage, if any. 
    /// @dev Fails if:
    /// @dev   i.   no `randomize()` was not called in either the given block, or afterwards.
    /// @dev   ii.  a request posted in/after given block does exist, but no result has been provided yet.
    /// @dev   iii. all requests in/after the given block were solved with errors.
    /// @param _block Block number from which the search will start.
    function getRandomnessAfter(uint256 _block)
        public view
        virtual override
        returns (bytes32)
    {
        if (__randomize_[_block].from == address(0)) {
            _block = getRandomnessNextBlock(_block);
        }
        uint256 _queryId = __randomize_[_block].witnetQueryId;
        require(_queryId != 0, "WitnetRandomnessProxiable: not randomized");
        Witnet.ResultStatus _resultStatus = witnet().checkResultStatus(_queryId);
        if (_resultStatus == Witnet.ResultStatus.Ready) {
            return witnet().readResponseResult(_queryId).asBytes32();
        } else if (_resultStatus == Witnet.ResultStatus.Error) {
            uint256 _nextRandomizeBlock = __randomize_[_block].nextBlock;
            require(_nextRandomizeBlock != 0, "WitnetRandomnessProxiable: faulty randomize");
            return getRandomnessAfter(_nextRandomizeBlock);
        } else {
            revert("WitnetRandomnessProxiable: pending randomize");
        }
    }

    /// Tells what is the number of the next block in which a randomization request was posted after the given one. 
    /// @param _block Block number from which the search will start.
    /// @return Number of the first block found after the given one, or `0` otherwise.
    function getRandomnessNextBlock(uint256 _block)
        public view
        virtual override
        returns (uint256)
    {
        return ((__randomize_[_block].from != address(0))
            ? __randomize_[_block].nextBlock
            // start search from the latest block
            : _searchNextBlock(_block, latestRandomizeBlock)
        );
    }

    /// Gets previous block in which a randomness request was posted before the given one.
    /// @param _block Block number from which the search will start. Cannot be zero.
    /// @return First block found before the given one, or `0` otherwise.
    function getRandomnessPrevBlock(uint256 _block)
        public view
        virtual override
        returns (uint256)
    {
        assert(_block > 0);
        uint256 _latest = latestRandomizeBlock;
        return ((_block > _latest)
            ? _latest
            // start search from the latest block
            : _searchPrevBlock(_block, __randomize_[_latest].prevBlock)
        );
    }

    /// Returns `true` only when the randomness request that got posted within given block was already
    /// reported back from the Witnet oracle, either successfully or with an error of any kind.
    function isRandomized(uint256 _block)
        public view
        virtual override
        returns (bool)
    {
        RandomizeData storage _data = __randomize_[_block];
        return (
            _data.witnetQueryId != 0 
                && witnet().getQueryStatus(_data.witnetQueryId) == Witnet.QueryStatus.Reported
        );
    }

    /// Generates a pseudo-random number uniformly distributed within the range [0 .. _range), by using 
    /// the given `_nonce` value and the randomness returned by `getRandomnessAfter(_block)`. 
    /// @dev Fails under same conditions as `getRandomnessAfter(uint256)` may do.
    /// @param _range Range within which the uniformly-distributed random number will be generated.
    /// @param _nonce Nonce value enabling multiple random numbers from the same randomness value.
    /// @param _block Block number from which the search will start.
    function random(uint32 _range, uint256 _nonce, uint256 _block)
        external view
        virtual override
        returns (uint32)
    {
        return random(
            _range,
            _nonce,
            keccak256(
                abi.encode(
                    msg.sender,
                    getRandomnessAfter(_block)
                )
            )
        );
    }

    /// Generates a pseudo-random number uniformly distributed within the range [0 .. _range), by using 
    /// the given `_nonce` value and the given `_seed` as a source of entropy.
    /// @param _range Range within which the uniformly-distributed random number will be generated.
    /// @param _nonce Nonce value enabling multiple random numbers from the same randomness value.
    /// @param _seed Seed value used as entropy source.
    function random(uint32 _range, uint256 _nonce, bytes32 _seed)
        public pure
        virtual override
        returns (uint32)
    {
        uint8 _flagBits = uint8(255 - _msbDeBruijn32(_range));
        uint256 _number = uint256(
                keccak256(
                    abi.encode(_seed, _nonce)
                )
            ) & uint256(2 ** _flagBits - 1);
        return uint32((_number * _range) >> _flagBits);
    }

    /// Requests the Witnet oracle to generate an EVM-agnostic and trustless source of randomness. 
    /// Only one randomness request per block will be actually posted to the WRB. Should there 
    /// already be a posted request within current block, it will try to upgrade Witnet fee of current's 
    /// block randomness request according to current gas price. In both cases, all unused funds shall 
    /// be transfered back to the tx sender.
    /// @return _usedFunds Amount of funds actually used from those provided by the tx sender.
    function randomize()
        external payable
        virtual override
        returns (uint256 _usedFunds)
    {
        if (latestRandomizeBlock < block.number) {
            // Post the Witnet Randomness request:
            uint _queryId;
            (_queryId, _usedFunds) = _witnetPostRequest(
                __witnetRandomnessRadHash,
                __witnetRandomnessSlaHash  
            );
            // Keep Randomize data in storage:
            RandomizeData storage _data = __randomize_[block.number];
            _data.witnetQueryId = _queryId;
            _data.from = msg.sender;
            // Update block links:
            uint256 _prevBlock = latestRandomizeBlock;
            _data.prevBlock = _prevBlock;
            __randomize_[_prevBlock].nextBlock = block.number;
            latestRandomizeBlock = block.number;
            // Throw event:
            emit Randomized(
                msg.sender,
                _prevBlock,
                _queryId,
                __witnetRandomnessRadHash
            );
            // Transfer back unused tx value:
            if (_usedFunds < msg.value) {
                payable(msg.sender).transfer(msg.value - _usedFunds);
            }
        } else {
            return upgradeRandomizeFee(block.number);
        }
    }

    /// Increases Witnet fee related to a pending-to-be-solved randomness request, as much as it
    /// may be required in proportion to how much bigger the current tx gas price is with respect the 
    /// highest gas price that was paid in either previous fee upgrades, or when the given randomness 
    /// request was posted. All unused funds shall be transferred back to the tx sender.
    /// @return _usedFunds Amount of dunds actually used from those provided by the tx sender.
    function upgradeRandomizeFee(uint256 _block)
        public payable
        virtual override
        returns (uint256 _usedFunds)
    {
        RandomizeData storage _data = __randomize_[_block];
        if (_data.witnetQueryId != 0) {
            _usedFunds = _witnetUpgradeReward(_data.witnetQueryId);
        }
        if (_usedFunds < msg.value) {
            payable(msg.sender).transfer(msg.value - _usedFunds);
        }
    }

    /// @notice Returns SLA parameters that are being used every time there's a new randomness request.
    function witnetRandomnessSLA()
        virtual override
        external view
        returns (Witnet.RadonSLA memory)
    {
        return witnet().registry().lookupRadonSLA(__witnetRandomnessSlaHash);
    }


    // ================================================================================================================
    // --- 'Upgradeable' extension ------------------------------------------------------------------------------------

    /// Initialize storage-context when invoked as delegatecall. 
    /// @dev Must fail when trying to initialize same instance more than once.
    function initialize(bytes memory) 
        public
        virtual override
        onlyDelegateCalls // => we don't want the logic base contract to be ever initialized
    {
        if (
            __proxiable().proxy == address(0)
                && __proxiable().implementation == address(0)
        ) {
            // a proxy is being initilized for the first time ...
            __proxiable().proxy = address(this);
            _transferOwnership(msg.sender);
            __initializeWitnetRandomnessSlaHash();
        }
        else if (__proxiable().implementation == base()) {
            revert("WitnetRandomnessProxiable: not upgradeable");
        }
        __proxiable().implementation = base();
    }

    /// Tells whether provided address could eventually upgrade the contract.
    function isUpgradableFrom(address) external pure override returns (bool) {
        return false;
    }


    // ================================================================================================================
    // --- 'Clonable' extension ---------------------------------------------------------------------------------------

    /// @notice Tells whether this instance has been initialized.
    function initialized()
        override
        public view
        returns (bool)
    {
        return address(witnetRandomnessRequest) != address(0);
    }


    // ================================================================================================================
    // --- INTERNAL FUNCTIONS -----------------------------------------------------------------------------------------

    /// @dev Common steps for both deterministic and non-deterministic cloning.
    function _afterClone(address _instance)
        virtual internal
        returns (WitnetRandomness)
    {
        WitnetRandomnessProxiable(_instance).initializeClone(hex"");
        return WitnetRandomness(_instance);
    }

    /// @notice Re-initialize contract's storage context upon a new upgrade from a proxy.    
    /// @dev Must fail when trying to upgrade to same logic contract more than once.
    function _initialize(bytes memory)
        virtual internal
    {
        // settle ownership:
        _transferOwnership(msg.sender);
        // initialize default Witnet SLA parameters used for every randomness request;
        __initializeWitnetRandomnessSlaHash();
        // make sure that this clone cannot ever get initialized as a proxy:
        __proxiable().implementation = base();
    }

    function __initializeWitnetRandomnessSlaHash() virtual internal {
        settleWitnetRandomnessSLA(Witnet.RadonSLA({
            numWitnesses: 5,
            minConsensusPercentage: 51,
            witnessReward: 2 * 10 ** 8,      // 0.2 WIT
            witnessCollateral: 2 * 10 ** 10, // 20 WIT
            minerCommitRevealFee: 10 ** 7    // 0.01 WIT
        }));
    }

    /// @dev Returns index of the Most Significant Bit of the given number, applying De Bruijn O(1) algorithm.
    function _msbDeBruijn32(uint32 _v)
        internal pure
        returns (uint8)
    {
        uint8[32] memory _bitPosition = [
                0, 9, 1, 10, 13, 21, 2, 29,
                11, 14, 16, 18, 22, 25, 3, 30,
                8, 12, 20, 28, 15, 17, 24, 7,
                19, 27, 23, 6, 26, 5, 4, 31
            ];
        _v |= _v >> 1;
        _v |= _v >> 2;
        _v |= _v >> 4;
        _v |= _v >> 8;
        _v |= _v >> 16;
        return _bitPosition[
            uint32(_v * uint256(0x07c4acdd)) >> 27
        ];
    }

    /// @dev Recursively searches for the number of the first block after the given one in which a Witnet randomization request was posted.
    /// @dev Returns 0 if none found.
    function _searchNextBlock(uint256 _target, uint256 _latest) internal view returns (uint256) {
        return ((_target >= _latest) 
            ? __randomize_[_latest].nextBlock
            : _searchNextBlock(_target, __randomize_[_latest].prevBlock)
        );
    }

    /// @dev Recursively searches for the number of the first block before the given one in which a Witnet randomization request was posted.
    /// @dev Returns 0 if none found.

    function _searchPrevBlock(uint256 _target, uint256 _latest) internal view returns (uint256) {
        return ((_target > _latest)
            ? _latest
            : _searchPrevBlock(_target, __randomize_[_latest].prevBlock)
        );
    }

}
