const utils = require("../src/utils")
const { expectEvent, expectRevert } = require("@openzeppelin/test-helpers")
const { assert } = require("chai")
const { expectRevertCustomError } = require("custom-error-test-helper")

const WitnetRadonRegistry = artifacts.require("WitnetRadonRegistryDefault")
const WitnetEncodingLib = artifacts.require("WitnetEncodingLib")
const Witnet = artifacts.require("Witnet")

contract("WitnetRadonRegistry", (accounts) => {
  const creatorAddress = accounts[0]
  const firstOwnerAddress = accounts[1]
  const unprivilegedAddress = accounts[4]

  let bytecodes

  before(async () => {
    await WitnetRadonRegistry.link(WitnetEncodingLib, WitnetEncodingLib.address)
    bytecodes = await WitnetRadonRegistry.new(
      true,
      utils.fromAscii("testing")
    )
  })

  beforeEach(async () => {
    /* before each context */
  })

  context("Ownable2Step", async () => {
    it("should revert if transferring ownership from stranger", async () => {
      await expectRevert(
        bytecodes.transferOwnership(unprivilegedAddress, { from: unprivilegedAddress }),
        "not the owner"
      )
    })
    it("owner can start transferring ownership", async () => {
      const tx = await bytecodes.transferOwnership(firstOwnerAddress, { from: creatorAddress })
      expectEvent(
        tx.receipt,
        "OwnershipTransferStarted",
        { newOwner: firstOwnerAddress }
      )
    })
    it("stranger cannot accept transferring ownership", async () => {
      await expectRevert(
        bytecodes.acceptOwnership({ from: unprivilegedAddress }),
        "not the new owner"
      )
    })
    it("ownership is fully transferred upon acceptance", async () => {
      const tx = await bytecodes.acceptOwnership({ from: firstOwnerAddress })
      expectEvent(
        tx.receipt,
        "OwnershipTransferred",
        {
          previousOwner: creatorAddress,
          newOwner: firstOwnerAddress,
        }
      )
      assert.equal(firstOwnerAddress, await bytecodes.owner())
    })
  })

  context("Upgradeable", async () => {
    it("should manifest to be upgradable from actual owner", async () => {
      assert.equal(
        await bytecodes.isUpgradableFrom(firstOwnerAddress),
        true
      )
    })
    it("should manifest to not be upgradable from anybody else", async () => {
      assert.equal(
        await bytecodes.isUpgradableFrom(unprivilegedAddress),
        false
      )
    })
    it("cannot be initialized more than once", async () => {
      await expectRevertCustomError(
        WitnetRadonRegistry,
        bytecodes.initialize("0x", { from: firstOwnerAddress }),
        "AlreadyUpgraded"
      )
      await expectRevertCustomError(
        WitnetRadonRegistry,
        bytecodes.initialize("0x", { from: unprivilegedAddress }),
        "OnlyOwner"
      )
    })
  })

  context("IWitnetRadonRegistry", async () => {
    let slaHash

    let concathashReducerHash
    let modeNoFiltersReducerHash
    let stdev15ReducerHash
    let stdev25ReducerHash

    let rngSourceHash
    let binanceTickerHash
    let uniswapToken1PriceHash
    let heavyRetrievalHash

    let rngHash

    let btcUsdPriceFeedHash

    context("verifyRadonRetrieval(..)", async () => {
      context("Witnet.RadonRetrievalMethods.RNG", async () => {
        it("emits appropiate single event when verifying randomness data source for the first time", async () => {
          const tx = await bytecodes.verifyRadonRetrieval(
            2, // requestMethod
            "", // requestSchema
            "", // requestFQDN
            "", // requestPath
            "", // requestQuery
            "", // requestBody
            [], // requestHeaders
            "0x80", // requestRadonScript
          )
          expectEvent(
            tx.receipt,
            "NewRadonRetrievalHash"
          )
          rngSourceHash = tx.logs[0].args.hash
        })
        it("emits no event when verifying already existing randomness data source", async () => {
          const tx = await bytecodes.verifyRadonRetrieval(
            2, // requestMethod
            "", // requestSchema
            "", // requestFQDN
            "", // requestPath
            "", // requestQuery
            "", // requestBody
            [], // requestHeaders
            "0x80", // requestRadonScript
          )
          assert.equal(tx.logs.length, 0, "some unexpected event was emitted")
        })
        it("generates proper hash upon offchain verification of already existing randmoness source", async () => {
          const hash = await bytecodes.verifyRadonRetrieval.call(
            2, // requestMethod
            "", // requestSchema
            "", // requestFQDN
            "", // requestPath
            "", // requestQuery
            "", // requestBody
            [], // requestHeaders
            "0x80", // requestRadonScript
          )
          assert.equal(hash, rngSourceHash)
        })
        // ... reverts
      })
      context("Witnet.RadonRetrievalMethods.HttpGet", async () => {
        it(
          "emits new data provider and source events when verifying a new http-get source for the first time", async () => {
            const tx = await bytecodes.verifyRadonRetrieval(
              1, // requestMethod
              "HTTPs://", // requestSchema
              "api.binance.US", // requestFQDN
              "api/v3/ticker/price", // requestPath
              "symbol=\\0\\\\1\\", // requestQuery
              "", // requestBody
              [], // requestHeaders
              "0x841877821864696c61737450726963658218571a000f4240185b", // requestRadonScript
            )
            expectEvent(
              tx.receipt,
              "NewDataProvider"
            )
            assert.equal(tx.logs[0].args.index, 1)
            expectEvent(
              tx.receipt,
              "NewRadonRetrievalHash"
            )
            binanceTickerHash = tx.logs[1].args.hash
          })
        it("data source metadata gets stored as expected", async () => {
          const ds = await bytecodes.lookupRadonRetrieval(binanceTickerHash)
          assert.equal(ds.method, 1) // HTTP-GET
          assert.equal(ds.resultDataType, 4) // Integer
          assert.equal(ds.url, "https://api.binance.us/api/v3/ticker/price?symbol=\\0\\\\1\\")
          assert.equal(ds.body, "")
          assert(ds.headers.length === 0)
          assert.equal(ds.script, "0x841877821864696c61737450726963658218571a000f4240185b")
        })
        it("emits one single event when verifying new http-get endpoint to already existing provider", async () => {
          const tx = await bytecodes.verifyRadonRetrieval(
            1, // requestMethod
            "http://", // requestSchema
            "api.binance.us", // requestFQDN
            "api/v3/ticker/24hr", // requestPath
            "symbol=\\0\\\\1\\", // requestQuery
            "", // requestBody
            [], // requestHeaders
            "0x841877821864696c61737450726963658218571a000f4240185b", // requestRadonScript
          )
          assert.equal(tx.logs.length, 1)
          expectEvent(
            tx.receipt,
            "NewRadonRetrievalHash"
          )
        })
      })
      context("Witnet.RadonRetrievalMethods.HttpPost", async () => {
        it(
          "emits new data provider and source events when verifying a new http-post source for the first time", async () => {
            const tx = await bytecodes.verifyRadonRetrieval(
              3, // requestMethod
              "HTTPs://", // requestSchema
              "api.thegraph.com", // requestFQDN
              "subgraphs/name/uniswap/uniswap-v3", // requestPath
              "", // requestQuery
              "{\"query\":\"{pool(id:\"\\0\\\"){token1Price}}\"}", // requestBody
              [
                ["user-agent", "witnet-rust"],
                ["content-type", "text/html; charset=utf-8"],
              ], // requestHeaders
              "0x861877821866646461746182186664706f6f6c8218646b746f6b656e3150726963658218571a000f4240185b", // requestRadonScript
            )
            expectEvent(
              tx.receipt,
              "NewDataProvider"
            )
            assert.equal(tx.logs[0].args.index, 2)
            expectEvent(
              tx.receipt,
              "NewRadonRetrievalHash"
            )
            uniswapToken1PriceHash = tx.logs[1].args.hash
          })
        it("data source metadata gets stored as expected", async () => {
          const ds = await bytecodes.lookupRadonRetrieval(uniswapToken1PriceHash)
          assert.equal(ds.method, 3) // HTTP-GET
          assert.equal(ds.resultDataType, 4) // Integer
          assert.equal(ds.url, "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3")
          assert.equal(ds.body, "{\"query\":\"{pool(id:\"\\0\\\"){token1Price}}\"}")
          assert(ds.headers.length === 2)
          assert.equal(ds.headers[0][0], "user-agent")
          assert.equal(ds.headers[0][1], "witnet-rust")
          assert.equal(ds.headers[1][0], "content-type")
          assert.equal(ds.headers[1][1], "text/html; charset=utf-8")
          assert.equal(ds.script, "0x861877821866646461746182186664706f6f6c8218646b746f6b656e3150726963658218571a000f4240185b")
        })
      })
    })

    context("verifyRadonReducer(..)", async () => {
      it("emits event when verifying new radon reducer with no filter", async () => {
        const tx = await bytecodes.verifyRadonReducer([
          11, // opcode: ConcatenateAndHash
          [], // filters
          "0x", // script
        ])
        expectEvent(
          tx.receipt,
          "NewRadonReducerHash"
        )
        concathashReducerHash = tx.logs[0].args.hash
        // concathashReducerBytecode = tx.logs[0].args.bytecode
      })
      it("emits no event when verifying an already verified radon sla with no filter", async () => {
        const tx = await bytecodes.verifyRadonReducer([
          11, // ConcatenateAndHash
          [], // filters
          "0x", // script
        ])
        assert.equal(
          tx.logs.length,
          0,
          "some unexpected event was emitted"
        )
      })
      it("generates proper hash upon offchain call", async () => {
        const hash = await bytecodes.verifyRadonReducer.call([
          11, // ConcatenateAndHash
          [], // filters
          "0x", // script
        ])
        assert.equal(hash, concathashReducerHash)
      })
      it("reverts custom error if verifying radon reducer with unsupported opcode", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonReducer([
            0, // Minimum
            [], // filters
            "0x", // script
          ]),
          "UnsupportedRadonReducerOpcode"
        )
      })
      it("reverts custom error if verifying radon reducer with at least one unsupported filter", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonReducer([
            5, // AverageMedian
            [
              [8, "0x"], // Mode: supported
              [0, "0x"], // Greater than: not yet supported
            ],
            "0x", // script
          ]),
          "UnsupportedRadonFilterOpcode"
        )
      })
      it("reverts custom error if verifying radon reducer with stdev filter but no args", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonReducer([
            2, // Mode
            [
              [5, "0x"], // Standard deviation filter
            ],
            "0x", // script
          ]),
          "RadonFilterMissingArgs"
        )
      })
      it("verifying radon reducer with stdev filter and args works", async () => {
        let tx = await bytecodes.verifyRadonReducer([
          3, // AverageMean
          [
            [5, "0xF93E00"], // StdDev(1.5) filter
          ],
          "0x", // script
        ])
        expectEvent(
          tx.receipt,
          "NewRadonReducerHash"
        )
        stdev15ReducerHash = tx.logs[0].args.hash
        tx = await bytecodes.verifyRadonReducer([
          2, // Mode
          [
            [5, "0xF94100"], // StdDev(2.5) filter
          ],
          "0x", // script
        ])
        stdev25ReducerHash = tx.logs[0].args.hash
      })
    })

    context("verifyRadonRequest(..)", async () => {
      context("Use case: Randomness", async () => {
        it("emits single event when verifying new radomness request", async () => {
          let tx = await bytecodes.verifyRadonReducer([
            2, // Mode
            [], // no filters
            "0x", // script
          ])
          expectEvent(
            tx.receipt,
            "NewRadonReducerHash"
          )
          modeNoFiltersReducerHash = tx.logs[0].args.hash
          //   modeNoFiltersReducerBytecode = tx.logs[0].args.bytecode
          tx = await bytecodes.verifyRadonRequest(
            [ // sources
              rngSourceHash,
            ],
            modeNoFiltersReducerHash, // aggregator
            concathashReducerHash, // tally
            0, [[]], // sourcesArgs
          )
          assert(tx.logs.length === 1)
          expectEvent(
            tx.receipt,
            "NewRadHash"
          )
          rngHash = tx.logs[0].args.hash
        })
        it("emits no event when verifying same randomness request", async () => {
          const tx = await bytecodes.verifyRadonRequest(
            [ // sources
              rngSourceHash,
            ],
            modeNoFiltersReducerHash, // aggregator
            concathashReducerHash, // tally
            0, [[]], // sourcesArgs
          )
          assert(tx.logs.length === 0)
        })
        it("generates same hash when verifying same randomness request offchain", async () => {
          const hash = await bytecodes.verifyRadonRequest.call(
            [ // sources
              rngSourceHash,
            ],
            modeNoFiltersReducerHash, // aggregator
            concathashReducerHash, // tally
            0, // resultMaxVariableSize
            [[]], // sourcesArgs
          )
          assert.equal(hash, rngHash)
        })
      })
      context("Use case: Price feeds", async () => {
        it("reverts custom error if trying to verify request w/ templated source and 0 args out of 2", async () => {
          await expectRevert.unspecified(
            bytecodes.verifyRadonRequest(
              [ // sources
                binanceTickerHash,
              ],
              stdev15ReducerHash, // aggregator
              stdev25ReducerHash, // tally
              0, // resultMaxVariableSize
              [[]],
            )
          )
        })
        it("reverts custom error if trying to verify request w/ templated source and 1 args out of 2", async () => {
          await expectRevert.unspecified(
            bytecodes.verifyRadonRequest(
              [ // sources
                binanceTickerHash,
              ],
              stdev15ReducerHash, // aggregator
              stdev25ReducerHash, // tally
              0, // resultMaxVariableSize
              [ // sourcesArgs
                ["BTC"],
              ],
            )
          )
        })
        it("emits single event when verifying new price feed request for the first time", async () => {
          const tx = await bytecodes.verifyRadonRequest(
            [ // source
              binanceTickerHash,
            ],
            stdev15ReducerHash, // aggregator
            stdev25ReducerHash, // tally
            0, // resultMaxVariableSize,
            [
              ["BTC", "USD"], // binance ticker args
            ],
          )
          assert(tx.logs.length === 1)
          expectEvent(
            tx.receipt,
            "NewRadHash"
          )
          btcUsdPriceFeedHash = tx.logs[0].args.hash
          // btcUsdPriceFeedBytecode = tx.logs[0].args.bytecode
        })
        it("verifying radon request with repeated sources works", async () => {
          const tx = await bytecodes.verifyRadonRequest(
            [ // sources
              binanceTickerHash,
              binanceTickerHash,
            ],
            stdev15ReducerHash, // aggregator
            stdev25ReducerHash, // tally
            0, // resultMaxVariableSize,
            [
              ["BTC", "USD"], // binance ticker args
              ["BTC", "USD"], // binance ticker args
            ],
          )
          assert(tx.logs.length === 1)
          expectEvent(
            tx.receipt,
            "NewRadHash"
          )
        })
        it("reverts if trying to verify radon request w/ incompatible sources", async () => {
          await expectRevertCustomError(
            Witnet,
            bytecodes.verifyRadonRequest(
              [ // sources
                binanceTickerHash,
                rngSourceHash,
              ],
              stdev15ReducerHash, // aggregator
              stdev25ReducerHash, // tally
              0, // resultMaxVariableSize,
              [
                ["BTC", "USD"], // binance ticker args
                [],
              ],
            ),
            "RadonRequestResultsMismatch", [
              1, // index
              0, // read
              4, // expected
            ]
          )
        })
        it("emits single event when verifying new radon request w/ http-post source", async () => {
          const tx = await bytecodes.verifyRadonRequest(
            [ // sources
              uniswapToken1PriceHash,
            ],
            stdev15ReducerHash, // aggregator
            stdev25ReducerHash, // tally
            0, // resultMaxVariableSize,
            [
              ["0xc2a856c3aff2110c1171b8f942256d40e980c726"], // pair id
            ],
          )
          assert(tx.logs.length === 1)
          expectEvent(
            tx.receipt,
            "NewRadHash"
          )
        })
        it("emits single event when verifying new radon request w/ repeated http-post sources", async () => {
          const tx = await bytecodes.verifyRadonRequest(
            [ // sources
              uniswapToken1PriceHash,
              uniswapToken1PriceHash,
              uniswapToken1PriceHash,
              uniswapToken1PriceHash,
              uniswapToken1PriceHash,
              uniswapToken1PriceHash,
            ],
            stdev15ReducerHash, // aggregator
            stdev25ReducerHash, // tally
            0, // resultMaxVariableSize,
            [
              ["0xc2a856c3aff2110c1171b8f942256d40e980c726"], // pair id
              ["0xc2a856c3aff2110c1171b8f942256d40e980c726"], // pair id
              ["0xc2a856c3aff2110c1171b8f942256d40e980c726"], // pair id
              ["0xc2a856c3aff2110c1171b8f942256d40e980c726"], // pair id
              ["0xc2a856c3aff2110c1171b8f942256d40e980c726"], // pair id
              ["0xc2a856c3aff2110c1171b8f942256d40e980c726"], // pair id
            ],
          )
          assert(tx.logs.length === 1)
          expectEvent(
            tx.receipt,
            "NewRadHash"
          )
          heavyRetrievalHash = tx.logs[0].args.hash
        })
      })
    })

    context("verifyRadonSLA(..)", async () => {
      it("emits event when verifying new radon sla", async () => {
        const tx = await bytecodes.verifyRadonSLA([
          10,
          51,
          10 ** 9,
          5 * 10 ** 9,
          10 ** 6,
        ])
        expectEvent(
          tx.receipt,
          "NewSlaHash"
        )
        slaHash = tx.logs[0].args.hash
      })
      it("emits no event when verifying an already verified radon sla", async () => {
        const tx = await bytecodes.verifyRadonSLA([
          10,
          51,
          10 ** 9,
          5 * 10 ** 9,
          10 ** 6,
        ])
        assert.equal(
          tx.logs.length,
          0,
          "some unexpected event was emitted"
        )
      })
      it("generates proper hash upon offchain call", async () => {
        const hash = await bytecodes.verifyRadonSLA.call([
          10,
          51,
          10 ** 9,
          5 * 10 ** 9,
          10 ** 6,
        ])
        assert.equal(hash, slaHash)
      })
      it("reverts custom error if verifying radon sla with no reward", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonSLA([
            10,
            51,
            0,
            5 * 10 ** 9,
            10 ** 6,
          ]),
          "RadonSlaNoReward"
        )
      })
      it("reverts custom error if verifying radon sla with no witnesses", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonSLA([
            0,
            51,
            10 ** 9,
            5 * 10 ** 9,
            10 ** 6,
          ]),
          "RadonSlaNoWitnesses"
        )
      })
      it("reverts custom error if verifying radon sla with too many witnesses", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonSLA([
            500,
            51,
            10 ** 9,
            15 * 10 ** 9,
            10 ** 6,
          ]),
          "RadonSlaTooManyWitnesses"
        )
      })
      it("reverts custom error if verifying radon sla with quorum out of range", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonSLA([
            10,
            50,
            10 ** 9,
            15 * 10 ** 9,
            10 ** 6,
          ]),
          "RadonSlaConsensusOutOfRange"
        )
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonSLA([
            10,
            100,
            10 ** 9,
            5 * 10 ** 9,
            10 ** 6,
          ]),
          "RadonSlaConsensusOutOfRange"
        )
      })
      it("reverts custom error if verifying radon sla with too low collateral", async () => {
        await expectRevertCustomError(
          Witnet,
          bytecodes.verifyRadonSLA([
            10,
            51,
            10 ** 6,
            10 ** 6,
            10 ** 6,
          ]),
          "RadonSlaLowCollateral"
        )
      })
    })

    context("bytecodeOf(..)", async () => {
      context("radon requests", async () => {
        it("reverts if trying to get bytecode from unknown radon request", async () => {
          await expectRevertCustomError(
            WitnetRadonRegistry,
            bytecodes.bytecodeOf("0x0"),
            "UnknownRadonRequest"
          )
        })
        it("works if trying to get bytecode onchain from known radon request", async () => {
          await bytecodes.bytecodeOf(btcUsdPriceFeedHash)
        })
        it("returns bytecode if getting it offchain from known radon request", async () => {
          await bytecodes.bytecodeOf(btcUsdPriceFeedHash)
        })
      })
      context("radon slas", async () => {
        it("reverts if trying to get bytecode from unknown radon sla", async () => {
          await expectRevertCustomError(
            WitnetRadonRegistry,
            bytecodes.bytecodeOf(btcUsdPriceFeedHash, "0x0"),
            "UnknownRadonSLA"
          )
        })
        it("works if trying to get bytecode onchain from known radon request and sla", async () => {
          await bytecodes.bytecodeOf(btcUsdPriceFeedHash, slaHash)
        })
      })
    })

    context("hashOf(..)", async () => {
      it("hashing unknown radon request doesn't revert", async () => {
        await bytecodes.hashOf("0x", slaHash)
      })
      it("hashing unknown radon sla doesn't revert", async () => {
        await bytecodes.hashOf(btcUsdPriceFeedHash, "0x0")
      })
      it("hashing of known radon request and sla works", async () => {
        await bytecodes.hashOf(btcUsdPriceFeedHash, slaHash)
      })
    })

    context("hashWeightRewardOf(..)", async () => {
      it("hashing unknown radon request reverts", async () => {
        await expectRevertCustomError(
          WitnetRadonRegistry,
          bytecodes.hashWeightWitsOf("0x0", slaHash),
          "UnknownRadonRequest"
        )
      })
      it("hashing unknown radon sla reverts", async () => {
        await expectRevertCustomError(
          WitnetRadonRegistry,
          bytecodes.hashWeightWitsOf(btcUsdPriceFeedHash, "0x0"),
          "UnknownRadonSLA"
        )
      })
      it("hashing of known radon request and sla works", async () => {
        await bytecodes.hashWeightWitsOf(
          heavyRetrievalHash, slaHash
        )
      })
    })
  })
})
