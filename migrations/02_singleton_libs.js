const ethUtils = require('ethereumjs-util')
const fs = require('fs')
const utils = require('../utils')

const SingletonFactory = artifacts.require("SingletonFactory")

module.exports = async function (deployer, network, accounts) {
  let addresses = require('./addresses.json')
  const singletons = require('./singletons.json') 

  const from = singletons.from || deployer.networks[network].from || acounts[0]
      
  // Generate SingletonFactory deployment transaction:
  const res = utils.generateDeployTx(
      SingletonFactory.toJSON(),
      singletons.sender.r,
      singletons.sender.s,
      singletons.sender.gasprice,
      singletons.sender.gas
    )

  const deployedCode = await web3.eth.getCode(res.contractAddr)

  if (deployedCode.length <= 3) {
    // Deploy SingletonFactory instance, if not yet deployed on this `network`:
    traceHeader(`Inception of 'SingletonFactory':`)

    const balance = await web3.eth.getBalance(from)
    const estimatedGas = res.gasLimit
    const value = estimatedGas * res.gasPrice
    let makerBalance = await web3.eth.getBalance(res.sender)

    if (makerBalance < value) {
      // transfer ETH funds to sender address, if currently not enough:
      await web3.eth.sendTransaction({
          from: from,
          to: res.sender,
          value: value - makerBalance
        })
      makerBalance = await web3.eth.getBalance(res.sender)
    }

    const tx = await web3.eth.sendSignedTransaction(res.rawTx)
    traceDeploymentTx(tx, web3.utils.fromWei((balance - await web3.eth.getBalance(from)).toString()))
  } else {
    traceHeader(`Singleton factory: 'SingletonFactory`)
  }

  // Set SingletonFactory address on current network:
  SingletonFactory.address = res.contractAddr;
  const factory = await SingletonFactory.deployed()

  // Trace factory relevant data:
  console.log("  ", "> sender's balance:\t", `${web3.utils.fromWei((await web3.eth.getBalance(res.sender)).toString(),'ether')} ETH`)
  console.log("  ", "> factory codehash:\t", web3.utils.soliditySha3(await web3.eth.getCode(res.contractAddr)))
  console.log("  ", "> factory sender:\t", res.sender)
  console.log("  ", "> factory address:\t", factory.address)
  console.log("  ", "> factory nonce:\t", await web3.eth.getTransactionCount(factory.address))
  console.log("")

  // Process all singleton libraries referred in config file:
  for (const lib in singletons.libs) {
  
    const artifact = artifacts.require(lib)
    const salt = singletons.libs[lib].salt  
        ? '0x' + ethUtils.setLengthLeft(ethUtils.toBuffer(singletons.libs[lib].salt), 32).toString('hex')
        : '0x0'
      ;

    let bytecode = artifact.toJSON().bytecode
    if (singletons.libs[lib].links) {
      singletons.libs[lib].links.forEach(
        // Join dependent library address(es) into the library bytecode to be deployed:
        // Please note: dependent libraries should have been previously deployed, 
        //   so order in which libraries are declared in the config file actually matters.
        sublib => {
          const sublib_artifact = artifacts.require(sublib)
          const sublib_addr = sublib_artifact.address.slice(2).toLowerCase()
          const sublib_mark = `__${sublib_artifact.contractName}${'_'.repeat(38 - sublib_artifact.contractName.length)}`
          bytecode = bytecode.split(sublib_mark).join(sublib_addr)
        }
      )
    }
    artifact.bytecode = bytecode

    var lib_addr = await factory.determineAddr.call(bytecode, salt)

    if ((await web3.eth.getCode(lib_addr)).length <= 3) {
      // Deploy library instance, if not yet deployed on this `network`:
      traceHeader(`Singleton inception of library '${lib}':`)

      const balance = await web3.eth.getBalance(from)
      const gas = singletons.libs[lib].gas || 10 ** 6
      const tx = await factory.deploy(bytecode, salt, {from: from, gas: gas})
      traceDeploymentTx(tx.receipt, web3.utils.fromWei((balance - await web3.eth.getBalance(from)).toString()))
    } else {
      traceHeader(`Singleton library: '${lib}'`)
    }

    artifact.address = lib_addr

    const lib_codehash = web3.utils.soliditySha3(await web3.eth.getCode(artifact.address))
    if (!lib_codehash) {
      throw new Error(`Fatal: unable to deploy library '${lib}' as singleton. Try providing more gas.`)
    }

    console.log("  ", "> library codehash:\t", lib_codehash)
    console.log("  ", "> library address:\t", artifact.address)
    console.log()

    addresses["singletons"]["libraries"][lib] = lib_addr
  }

  fs.writeFileSync("./migrations/addresses.json", JSON.stringify(addresses, null, 2))
}

function traceHeader(header) {
  console.log("")
  console.log("  ", header)
  console.log("  ", `${'-'.repeat(header.length)}`)
}

function traceDeploymentTx(receipt, total_cost) {
  console.log("  ", "> transaction hash:\t", receipt.transactionHash)
  console.log("  ", "> block number:\t", receipt.blockNumber)
  console.log("  ", "> gas used:\t\t", receipt.cumulativeGasUsed)
  if (total_cost) {
    console.log("  ", "> total cost:\t", total_cost, "ETH")
  }
  console.log()
}