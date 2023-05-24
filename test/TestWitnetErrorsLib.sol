// SPDX-License-Identifier: MIT

pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import "truffle/Assert.sol";
import "../contracts/libs/WitnetErrorsLib.sol";

contract TestWitnetErrorsLib {

  using Witnet for Witnet.Result;

  event Log(bytes data, uint256 length);
  event Error(Witnet.ResultError log);

  // Test decoding of `RadonError` error codes
  function testErrorCodes1() external {
    Witnet.ResultError memory errorEmpty = WitnetErrorsLib.resultErrorFromCborBytes(hex"D82780");
    Witnet.ResultError memory error0x00 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278100");
    Witnet.ResultError memory error0x01 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278101");
    Witnet.ResultError memory error0x02 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278102");
    Witnet.ResultError memory error0x03 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278103");
    Witnet.ResultError memory error0x10 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278110");
    Witnet.ResultError memory error0x11 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278111");
    Witnet.ResultError memory error0x20 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811820");
    Witnet.ResultError memory error0x30 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811830");
    Witnet.ResultError memory error0x31 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811831");
    Witnet.ResultError memory error0x40 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811840");
    Witnet.ResultError memory error0x41 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811841");
    Witnet.ResultError memory error0x42  = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811842");
    Assert.equal(
      uint(errorEmpty.code),
      uint(Witnet.ResultErrorCodes.Unknown),
      "empty error code `[]` should be `Witnet.ResultErrorCodes.Unknown`"
    );
    Assert.equal(
      uint(error0x00.code),
      uint(Witnet.ResultErrorCodes.Unknown),
      "error code `0x00` should be `Witnet.ResultErrorCodes.Unknown`"
    );
    Assert.equal(
      uint(error0x01.code),
      uint(Witnet.ResultErrorCodes.SourceScriptNotCBOR),
      "error code `0x01` should be `Witnet.ResultErrorCodes.SourceScriptNotCBOR`"
    );
    Assert.equal(
      uint(error0x02.code),
      uint(Witnet.ResultErrorCodes.SourceScriptNotArray),
      "error code `0x02` should be `Witnet.ResultErrorCodes.SourceScriptNotArray`"
    );
    Assert.equal(
      uint(error0x03.code),
      uint(Witnet.ResultErrorCodes.SourceScriptNotRADON),
      "error code `0x03` should be `Witnet.ResultErrorCodes.SourceScriptNotRADON`"
    );
    Assert.equal(
      uint(error0x10.code),
      uint(Witnet.ResultErrorCodes.RequestTooManySources),
      "error code `0x10` should be `Witnet.ResultErrorCodes.RequestTooManySources`"
    );
    Assert.equal(
      uint(error0x11.code),
      uint(Witnet.ResultErrorCodes.ScriptTooManyCalls),
      "error code `0x11` should be `Witnet.ResultErrorCodes.ScriptTooManyCalls`"
    );
    Assert.equal(
      uint(error0x20.code),
      uint(Witnet.ResultErrorCodes.UnsupportedOperator),
      "error code `0x20` should be `Witnet.ResultErrorCodes.UnsupportedOperator`"
    );
    Assert.equal(
      uint(error0x30.code),
      uint(Witnet.ResultErrorCodes.HTTP),
      "error code `0x30` should be `Witnet.ResultErrorCodes.HTTP`"
    );
    Assert.equal(
      uint(error0x31.code),
      uint(Witnet.ResultErrorCodes.RetrievalTimeout),
      "Error code 0x31 should be `Witnet.ResultErrorCodes.RetrievalTimeout`"
    );
    Assert.equal(
      uint(error0x40.code),
      uint(Witnet.ResultErrorCodes.Underflow),
      "error code `0x40` should be `Witnet.ResultErrorCodes.Underflow`"
    );
    Assert.equal(
      uint(error0x41.code),
      uint(Witnet.ResultErrorCodes.Overflow),
      "error code `0x41` should be `Witnet.ResultErrorCodes.Overflow`"
    );
    Assert.equal(
      uint(error0x42.code),
      uint(Witnet.ResultErrorCodes.DivisionByZero),
      "Error code #0x42 should be `Witnet.ResultErrorCodes.DivisionByZero`"
    );
  }

  function testErrorCodes2() external {
    Witnet.ResultError memory error0x50 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811850");
    Witnet.ResultError memory error0x51 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811851");
    Witnet.ResultError memory error0x52 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811852");
    Witnet.ResultError memory error0x53 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811853");
    Witnet.ResultError memory error0x60 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811860");
    Witnet.ResultError memory error0x70 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811870");
    Witnet.ResultError memory error0x71 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827811871");
    Witnet.ResultError memory error0xe0 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278118E0");
    Witnet.ResultError memory error0xe1 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278118E1");
    Witnet.ResultError memory error0xe2 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278118E2");
    Witnet.ResultError memory error0xff = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278118FF");
    Assert.equal(
      uint(error0x50.code),
      uint(Witnet.ResultErrorCodes.NoReveals),
      "Error code #0x50 should be `Witnet.ResultErrorCodes.NoReveals`"
    );
    Assert.equal(
      uint(error0x51.code),
      uint(Witnet.ResultErrorCodes.InsufficientConsensus),
      "Error code #0x51 should be `Witnet.ResultErrorCodes.InsufficientConsensus`"
    );
    Assert.equal(
      uint(error0x52.code),
      uint(Witnet.ResultErrorCodes.InsufficientCommits),
      "Error code #0x52 should be `Witnet.ResultErrorCodes.InsufficientCommits`"
    );
    Assert.equal(
      uint(error0x53.code),
      uint(Witnet.ResultErrorCodes.TallyExecution),
      "Error code #0x53 should be `Witnet.ResultErrorCodes.TallyExecution`"
    );
    Assert.equal(
      uint(error0x60.code),
      uint(Witnet.ResultErrorCodes.MalformedReveal),
      "Error code #0x60 should be `Witnet.ResultErrorCodes.MalformedReveal`"
    );
    Assert.equal(
      uint(error0x70.code),
      uint(Witnet.ResultErrorCodes.ArrayIndexOutOfBounds),
      "Error code #0x70 should be `Witnet.ResultErrorCodes.ArrayIndexOutOfBounds`"
    );
    Assert.equal(
      uint(error0x71.code),
      uint(Witnet.ResultErrorCodes.MapKeyNotFound),
      "Error code #0x71 should be `Witnet.ResultErrorCodes.MapKeyNotFound`"
    );
    Assert.equal(
      uint(error0xe0.code),
      uint(Witnet.ResultErrorCodes.BridgeMalformedRequest),
      "Error code #0xE0 should be `Witnet.ResultErrorCodes.BridgeMalformedRequest`"
    );
    Assert.equal(
      uint(error0xe1.code),
      uint(Witnet.ResultErrorCodes.BridgePoorIncentives),
      "Error code #0xE1 should be `Witnet.ResultErrorCodes.BridgePoorIncentives`"
    );
    Assert.equal(
      uint(error0xe2.code),
      uint(Witnet.ResultErrorCodes.BridgeOversizedResult),
      "Error code #0xE2 should be `Witnet.ResultErrorCodes.BridgeOversizedResult`"
    );
    Assert.equal(
      uint(error0xff.code),
      uint(Witnet.ResultErrorCodes.UnhandledIntercept),
      "Error code #0xFF should be `Witnet.ResultErrorCodes.UnhandledIntercept`"
    );
  }

  // Test decoding of `RadonError` error messages
  function testErrorMessages() external {
    Witnet.ResultError memory errorEmpty = WitnetErrorsLib.resultErrorFromCborBytes(hex"D82780");
    Witnet.ResultError memory error0x00 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278100");
    Witnet.ResultError memory error0x01 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827820102");
    Witnet.ResultError memory error0x02 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827820203");
    Witnet.ResultError memory error0x03 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827820304");
    Witnet.ResultError memory error0x10 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827821005");
    Witnet.ResultError memory error0x11 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278411000708");
    Witnet.ResultError memory error0x20 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278518200108090A");
    Witnet.ResultError memory error0x30 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D82783183008190141");
    Witnet.ResultError memory error0x31 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D82782183109");
    Witnet.ResultError memory error0x40 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D82785184002090A0B");
    Witnet.ResultError memory error0x41 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827851841000A0B0C");
    Witnet.ResultError memory error0x42 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D827851842010B0C0D");
    Assert.equal(
      errorEmpty.reason,
      "Unknown error: no error code was found.",
      "Empty error message `[]` should be properly formatted"
    );
    Assert.equal(
      error0x00.reason,
      "Unhandled error: 0x00.",
      "Error message 0x00 should be properly formatted"
    );
    Assert.equal(
      error0x01.reason,
      "Witnet: Radon: Script #2: invalid CBOR value.",
      "Error message for error code `0x01` (`Witnet.ResultErrorCodes.SourceScriptNotCBOR`) should be properly formatted"
    );
    Assert.equal(
      error0x02.reason,
      "Witnet: Radon: Script #3: CBOR value expected to be an array of calls.",
      "Error message for error code `0x02` (`Witnet.ResultErrorCodes.SourceScriptNotArray`) should be properly formatted"
    );
    Assert.equal(
      error0x03.reason,
      "Witnet: Radon: Script #4: CBOR value expected to be a data request.",
      "Error message for error code `0x03` (`Witnet.ResultErrorCodes.SourceScriptNotRADON`) should be properly formatted"
    );
    Assert.equal(
      error0x10.reason,
      "Witnet: Radon: too many sources (5).",
      "Error message for error code `0x10` (`Witnet.ResultErrorCodes.RequestTooManySources`) should be properly formatted"
    );
    Assert.equal(
      error0x11.reason,
      "Witnet: Retrieval: Script #7: too many calls (8).",
      "Error message for error code `0x11` (`Witnet.ResultErrorCodes.ScriptTooManyCalls`) should be properly formatted"
    );
    Assert.equal(
      error0x20.reason,
      "Witnet: Aggregation: Script #8: Step #9: unsupported opcode (0x0A).",
      "Error message for error code `0x20` (`Witnet.ResultErrorCodes.UnsupportedOperator`) should be properly formatted"
    );
    Assert.equal(
      error0x30.reason,
      "Witnet: Retrieval: Source #8: HTTP/321 error.",
      "Error message for error code `0x30` (`Witnet.ResultErrorCodes.HTTP`) should be properly formatted"
    );
    Assert.equal(
      error0x31.reason,
      "Witnet: Retrieval: Source #9: timeout.",
      "Error message for error code `0x31` (`Witnet.ResultErrorCodes.RetrievalTimeout`) should be properly formatted"
    );
    Assert.equal(
      error0x40.reason,
      "Witnet: Tally: Script #9: Step #10: math underflow (0x0B).",
      "Error message for error code `0x40` (`Witnet.ResultErrorCodes.Underflow`) should be properly formatted"
    );
    Assert.equal(
      error0x41.reason,
      "Witnet: Retrieval: Script #10: Step #11: math overflow (0x0C).",
      "Error message for error code `0x41` (`Witnet.ResultErrorCodes.Overflow`) should be properly formatted"
    );
    Assert.equal(
      error0x42.reason,
      "Witnet: Aggregation: Script #11: Step #12: division by zero (0x0D).",
      "Error message for error code `0x42` (`Witnet.ResultErrorCodes.DivisionByZero`) should be properly formatted"
    );
  }

  function testBridgeErrorMessages() external { 
    Witnet.ResultError memory error0xe0 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278118E0");
    Witnet.ResultError memory error0xe1 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278118E1");
    Witnet.ResultError memory error0xe2 = WitnetErrorsLib.resultErrorFromCborBytes(hex"D8278118E2");  

    Assert.equal(
      error0xe0.reason,
      "Witnet: Bridge: malformed data request cannot be processed.",
      "Error message failed (0xE0)"
    );
    Assert.equal(
      error0xe1.reason,
      "Witnet: Bridge: rejected due to poor witnessing incentives.",
      "Error message failed (0xE1)"
    );
    Assert.equal(
      error0xe2.reason,
      "Witnet: Bridge: rejected due to poor bridging incentives.",
      "Error message failed (0xE2)"
    );
  }

}
