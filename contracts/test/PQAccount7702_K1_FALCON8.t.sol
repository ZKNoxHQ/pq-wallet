// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {PythonSigner as FalconSigner} from "ETHFALCON/src/ZKNOX_PythonSigner.sol";
import {_packUint256Array, _packSignature} from "ETHFALCON/src/ZKNOX_common.sol";
import {ZKNOX_falcon8_verifier} from "../src/ZKNOX_falcon8_verifier.sol";
import {PQAccountScenarios} from "./PQAccountScenarios.sol";
import {PQPairScenarios} from "./PQPairScenarios.sol";

/// ECDSA secp256k1 + Falcon-512 NIST (ZKNOX_falcon8, ETHFALCON exp/pq-verifier-gas).
contract PQAccount7702_K1_FALCON8 is PQAccountScenarios, PQPairScenarios {
    string constant PY = "../lib/ETHFALCON/pythonref";
    string constant SEED = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";
    FalconSigner signer = new FalconSigner();

    function _deployPQVerifier() internal override returns (ISigVerifier) {
        return new ZKNOX_falcon8_verifier(f1600ZknoxHelper);
    }

    function _rawPostQuantumKey() internal override returns (bytes memory) {
        (uint256[32] memory pk,,) = signer.sign(PY, "0xabcd", "NIST", SEED);
        return _packUint256Array(pk);
    }

    /// ZKNOX_falcon8_verifier still writes the key to SSTORE2 and returns the pointer
    function _normalizedPostQuantumKey() internal view override returns (bytes memory) {
        return _lastSstore2Pointer();
    }

    function _signPostQuantum(bytes32 digest) internal override returns (bytes memory) {
        (, bytes memory salt, uint256[32] memory s2) = signer.sign(PY, _bytes32ToHex(digest), "NIST", SEED);
        return _packSignature(salt, s2);
    }
}
