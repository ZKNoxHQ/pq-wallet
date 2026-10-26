// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {PythonSigner as DilithiumSigner} from "ETHDILITHIUM/src/ZKNOX_PythonSigner.sol";
import {Vm} from "forge-std/Test.sol";
import {ZKNOX_dilithium} from "ETHDILITHIUM/src/ZKNOX_dilithium.sol";
import {PQAccountScenarios} from "./PQAccountScenarios.sol";
import {PQPairScenarios} from "./PQPairScenarios.sol";

/// ECDSA secp256k1 + ML-DSA-44 NIST (ZKNOX_dilithium packed, ETHDILITHIUM exp/packed-verifier).
contract PQAccount7702_K1_MLDSA_packed is PQAccountScenarios, PQPairScenarios {
    string constant PY = "../lib/ETHDILITHIUM/pythonref";
    string constant SEED = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";
    DilithiumSigner signer = new DilithiumSigner();

    function _deployPQVerifier() internal override returns (ISigVerifier) {
        return new ZKNOX_dilithium(f1600Helper);
    }

    /// The flat 21,216-byte key ZKNOX_dilithium reads in place (ETHDILITHIUM ADR-010). Its
    /// PythonSigner.getPubKey passes an empty third argument, which the generator now rejects, so the
    /// format is given here.
    function _rawPostQuantumKey() internal override returns (bytes memory) {
        string[] memory cmds = new string[](5);
        cmds[0] = string.concat(PY, "/myenv/bin/python");
        cmds[1] = string.concat(PY, "/prepare_pk_for_deployment.py");
        cmds[2] = "NIST";
        cmds[3] = SEED;
        cmds[4] = "flat";
        return vm.ffi(cmds);
    }

    function _signPostQuantum(bytes32 digest) internal override returns (bytes memory) {
        (bytes memory cTilde, bytes memory z, bytes memory h) = signer.sign(PY, _bytes32ToHex(digest), "NIST", SEED);
        return abi.encodePacked(cTilde, z, h);
    }
}
