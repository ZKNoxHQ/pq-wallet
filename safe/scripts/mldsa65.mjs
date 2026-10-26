#!/usr/bin/env node
// ML-DSA-65 key and signature helper for the Forge tests (vm.ffi), on top of
// js/mldsa65.js of ETHDILITHIUM. Everything is derived from a 32-byte seed, so
// a holder is one seed and the tests stay deterministic.
//
//   node scripts/mldsa65.mjs key  <seedHex32>            -> expanded public key (38,112 bytes)
//   node scripts/mldsa65.mjs sign <seedHex32> <hash32Hex> -> signature (3,309 bytes)
//
// The signature is the one ISigVerifier.verify(pk, bytes32, sig) checks: the
// 32-byte hash as the message, empty context.
import { keygen, sign, expandPublicKey65, encodePublicKey65, hexToBytes, bytesToHex }
  from '../../lib/ETHDILITHIUM/js/mldsa65.js';

const [cmd, ...args] = process.argv.slice(2);
const seed = hexToBytes(args[0]);
if (seed.length !== 32) throw new Error('seed must be 32 bytes');
const { publicKey, secretKey } = keygen(seed);

switch (cmd) {
  case 'key':
    process.stdout.write(encodePublicKey65(expandPublicKey65(publicKey)));
    break;
  case 'sign': {
    const hash = hexToBytes(args[1]);
    if (hash.length !== 32) throw new Error('hash must be 32 bytes');
    process.stdout.write(bytesToHex(sign(hash, secretKey, { deterministic: true })));
    break;
  }
  default:
    throw new Error(`unknown command ${cmd}`);
}
