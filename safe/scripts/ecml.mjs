#!/usr/bin/env node
// Talks to a Ledger running ECML-Signer and produces exactly what the rest of this repository needs.
//
//   node scripts/ecml.mjs key  --path "m/44'/60'/0'/0'/0'" --out keys/holder-1.hex
//   node scripts/ecml.mjs sign --path "m/44'/60'/0'/0'/0'" --digest 0x… --out answers/holder-1.json
//
// `key` is the setup step: it reports the secp256k1 address and writes the 38,112-byte expanded ML-DSA-65
// key, which `script/CreatePqOwner.s.sol` turns into an on-chain owner. `sign` is the per-transaction step:
// it hands the device one digest and returns the four values the front's paste form takes.
//
// Three things about this app that the code below has to respect (ecml-signer v2.4.0, CLA 0xE0):
//
//   - HYBRID_SIGN_HASH (0x16) returns ONLY the secp256k1 half inline, DER encoded, with `v` as a parity
//     bit. The ML-DSA key and signature stay in device RAM and come back through GET_PK_CHUNK (0x13) and
//     GET_SIG_CHUNK (0x12), 255 bytes at a time;
//   - GET_PUBLIC_KEY (0x05) and KEYGEN_DILITHIUM (0x11) share a union with that RAM and wipe it. Nothing
//     may be interleaved between 0x16 and the chunk reads;
//   - 0x16 is blind signing, which is off when the app is installed. Enable it in the app's Settings on
//     the device, or every call answers 0xB00A.
//
// The device path is the part of this repository that no test covers: there is no hardware in CI. What is
// testable — the DER conversion, the address derivation, the key expansion, the chunk plan — lives in
// ecml-core.mjs and is checked in app/packages/safe/test/ecml-core.test.ts.
import { writeFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import {
  addressFromPubkey, chunkPlan, derToRsv, expandedKey, hex, keccak, packDerivationPath, toBytes,
  MLDSA65_KEY_BYTES, MLDSA65_PK_BYTES, MLDSA65_SIG_BYTES,
} from "./ecml-core.mjs";

const CLA = 0xe0;
const INS = { GET_PUBLIC_KEY: 0x05, GET_SIG_CHUNK: 0x12, GET_PK_CHUNK: 0x13, KEYGEN_DILITHIUM: 0x11, HYBRID_SIGN_HASH: 0x16 };
const P2_MLDSA_65 = 0x01;
const SW = {
  0x9000: "ok",
  0x6985: "refused on the device",
  0x6a86: "wrong P1/P2",
  0x6a87: "wrong length",
  0x6d00: "unknown instruction — is ECML-Signer the open app?",
  0x6e00: "wrong CLA — another app is open",
  0x6600: "the device failed to sign",
  0x6a84: "not enough memory on the device",
  0xb00a: "blind signing is disabled: turn it on in the app's Settings, then retry",
};

const args = process.argv.slice(2);
const cmd = args[0];
const flag = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const v = args[i + 1];
  if (v === undefined || v.startsWith("--")) throw new Error(`--${name} needs a value`);
  return v;
};

async function open() {
  // The package's ESM build imports its own files without extensions, which Node refuses. ecml-signer's
  // own client reaches past it to the CommonJS entry; so does this.
  const require = createRequire(import.meta.url);
  const mod = require("@ledgerhq/hw-transport-node-hid/lib/TransportNodeHid");
  const Transport = mod.default ?? mod;
  const transport = await Transport.open("").catch((e) => {
    const why = String(e?.name === "TransportError" || e?.message === "NoDevice" ? "no Ledger answered" : e?.message ?? e);
    throw new Error(
      `${why}. Plug the device in, unlock it, open ECML-Signer, and on Linux make sure the udev rules are ` +
        `installed (ecml-signer/.vscode/20-ledger.ledgerblue.rules).`,
    );
  });
  return {
    async send(ins, p1, p2, data = Buffer.alloc(0)) {
      const res = await transport.send(CLA, ins, p1, p2, Buffer.from(data), Object.keys(SW).map(Number));
      const sw = res.readUInt16BE(res.length - 2);
      if (sw !== 0x9000) throw new Error(`APDU ${ins.toString(16)} -> 0x${sw.toString(16)}: ${SW[sw] ?? "unexpected status"}`);
      return res.subarray(0, res.length - 2);
    },
    close: () => transport.close(),
  };
}

/** Reads `total` bytes through a chunked instruction. No other APDU may run in between. */
async function fetchChunks(dev, ins, total) {
  const parts = [];
  for (const [index, length] of chunkPlan(total)) parts.push(await dev.send(ins, index, length));
  const out = Buffer.concat(parts);
  if (out.length !== total) throw new Error(`expected ${total} bytes, the device returned ${out.length}`);
  return out;
}

/** GET_PUBLIC_KEY returns [65][uncompressed point][32][chain code]; the address is ours to compute. */
async function k1Address(dev, path) {
  const res = await dev.send(INS.GET_PUBLIC_KEY, 0x00, 0x00, packDerivationPath(path));
  const len = res[0];
  if (len !== 65) throw new Error(`expected a 65-byte point, the device announced ${len}`);
  return addressFromPubkey(res.subarray(1, 1 + 65));
}

async function cmdKey() {
  const path = flag("path", "m/44'/60'/0'/0'/0'");
  const out = flag("out");
  const dev = await open();
  try {
    const address = await k1Address(dev, path);
    // KEYGEN_DILITHIUM loads the key into the context without asking the user; the chunks then read it.
    await dev.send(INS.KEYGEN_DILITHIUM, 0x00, P2_MLDSA_65, packDerivationPath(path));
    const rawPk = await fetchChunks(dev, INS.GET_PK_CHUNK, MLDSA65_PK_BYTES);
    const key = expandedKey(rawPk);
    console.log(`path            ${path}`);
    console.log(`k1 address      ${address}`);
    console.log(`keccak(address) ${keccak(address)}`);
    console.log(`ML-DSA-65 pk    ${MLDSA65_PK_BYTES} bytes -> expanded ${MLDSA65_KEY_BYTES}`);
    console.log(`keccak(key)     ${keccak(key)}`);
    if (out) {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, key);
      console.log(`\nwrote ${out}`);
      console.log(`\nFACTORY=<from deployments/<chainId>-pq65.json> K1_ADDRESS=${address} KEY_FILE=${out} make safe-create-owner`);
    }
  } finally {
    await dev.close();
  }
}

async function cmdSign() {
  const path = flag("path", "m/44'/60'/0'/0'/0'");
  const out = flag("out");
  const digest = toBytes(flag("digest"));
  if (digest.length !== 32) throw new Error(`a digest is 32 bytes, got ${digest.length}`);

  const dev = await open();
  try {
    console.log(`Check the device screen. It must show exactly:\n  ${hex(digest).slice(2)}\n`);
    const res = await dev.send(
      INS.HYBRID_SIGN_HASH, 0x00, P2_MLDSA_65,
      Buffer.concat([packDerivationPath(path), digest]),
    );
    // [len][DER][parity]; nothing else may be sent before the two chunk reads below
    const derLen = res[0];
    const k1Signature = derToRsv(res.subarray(1, 1 + derLen), res[1 + derLen]);
    const rawPk = await fetchChunks(dev, INS.GET_PK_CHUNK, MLDSA65_PK_BYTES);
    const pqSignature = hex(await fetchChunks(dev, INS.GET_SIG_CHUNK, MLDSA65_SIG_BYTES));
    const key = expandedKey(rawPk);
    const k1Address_ = await k1Address(dev, path); // safe now: the chunks are already read

    const answer = { path, digest: hex(digest), k1Address: k1Address_, k1Signature, expandedKey: key, pqSignature };
    console.log(`k1 address      ${k1Address_}`);
    console.log(`k1 signature    65 bytes`);
    console.log(`ML-DSA-65 sig   ${MLDSA65_SIG_BYTES} bytes`);
    console.log(`keccak(key)     ${keccak(key)}`);
    if (out) {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, JSON.stringify(answer, null, 2));
      console.log(`\nwrote ${out} — paste its four fields into the signer page`);
    } else {
      console.log(JSON.stringify(answer, null, 2));
    }
  } finally {
    await dev.close();
  }
}

const usage = `ecml.mjs — ECML-Signer host side

  key   --path <m/44'/60'/0'/0'/0'> [--out keys/holder-1.hex]
  sign  --path <…> --digest 0x<64 hex> [--out answers/holder-1.json]

The path must be fully hardened: the app hardens every component of the ML-DSA path and none of the
secp256k1 one, so anything else gives two halves that do not belong together.`;

try {
  if (cmd === "key") await cmdKey();
  else if (cmd === "sign") await cmdSign();
  else {
    console.error(usage);
    process.exit(cmd ? 1 : 0);
  }
} catch (e) {
  console.error(`\n${e instanceof Error ? e.message : e}`);
  process.exit(1);
}
