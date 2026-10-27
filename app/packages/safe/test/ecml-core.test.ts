// The host-side conversions between the ECML-Signer Ledger app and the chain, checked without a device.
// A device would only add the transport; these are the three places where a wrong assumption yields a
// signature that fails on chain, at 3.9 M gas, with nothing on screen to explain it.
import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { hexToBytes, keccak256, recoverAddress, stringToBytes, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const CORE = resolve(__dirname, "../../../../safe/scripts/ecml-core.mjs");
const MLDSA = resolve(__dirname, "../../../../lib/ETHDILITHIUM/js/mldsa65.js");
const JSDEPS = resolve(__dirname, "../../../../lib/ETHDILITHIUM/js/node_modules");
const ready = existsSync(CORE) && existsSync(JSDEPS);

type Core = {
  addressFromPubkey: (p: Uint8Array | string) => string;
  derToRsv: (der: Uint8Array | string, parity: number) => Hex;
  parseDer: (der: Uint8Array | string) => { r: Buffer; s: Buffer };
  parseEthAppAddress: (res: Uint8Array | string) => string;
  expandedKey: (pk: Uint8Array | string) => Hex;
  packDerivationPath: (p: string, requireHardened?: boolean) => Buffer;
  chunkPlan: (total: number, stride?: number) => [number, number][];
  MLDSA65_KEY_BYTES: number;
  MLDSA65_PK_BYTES: number;
  MLDSA65_SIG_BYTES: number;
};
const core = async (): Promise<Core> => (await import(/* @vite-ignore */ CORE)) as unknown as Core;

const KEY: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const account = privateKeyToAccount(KEY);

/** DER SEQUENCE { INTEGER r, INTEGER s }, as the Ledger app emits it. Written here so the parser is fed
 *  something produced independently of itself. */
function toDer(r: Hex, s: Hex): Uint8Array {
  const int = (v: Hex) => {
    let b = Array.from(hexToBytes(v));
    while (b.length > 1 && b[0] === 0) b.shift(); // DER integers carry no leading zeros
    if (b[0] & 0x80) b.unshift(0); //            ... and are signed, so a high bit needs one
    return [0x02, b.length, ...b];
  };
  const body = [...int(r), ...int(s)];
  return Uint8Array.from([0x30, body.length, ...body]);
}

describe.skipIf(!ready)("ECML-Signer host conversions", () => {
  it("derives the address the app never returns: keccak of the uncompressed point", async () => {
    const { addressFromPubkey } = await core();
    expect(addressFromPubkey(account.publicKey).toLowerCase()).toBe(account.address.toLowerCase());
  });

  it("refuses anything that is not a 65-byte uncompressed point", async () => {
    const { addressFromPubkey } = await core();
    expect(() => addressFromPubkey(`0x02${account.publicKey.slice(4, 68)}`)).toThrow(/65-byte/);
  });

  it("turns DER + a parity bit into the 65 bytes ECDSAk1Verifier reads", async () => {
    const { derToRsv } = await core();
    const digest = keccak256(stringToBytes("a digest the device would show"));
    const rsv = await account.sign({ hash: digest });
    const r = `0x${rsv.slice(2, 66)}` as Hex;
    const s = `0x${rsv.slice(66, 130)}` as Hex;
    const parity = parseInt(rsv.slice(130, 132), 16) - 27;
    expect(derToRsv(toDer(r, s), parity)).toBe(rsv);
  });

  it("and the result recovers the signer, which is all the verifier checks", async () => {
    const { derToRsv } = await core();
    const digest = keccak256(stringToBytes("x"));
    const rsv = await account.sign({ hash: digest });
    const rebuilt = derToRsv(
      toDer(`0x${rsv.slice(2, 66)}` as Hex, `0x${rsv.slice(66, 130)}` as Hex),
      parseInt(rsv.slice(130, 132), 16) - 27,
    );
    expect((await recoverAddress({ hash: digest, signature: rebuilt })).toLowerCase()).toBe(
      account.address.toLowerCase(),
    );
  });

  it("rejects a v that is not a parity bit, which is how the device reports it", async () => {
    const { derToRsv } = await core();
    const rsv = await account.sign({ hash: keccak256(stringToBytes("y")) });
    const der = toDer(`0x${rsv.slice(2, 66)}` as Hex, `0x${rsv.slice(66, 130)}` as Hex);
    expect(() => derToRsv(der, 27)).toThrow(/parity/);
  });

  it("pads a short DER integer back to 32 bytes", async () => {
    const { parseDer } = await core();
    const { r, s } = parseDer(toDer("0x0000000000000000000000000000000000000000000000000000000000000001", "0x02"));
    expect(r.length).toBe(32);
    expect(s.length).toBe(32);
    expect(Buffer.from(s).toString("hex")).toBe("00".repeat(31) + "02");
  });

  it("expands the device's packed key to the 38,112 bytes the verifier reads", async () => {
    const { expandedKey, MLDSA65_KEY_BYTES } = await core();
    const { keygen } = (await import(/* @vite-ignore */ MLDSA)) as { keygen: (s: Uint8Array) => { publicKey: Uint8Array } };
    const { publicKey } = keygen(hexToBytes(`0x${"18f6d4b2907e5c3a".repeat(4)}`));
    const out = expandedKey(publicKey);
    expect((out.length - 2) / 2).toBe(MLDSA65_KEY_BYTES);
    // the same bytes @zknox/pq-safe derives in TypeScript, which is what the front shows and hashes
    const { expandedPublicKey } = await import("../src/mldsa65");
    expect(out.toLowerCase()).toBe(expandedPublicKey(publicKey).toLowerCase());
  });

  it("packs a fully hardened path", async () => {
    const { packDerivationPath } = await core();
    const p = packDerivationPath("m/44'/60'/0'/0'/0'");
    expect(p[0]).toBe(5);
    expect(p.length).toBe(21);
    expect(p.readUInt32BE(1)).toBe(0x8000002c); // 44'
  });

  it("and the ordinary BIP-44 path, which the app's own derivation expects", async () => {
    // ecml-signer uses the path raw for secp256k1 and forces hardening for ML-DSA, so a non-hardened
    // path is the intended input rather than a mistake (src/crypto/mldsa_derive.c).
    const { packDerivationPath } = await core();
    const p = packDerivationPath("m/44'/60'/0'/0/0");
    expect(p.readUInt32BE(13)).toBe(0);
    expect(() => packDerivationPath("m/44'/60'/0'/0/0", true)).toThrow(/hardened/);
  });

  it("reads the deploying address out of the stock Ethereum app's answer", async () => {
    const { parseEthAppAddress } = await core();
    const pub = hexToBytes(account.publicKey); // 65 bytes, 0x04-tagged
    const ascii = Buffer.from(account.address.slice(2).toLowerCase(), "ascii");
    const frame = Uint8Array.from([65, ...pub, 40, ...ascii]);
    expect(parseEthAppAddress(frame).toLowerCase()).toBe(account.address.toLowerCase());
  });

  it("refuses an Ethereum-app answer whose address and public key disagree", async () => {
    const { parseEthAppAddress } = await core();
    const pub = hexToBytes(account.publicKey);
    const wrong = Buffer.from("00".repeat(20), "ascii"); // 40 ASCII characters, wrong address
    expect(() => parseEthAppAddress(Uint8Array.from([65, ...pub, 40, ...wrong]))).toThrow(/does not match/);
    expect(() => parseEthAppAddress(Uint8Array.from([64, ...pub.slice(0, 64)]))).toThrow(/65-byte/);
  });

  it("packs a non-hardened path only when asked, as the Ethereum app needs", async () => {
    const { packDerivationPath } = await core();
    const p = packDerivationPath("m/44'/60'/0'/0/0", false);
    expect(p[0]).toBe(5);
    expect(p.readUInt32BE(1)).toBe(0x8000002c); // 44'
    expect(p.readUInt32BE(13)).toBe(0); //          0, not hardened
    expect(p.readUInt32BE(17)).toBe(0);
  });

  it("plans the chunk reads the app's 255-byte stride needs", async () => {
    const { chunkPlan, MLDSA65_PK_BYTES, MLDSA65_SIG_BYTES } = await core();
    const pk = chunkPlan(MLDSA65_PK_BYTES);
    const sig = chunkPlan(MLDSA65_SIG_BYTES);
    expect(pk.length).toBe(8);
    expect(pk[7]).toEqual([7, 167]); //  7 x 255 + 167 = 1952
    expect(sig.length).toBe(13);
    expect(sig[12]).toEqual([12, 249]); // 12 x 255 + 249 = 3309
  });
});
