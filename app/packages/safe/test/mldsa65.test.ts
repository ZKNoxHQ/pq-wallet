// ML-DSA-65 against ETHDILITHIUM's own js encoder — the one the Forge tests drive through vm.ffi. If the
// expanded-key layout ever changes upstream, this is where it shows up, not in a verifier revert.
import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { bytesToHex, hexToBytes, keccak256, stringToBytes, size } from "viem";
import { expandedPublicKey, flattenKeyPolys, keygen, sign, verify, MLDSA65 } from "../src/mldsa65";

const JS = resolve(__dirname, "../../../../lib/ETHDILITHIUM/js");
const SEED = "18f6d4b2907e5c3a18f6d4b2907e5c3a18f6d4b2907e5c3a18f6d4b2907e5c3a";
const installed = existsSync(resolve(JS, "node_modules"));

describe("ML-DSA-65", () => {
  it("round trips, with FIPS 204 sizes", () => {
    const { publicKey, secretKey } = keygen(hexToBytes(`0x${SEED}`));
    expect(publicKey.length).toBe(MLDSA65.pkBytes);
    const digest = hexToBytes(keccak256(stringToBytes("x")));
    const sig = sign(secretKey, digest);
    expect(sig.length).toBe(MLDSA65.sigBytes);
    expect(verify(publicKey, digest, sig)).toBe(true);
    digest[0] ^= 1;
    expect(verify(publicKey, digest, sig)).toBe(false);
  });

  it("signs deterministically: the same seed and digest give the same bytes", () => {
    const { secretKey } = keygen(hexToBytes(`0x${SEED}`));
    const digest = hexToBytes(keccak256(stringToBytes("x")));
    expect(bytesToHex(sign(secretKey, digest))).toBe(bytesToHex(sign(secretKey, digest)));
  });

  it("the expanded key is 36 polynomials of 32 words, then tr", () => {
    const { publicKey } = keygen(hexToBytes(`0x${SEED}`));
    const polys = flattenKeyPolys(publicKey);
    expect(polys.length).toBe(MLDSA65.keyPolys);
    for (const p of polys) expect(p.length).toBe(32);
    expect(size(expandedPublicKey(publicKey))).toBe(MLDSA65.keyBytes);
  });

  it.skipIf(!installed)("matches ETHDILITHIUM's js encoder, key and signature", async () => {
    const ref = await import(/* @vite-ignore */ resolve(JS, "mldsa65.js"));
    const seed = hexToBytes(`0x${SEED}`);
    const theirs = ref.keygen(seed);
    const ours = keygen(seed);
    expect(bytesToHex(ours.publicKey)).toBe(ref.bytesToHex(theirs.publicKey));
    expect(expandedPublicKey(ours.publicKey)).toBe(
      ref.encodePublicKey65(ref.expandPublicKey65(theirs.publicKey)),
    );
    const digest = keccak256(stringToBytes("safe"));
    expect(bytesToHex(sign(ours.secretKey, hexToBytes(digest)))).toBe(
      ref.bytesToHex(ref.sign(hexToBytes(digest), theirs.secretKey, { deterministic: true })),
    );
  });
});
