// Cross-check against the ETHDILITHIUM Python reference (pythonref/myenv), the same signer the Forge tests use.
import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { hexToBytes, bytesToHex, keccak256, stringToBytes } from "viem";
import { keygen, sign, verify, expandedPublicKey } from "../src/keys/mldsa44";
import { deriveSeed, mnemonicToSeed, defaultPath } from "../src/keys";

const PYREF = resolve(__dirname, "../../../../contracts/lib/ETHDILITHIUM/pythonref");
const PY = resolve(PYREF, "myenv/bin/python");
const py = (script: string, ...args: string[]) => execFileSync(PY, [script, ...args], { cwd: PYREF, maxBuffer: 1 << 24 }).toString().trim();
const SEED = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";

describe("ML-DSA-44 against the Python reference", () => {
  const available = existsSync(PY);
  it.skipIf(!available)("expanded public key blob matches prepare_pk_for_deployment.py", () => {
    const { publicKey } = keygen(hexToBytes(`0x${SEED}`));
    const ours = expandedPublicKey(publicKey);
    const theirs = "0x" + py("prepare_pk_for_deployment.py", "NIST", SEED);
    expect(ours.length).toBe(theirs.length);
    expect(ours).toBe(theirs);
  });

  it.skipIf(!available)("signature matches sig_sol.py (deterministic, empty context)", () => {
    const { secretKey } = keygen(hexToBytes(`0x${SEED}`));
    const digest = keccak256(stringToBytes("hello"));
    const sig = sign(secretKey, hexToBytes(digest));
    const out = py("sig_sol.py", digest, "NIST", SEED); // abi.encode(bytes cTilde, bytes z, bytes h)
    // decode the three parts and concatenate
    const words = (out.match(/.{64}/g) ?? []).map((w: string) => BigInt("0x" + w));
    const offs = words.slice(0, 3).map((o: bigint) => Number(o) / 32);
    const parts = offs.map((o: number) => { const len = Number(words[o]); return out.slice((o + 1) * 64, (o + 1) * 64 + len * 2); });
    expect(bytesToHex(sig)).toBe("0x" + parts.join(""));
  });

  it("sign / verify round trip, signature length", () => {
    const { secretKey, publicKey } = keygen(hexToBytes(`0x${SEED}`));
    const digest = hexToBytes(keccak256(stringToBytes("x")));
    const sig = sign(secretKey, digest);
    expect(sig.length).toBe(2420);
    expect(verify(publicKey, digest, sig)).toBe(true);
    digest[0] ^= 1;
    expect(verify(publicKey, digest, sig)).toBe(false);
  });
});

describe("SLIP-0010 extended derivation", () => {
  it("is deterministic, hardened-only, and separates schemes", () => {
    const seed = mnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    const a = deriveSeed("ML-DSA-44", seed, defaultPath());
    const b = deriveSeed("ML-DSA-44", seed, defaultPath());
    const c = deriveSeed("Falcon-512", seed, defaultPath());
    const d = deriveSeed("ML-DSA-44", seed, defaultPath(0, 1));
    expect(bytesToHex(a.seed)).toBe(bytesToHex(b.seed));
    expect(bytesToHex(a.seed)).not.toBe(bytesToHex(c.seed));
    expect(bytesToHex(a.seed)).not.toBe(bytesToHex(d.seed));
    expect(() => deriveSeed("ML-DSA-44", seed, "m/44'/60'/0'/0/0")).toThrow(/hardened/);
    // vector, to be frozen once the Ledger side is aligned
    expect(bytesToHex(a.seed)).toMatchInlineSnapshot(`"0x0f2e6178b06ddff10673dd4e02f5579cd7faf0a6cea4f1cb8b195ea778e67578"`);
  });
});
