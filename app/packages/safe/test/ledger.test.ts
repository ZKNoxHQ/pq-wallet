// The ECML-Signer dialogue, against a fake device.
//
// The device path used to be the one part of this repository with no coverage: a CLI drove it by hand and
// nothing checked the conversions in context. The transport being injectable, a fake app can stand in —
// and it enforces the rule that costs the most to get wrong: GET_PUBLIC_KEY and KEYGEN_DILITHIUM share a
// memory union with the ML-DSA signature, so either of them between HYBRID_SIGN_HASH and the chunk reads
// destroys what is being read. Here that is a failed test rather than a 3.9 M gas revert.
import { describe, expect, it } from "vitest";
import { hexToBytes, keccak256, recoverAddress, stringToBytes, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  CLA, INS, LedgerAccounts, MLDSA65, addressFromPubkey, chunkPlan, defaultPaths, derToRsv, ledgerSigner,
  packDerivationPath, parseDer, readAccount, signWithAccount,
} from "../src";
import { expandedPublicKey, keygen, sign as mldsaSign, verify as mldsaVerify } from "../src/mldsa65";

const OWNER = "0x000000000000000000000000000000000000dEaD" as Address;

/** DER SEQUENCE { INTEGER r, INTEGER s }, written here so the parser is fed something produced
 *  independently of itself. */
function toDer(r: Hex, s: Hex): Uint8Array {
  const int = (v: Hex) => {
    let b = Array.from(hexToBytes(v));
    while (b.length > 1 && b[0] === 0) b.shift(); // DER integers carry no leading zeros
    if (b[0] & 0x80) b.unshift(0); //              ... and are signed, so a high bit needs one
    return [0x02, b.length, ...b];
  };
  const body = [...int(r), ...int(s)];
  return Uint8Array.from([0x30, body.length, ...body]);
}

type Fake = {
  send: (ins: number, p1: number, p2: number, data?: Uint8Array) => Promise<Uint8Array>;
  /** every instruction byte the device saw, in order */
  log: number[];
  /** how many times a path was derived from scratch */
  derivations: number;
};

/** One ECML-Signer, with one hybrid key per derivation path and the same RAM aliasing as the real app. */
function fakeDevice(opts: { swapKeyAfterSign?: boolean } = {}): Fake {
  const log: number[] = [];
  let derivations = 0;
  let ram: { pk: Uint8Array | null; sig: Uint8Array | null } = { pk: null, sig: null };

  const seedFor = (path: string) => hexToBytes(keccak256(stringToBytes(`ecml:${path}`)));
  const k1For = (path: string) => privateKeyToAccount(keccak256(stringToBytes(`k1:${path}`)));
  const mldsaFor = (path: string) => keygen(seedFor(path));

  const pathOf = (data: Uint8Array): string => {
    const n = data[0];
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const parts: string[] = [];
    for (let i = 0; i < n; i++) {
      const v = view.getUint32(1 + 4 * i, false);
      parts.push(v >= 0x80000000 ? `${v - 0x80000000}'` : `${v}`);
    }
    return `m/${parts.join("/")}`;
  };

  const chunk = (buf: Uint8Array | null, p1: number, p2: number, what: string) => {
    if (!buf) throw new Error(`the device's ${what} RAM was wiped before it was read`);
    const off = p1 * 255;
    const out = buf.subarray(off, off + p2);
    if (out.length !== p2) throw new Error(`chunk ${p1} of ${what}: asked ${p2}, have ${out.length}`);
    return out;
  };

  return {
    log,
    get derivations() {
      return derivations;
    },
    async send(ins, p1, p2, data = new Uint8Array(0)) {
      log.push(ins);
      switch (ins) {
        case INS.GET_PUBLIC_KEY: {
          ram = { pk: null, sig: null }; // shares a union with the ML-DSA context
          derivations++;
          const pub = hexToBytes(k1For(pathOf(data)).publicKey);
          return Uint8Array.from([65, ...pub, 32, ...new Uint8Array(32)]);
        }
        case INS.KEYGEN_DILITHIUM: {
          const { publicKey } = mldsaFor(pathOf(data));
          ram = { pk: publicKey, sig: null };
          return new Uint8Array(0);
        }
        case INS.HYBRID_SIGN_HASH: {
          const path = pathOf(data.subarray(0, data.length - 32));
          const digest = data.subarray(data.length - 32);
          const { publicKey, secretKey } = mldsaFor(path);
          const rsv = await k1For(path).sign({ hash: `0x${Buffer.from(digest).toString("hex")}` as Hex });
          const der = toDer(`0x${rsv.slice(2, 66)}` as Hex, `0x${rsv.slice(66, 130)}` as Hex);
          const parity = parseInt(rsv.slice(130, 132), 16) - 27;
          ram = {
            pk: opts.swapKeyAfterSign ? mldsaFor("m/44'/60'/0'/9'/9'").publicKey : publicKey,
            sig: mldsaSign(secretKey, digest),
          };
          return Uint8Array.from([der.length, ...der, parity]);
        }
        case INS.GET_PK_CHUNK:
          return chunk(ram.pk, p1, p2, "public key");
        case INS.GET_SIG_CHUNK:
          return chunk(ram.sig, p1, p2, "signature");
        default:
          throw new Error(`unexpected instruction 0x${ins.toString(16)}`);
      }
    },
  };
}

const PATH = "m/44'/60'/0'/1'/0'";

describe("packDerivationPath", () => {
  it("packs a fully hardened path as [len][u32 BE x len]", () => {
    const p = packDerivationPath("m/44'/60'/0'/0'/0'");
    expect(p.length).toBe(21);
    expect(p[0]).toBe(5);
    expect(new DataView(p.buffer).getUint32(1, false)).toBe(0x8000002c);
  });

  it("accepts the ordinary BIP-44 path, which is what the app's own derivation expects", () => {
    // The device uses the path raw for secp256k1 and forces hardening for ML-DSA, so a non-hardened path
    // is not a mistake: it is the intended input (ecml-signer, src/crypto/mldsa_derive.c).
    const p = packDerivationPath("m/44'/60'/0'/0/0");
    expect(p[0]).toBe(5);
    expect(new DataView(p.buffer).getUint32(13, false)).toBe(0);
    expect(new DataView(p.buffer).getUint32(17, false)).toBe(0);
  });

  it("still refuses one when the caller asks for hardened only", () => {
    expect(() => packDerivationPath("m/44'/60'/0'/0/0", true)).toThrow(/hardened/);
  });
});

describe("the conversions between the app and the chain", () => {
  it("derives the address the app never returns", () => {
    const a = privateKeyToAccount(keccak256(stringToBytes("x")));
    expect(addressFromPubkey(hexToBytes(a.publicKey)).toLowerCase()).toBe(a.address.toLowerCase());
  });

  it("turns DER plus a parity bit into 65 bytes that recover the signer", async () => {
    const a = privateKeyToAccount(keccak256(stringToBytes("y")));
    const digest = keccak256(stringToBytes("a digest the device would show"));
    const rsv = await a.sign({ hash: digest });
    const rebuilt = derToRsv(
      toDer(`0x${rsv.slice(2, 66)}` as Hex, `0x${rsv.slice(66, 130)}` as Hex),
      parseInt(rsv.slice(130, 132), 16) - 27,
    );
    expect(rebuilt).toBe(rsv);
    expect((await recoverAddress({ hash: digest, signature: rebuilt })).toLowerCase()).toBe(
      a.address.toLowerCase(),
    );
  });

  it("rejects a v that is not a parity bit", () => {
    const a = privateKeyToAccount(keccak256(stringToBytes("z")));
    const der = toDer(`0x${"11".repeat(32)}`, `0x${"22".repeat(32)}`);
    expect(() => derToRsv(der, 27)).toThrow(/parity/);
    expect(a.address).toBeTruthy();
  });

  it("pads a short DER integer back to 32 bytes", () => {
    const { r, s } = parseDer(toDer(`0x${"00".repeat(31)}01`, "0x02"));
    expect(r.length).toBe(32);
    expect(s[31]).toBe(2);
  });

  it("plans the chunk reads the 255-byte stride needs", () => {
    expect(chunkPlan(MLDSA65.pkBytes)).toHaveLength(8);
    expect(chunkPlan(MLDSA65.pkBytes)[7]).toEqual([7, 167]); //   7 x 255 + 167 = 1952
    expect(chunkPlan(MLDSA65.sigBytes)).toHaveLength(13);
    expect(chunkPlan(MLDSA65.sigBytes)[12]).toEqual([12, 249]); // 12 x 255 + 249 = 3309
  });
});

describe("readAccount", () => {
  it("returns both halves and the two hashes a clone stores", async () => {
    const dev = fakeDevice();
    const a = await readAccount(dev.send, PATH);
    expect(a.path).toBe(PATH);
    expect((a.expandedKey.length - 2) / 2).toBe(MLDSA65.keyBytes);
    expect(a.preQKeyHash).toBe(keccak256(a.k1Address));
    expect(a.postQKeyHash).toBe(keccak256(a.expandedKey));
  });

  it("expands the packed key exactly as the rest of the front does", async () => {
    const dev = fakeDevice();
    const a = await readAccount(dev.send, PATH);
    const { publicKey } = keygen(hexToBytes(keccak256(stringToBytes(`ecml:${PATH}`))));
    expect(a.expandedKey.toLowerCase()).toBe(expandedPublicKey(publicKey).toLowerCase());
  });
});

describe("signWithAccount", () => {
  it("returns a hybrid signature both verifiers accept", async () => {
    const dev = fakeDevice();
    const account = await readAccount(dev.send, PATH);
    const digest = keccak256(stringToBytes("S_pq approving the root's hash"));
    const answer = await signWithAccount(dev.send, account, OWNER, digest);

    expect(answer.owner).toBe(OWNER);
    expect((answer.k1Signature.length - 2) / 2).toBe(65);
    expect((answer.pqSignature.length - 2) / 2).toBe(MLDSA65.sigBytes);
    expect(answer.expandedKey).toBe(account.expandedKey);
    expect((await recoverAddress({ hash: digest, signature: answer.k1Signature })).toLowerCase()).toBe(
      account.k1Address.toLowerCase(),
    );
    const { publicKey } = keygen(hexToBytes(keccak256(stringToBytes(`ecml:${PATH}`))));
    expect(mldsaVerify(publicKey, hexToBytes(digest), hexToBytes(answer.pqSignature))).toBe(true);
  });

  it("runs nothing between HYBRID_SIGN_HASH and the chunk reads", async () => {
    const dev = fakeDevice();
    const account = await readAccount(dev.send, PATH);
    const before = dev.log.length;
    await signWithAccount(dev.send, account, OWNER, keccak256(stringToBytes("one")));
    const after = dev.log.slice(before);

    expect(after[0]).toBe(INS.HYBRID_SIGN_HASH);
    // 1 sign + 8 public-key chunks + 13 signature chunks, and nothing else
    expect(after).toHaveLength(1 + 8 + 13);
    expect(after.slice(1, 9).every((i) => i === INS.GET_PK_CHUNK)).toBe(true);
    expect(after.slice(9).every((i) => i === INS.GET_SIG_CHUNK)).toBe(true);
    expect(after).not.toContain(INS.GET_PUBLIC_KEY);
    expect(after).not.toContain(INS.KEYGEN_DILITHIUM);
  });

  it("refuses a digest that is not 32 bytes", async () => {
    const dev = fakeDevice();
    const account = await readAccount(dev.send, PATH);
    await expect(signWithAccount(dev.send, account, OWNER, "0xdeadbeef")).rejects.toThrow(/32 bytes/);
  });

  it("notices if the device answers with a different key than the one read at this path", async () => {
    const dev = fakeDevice({ swapKeyAfterSign: true });
    const account = await readAccount(dev.send, PATH);
    await expect(
      signWithAccount(dev.send, account, OWNER, keccak256(stringToBytes("two"))),
    ).rejects.toThrow(/different ML-DSA-65 key/);
  });
});

describe("LedgerAccounts", () => {
  it("finds the account whose keys a clone stores, and scans no further", async () => {
    const dev = fakeDevice();
    const accounts = new LedgerAccounts(dev.send);
    const want = await readAccount(dev.send, "m/44'/60'/0'/0/1");
    const derivationsBefore = dev.derivations;

    const found = await accounts.find(want.postQKeyHash, want.preQKeyHash);
    expect(found?.path).toBe("m/44'/60'/0'/0/1");
    // the two families interleaved: 0/0, 0'/0', 0/1 — it stops at the match
    expect(dev.derivations - derivationsBefore).toBe(3);
  });

  it("scans both path families, since both are in use", () => {
    const paths = defaultPaths(3);
    expect(paths).toEqual([
      "m/44'/60'/0'/0/0", "m/44'/60'/0'/0'/0'",
      "m/44'/60'/0'/0/1", "m/44'/60'/0'/1'/0'",
      "m/44'/60'/0'/0/2", "m/44'/60'/0'/2'/0'",
    ]);
  });

  it("will not pair the right ML-DSA key with the wrong secp256k1 half", async () => {
    // On a real device m/44'/60'/0'/0/0 and m/44'/60'/0'/0'/0' share their ML-DSA key and differ in k1,
    // which is exactly the confusion `preQKeyHash` exists to catch.
    const dev = fakeDevice();
    const accounts = new LedgerAccounts(dev.send);
    const a = await accounts.at("m/44'/60'/0'/0/0");
    const b = await accounts.at("m/44'/60'/0'/1'/0'");
    expect(await accounts.find(a.postQKeyHash, b.preQKeyHash)).toBeNull();
    expect(await accounts.find(a.postQKeyHash, a.preQKeyHash)).toEqual(a);
  });

  it("answers from cache the second time, so a second owner costs no APDU", async () => {
    const dev = fakeDevice();
    const accounts = new LedgerAccounts(dev.send);
    const first = await accounts.at(PATH);
    const n = dev.log.length;
    const again = await accounts.find(first.postQKeyHash);
    expect(again).toEqual(first);
    expect(dev.log.length).toBe(n);
  });

  it("returns null when no account of the device owns the clone", async () => {
    const dev = fakeDevice();
    const accounts = new LedgerAccounts(dev.send);
    expect(await accounts.find(keccak256(stringToBytes("nobody's key")))).toBeNull();
  });

  it("signs through the class, so a caller never holds the APDU channel", async () => {
    const dev = fakeDevice();
    const accounts = new LedgerAccounts(dev.send);
    const account = await accounts.at(PATH);
    const digest = keccak256(stringToBytes("through the class"));
    const answer = await accounts.signAs(account, OWNER, digest);
    expect(answer.k1Address).toBe(account.k1Address);
    expect((await recoverAddress({ hash: digest, signature: answer.k1Signature })).toLowerCase()).toBe(
      account.k1Address.toLowerCase(),
    );
  });
});

describe("ledgerSigner", () => {
  it("is interchangeable with the software holder", async () => {
    const dev = fakeDevice();
    const account = await readAccount(dev.send, PATH);
    const signer = ledgerSigner(dev.send, account);
    expect(signer.id).toContain(account.k1Address);
    expect(await signer.keyHashes()).toEqual({
      preQKeyHash: account.preQKeyHash,
      postQKeyHash: account.postQKeyHash,
    });
    const answer = await signer.sign(OWNER, keccak256(stringToBytes("three")));
    expect(answer.k1Address).toBe(account.k1Address);
  });
});

describe("the protocol constants", () => {
  it("are the ones ecml-signer v2.4.0 answers to", () => {
    expect(CLA).toBe(0xe0);
    expect(INS).toEqual({
      GET_PUBLIC_KEY: 0x05,
      KEYGEN_DILITHIUM: 0x11,
      GET_SIG_CHUNK: 0x12,
      GET_PK_CHUNK: 0x13,
      HYBRID_SIGN_HASH: 0x16,
    });
  });
});
