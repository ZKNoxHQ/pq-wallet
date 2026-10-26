// Safe signature packing: the layout `checkNSignatures` reads, on cases small enough to read by eye.
// The large one — two post-quantum owners, 84 kB — is in fixture.test.ts, against the Solidity.
import { describe, it, expect } from "vitest";
import { size, type Address, type Hex } from "viem";
import { approvedSig, contractSig, ecdsaSig, normalizeV, pack } from "../src/signatures";
import { calldataGas, fitsInMempool, TXPOOL_LIMIT } from "../src/plan";

const A: Address = "0x1111111111111111111111111111111111111111";
const B: Address = "0x2222222222222222222222222222222222222222";
const C: Address = "0xcccccccccccccccccccccccccccccccccccccccc";
const rsv = (b: string): Hex => `0x${b.repeat(64)}${b.repeat(64)}1b` as Hex;

describe("pack", () => {
  it("sorts by owner, whatever order they arrive in", () => {
    const sorted = pack([approvedSig(A), approvedSig(B), approvedSig(C)]);
    expect(pack([approvedSig(C), approvedSig(A), approvedSig(B)])).toBe(sorted);
    expect(size(sorted)).toBe(195);
    // first record: owner A, 0, v = 1
    expect(sorted.slice(2, 66)).toBe(`000000000000000000000000${A.slice(2)}`);
    expect(sorted.slice(130, 132)).toBe("01");
  });

  it("an ECDSA record is the 65 bytes themselves", () => {
    expect(pack([ecdsaSig(A, rsv("a"))])).toBe(rsv("a"));
    expect(() => pack([ecdsaSig(A, "0xdead")])).toThrow(/65 bytes/);
  });

  it("a contract record points past the whole static part", () => {
    const payload: Hex = "0xdeadbeef";
    const blob = pack([ecdsaSig(A, rsv("a")), contractSig(B, payload)]);
    // 2 records of 65 bytes, then B's dynamic part: a length word and the payload
    expect(size(blob)).toBe(130 + 32 + 4);
    const chars = blob.slice(2);
    const record = (i: number) => chars.slice(i * 130, (i + 1) * 130); // 65 bytes = 130 hex characters
    expect(record(0)).toBe(rsv("a").slice(2));
    expect(record(1).slice(0, 64)).toBe(`000000000000000000000000${B.slice(2)}`);
    expect(BigInt(`0x${record(1).slice(64, 128)}`)).toBe(130n); // past both static records
    expect(record(1).slice(128)).toBe("00"); // v = 0: a contract signature
    const tail = chars.slice(2 * 130);
    expect(BigInt(`0x${tail.slice(0, 64)}`)).toBe(4n);
    expect(tail.slice(64)).toBe("deadbeef");
  });

  it("two contract records: the second offset counts the first's length word", () => {
    const blob = pack([contractSig(A, "0x1234"), contractSig(B, "0x5678")]);
    const off = (i: number) => BigInt(`0x${blob.slice(2 + i * 130 + 64, 2 + i * 130 + 128)}`);
    expect(off(0)).toBe(130n);
    expect(off(1)).toBe(130n + 32n + 2n);
    expect(size(blob)).toBe(130 + 2 * (32 + 2));
  });

  it("the input array is left alone", () => {
    const sigs = [approvedSig(C), approvedSig(A)];
    pack(sigs);
    expect(sigs[0].owner).toBe(C);
  });
});

describe("normalizeV", () => {
  it("lifts v to 27/28 and adds 4 for a personal_sign signature", () => {
    const raw = (`0x${"11".repeat(32)}${"22".repeat(32)}00`) as Hex;
    expect(normalizeV(raw).slice(-2)).toBe("1b");
    expect(normalizeV(raw, true).slice(-2)).toBe("1f");
    expect(normalizeV((raw.slice(0, 130) + "1c") as Hex, true).slice(-2)).toBe("20");
  });
});

describe("what to say before an 84 kB transaction leaves", () => {
  it("counts the EIP-7623 floor and the classical intrinsic cost", () => {
    const g = calldataGas("0x0000ffff");
    expect(g).toMatchObject({ bytes: 4, zeros: 2, nonzeros: 2 });
    expect(g.intrinsic).toBe(21000 + 8 + 32);
    expect(g.floor).toBe(21000 + 10 * (2 + 8));
  });

  it("knows the 128 KiB a node will relay", () => {
    expect(TXPOOL_LIMIT).toBe(131072);
    expect(fitsInMempool(`0x${"ab".repeat(131000)}`)).toBe(false); // 131,000 bytes: over, once the
    expect(fitsInMempool(`0x${"ab".repeat(84580)}`)).toBe(true); //  envelope is counted. k = 2 fits.
  });
});
