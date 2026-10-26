import { describe, it, expect } from "vitest";
import { encryptMnemonic, decryptMnemonic, newMnemonic, isMnemonic } from "../src/keys";

describe("keystore", () => {
  it("round-trips with the right password and rejects a wrong one", async () => {
    const m = newMnemonic();
    expect(isMnemonic(m)).toBe(true);
    const ks = await encryptMnemonic(m, "correct horse", 20_000);
    expect(ks.ct).not.toContain(m.split(" ")[0]);
    expect(await decryptMnemonic(ks, "correct horse")).toBe(m);
    await expect(decryptMnemonic(ks, "battery staple")).rejects.toThrow(/wrong password/);
  });
});
