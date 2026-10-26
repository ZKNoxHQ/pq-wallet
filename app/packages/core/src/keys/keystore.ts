// Encrypted mnemonic at rest (browser or Node 20+): PBKDF2-SHA256 → AES-256-GCM, WebCrypto only.
export type Keystore = { v: 1; kdf: "pbkdf2-sha256"; iterations: number; salt: string; iv: string; ct: string };

const subtle = () => globalThis.crypto.subtle;
const enc = new TextEncoder();
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const buf = (b: Uint8Array) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

async function deriveKey(password: string, salt: Uint8Array, iterations: number) {
  const saltBuf = buf(salt);
  const base = await subtle().importKey("raw", enc.encode(password.normalize("NFKD")), "PBKDF2", false, ["deriveKey"]);
  return subtle().deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: saltBuf, iterations }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function encryptMnemonic(mnemonic: string, password: string, iterations = 600_000): Promise<Keystore> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, iterations);
  const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: buf(iv) }, key, enc.encode(mnemonic)));
  return { v: 1, kdf: "pbkdf2-sha256", iterations, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}

export async function decryptMnemonic(ks: Keystore, password: string): Promise<string> {
  if (ks.v !== 1 || ks.kdf !== "pbkdf2-sha256") throw new Error("unsupported keystore");
  const key = await deriveKey(password, unb64(ks.salt), ks.iterations);
  try {
    const pt = await subtle().decrypt({ name: "AES-GCM", iv: buf(unb64(ks.iv)) }, key, buf(unb64(ks.ct)));
    return new TextDecoder().decode(pt);
  } catch {
    throw new Error("wrong password");
  }
}
