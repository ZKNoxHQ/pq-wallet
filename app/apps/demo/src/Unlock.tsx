import React, { useState } from "react";
import { encryptMnemonic, decryptMnemonic, newMnemonic, isMnemonic, type Keystore } from "@zknox/pq-core";

const STORE_KEY = "zknox.wallet.keystore.v1";
export const loadKeystore = (): Keystore | null => { const raw = localStorage.getItem(STORE_KEY); return raw ? (JSON.parse(raw) as Keystore) : null; };
export const clearKeystore = () => localStorage.removeItem(STORE_KEY);

const box: React.CSSProperties = { maxWidth: 520, margin: "10vh auto", padding: 24, borderRadius: 14, background: "#101014", border: "1px solid #33333a", color: "#ececee", fontFamily: "'Helvetica Neue', Helvetica, Arial, system-ui, sans-serif" };
const input: React.CSSProperties = { display: "block", width: "100%", boxSizing: "border-box", marginTop: 7, padding: "9px 11px", borderRadius: 8, background: "#17171b", border: "1px solid #33333a", color: "#ececee", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 13 };
const btn = (primary = false): React.CSSProperties => ({ padding: "9px 16px", borderRadius: 8, border: primary ? "1px solid #7c3aed" : "1px solid #33333a", background: primary ? "linear-gradient(180deg, #7c3aed, #5b21b6)" : "#1c1c21", color: primary ? "#fff" : "#d6d6db", fontFamily: "inherit", fontSize: 13, fontWeight: 500, cursor: "pointer" });
const label: React.CSSProperties = { fontSize: 12, letterSpacing: "0.04em", textTransform: "uppercase", color: "#8f8f99" };

/** Create, import or unlock the encrypted mnemonic. Calls `onUnlocked(mnemonic)`. */
export function Unlock({ onUnlocked }: { onUnlocked: (mnemonic: string) => void }) {
  const existing = loadKeystore();
  const [mode, setMode] = useState<"unlock" | "create" | "import">(existing ? "unlock" : "create");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [phrase, setPhrase] = useState(() => (existing ? "" : newMnemonic()));
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const go = async () => {
    setErr(null); setBusy(true);
    try {
      if (mode === "unlock") { onUnlocked(await decryptMnemonic(existing!, password)); return; }
      if (password.length < 8) throw new Error("Use at least 8 characters");
      if (password !== confirm) throw new Error("Passwords differ");
      const m = phrase.trim().toLowerCase().replace(/\s+/g, " ");
      if (!isMnemonic(m)) throw new Error("Not a valid BIP39 phrase");
      localStorage.setItem(STORE_KEY, JSON.stringify(await encryptMnemonic(m, password)));
      onUnlocked(m);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0b0b0c" }}>
      <div style={box}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 600 }}>Ethereum wallet</h1>
        <p style={{ margin: "6px 0 0", fontSize: 13, color: "#a8a8b2" }}>Your phrase stays in this browser, encrypted with your password (PBKDF2, AES-256-GCM). It derives the public account key and the ML-DSA-44 key.</p>
        <div style={{ display: "flex", gap: 6, marginTop: 16 }}>
          {existing && <button style={btn(mode === "unlock")} onClick={() => setMode("unlock")}>Unlock</button>}
          <button style={btn(mode === "create")} onClick={() => { setMode("create"); setPhrase(newMnemonic()); }}>New wallet</button>
          <button style={btn(mode === "import")} onClick={() => { setMode("import"); setPhrase(""); }}>Import phrase</button>
        </div>
        {mode !== "unlock" && (
          <label style={{ display: "block", marginTop: 16 }}>
            <span style={label}>{mode === "create" ? "Your new recovery phrase — write it down, it is shown once" : "Recovery phrase"}</span>
            <textarea style={{ ...input, minHeight: 72 }} value={phrase} onChange={(e) => setPhrase(e.target.value)} readOnly={mode === "create"} />
          </label>
        )}
        <label style={{ display: "block", marginTop: 16 }}><span style={label}>Password</span><input style={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void go()} /></label>
        {mode !== "unlock" && <label style={{ display: "block", marginTop: 12 }}><span style={label}>Confirm password</span><input style={input} type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void go()} /></label>}
        {err && <div style={{ marginTop: 12, padding: "9px 11px", borderRadius: 8, background: "#2a1113", border: "1px solid #5c1d22", color: "#ff9ea6", fontSize: 13 }}>{err}</div>}
        <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginTop: 18 }}>
          {existing ? <button style={btn()} onClick={() => { if (window.confirm("Forget the stored phrase on this browser?")) { clearKeystore(); location.reload(); } }}>Forget this wallet</button> : <span />}
          <button style={btn(true)} disabled={busy} onClick={() => void go()}>{busy ? "…" : mode === "unlock" ? "Unlock" : "Save and open"}</button>
        </div>
      </div>
    </div>
  );
}
