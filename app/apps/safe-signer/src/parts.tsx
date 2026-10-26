// Small pieces the four blocks share.
import React, { useState } from "react";
import { button, C, card, groups, input, label, mono, short } from "./theme";

export const Card: React.FC<{ step?: number; title: string; note?: string; children: React.ReactNode }> = ({
  step, title, note, children,
}) => (
  <section style={{ ...card, marginBottom: 16 }}>
    <header style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 14 }}>
      {step !== undefined && (
        <span
          style={{
            ...mono(11), width: 20, height: 20, borderRadius: 6, flex: "none",
            background: "#1d1d22", color: C.link, display: "grid", placeItems: "center",
          }}
        >
          {step}
        </span>
      )}
      <h2 style={{ margin: 0, fontSize: 15, fontWeight: 600 }}>{title}</h2>
      {note && <span style={{ fontSize: 12, color: C.faint, marginLeft: "auto" }}>{note}</span>}
    </header>
    {children}
  </section>
);

export const Field: React.FC<{
  name: string; value: string; onChange: (v: string) => void;
  placeholder?: string; hint?: string; wide?: boolean; disabled?: boolean;
}> = ({ name, value, onChange, placeholder, hint, wide, disabled }) => (
  <div style={{ gridColumn: wide ? "1 / -1" : undefined, minWidth: 0 }}>
    <span style={label}>{name}</span>
    <input
      style={input} value={value} placeholder={placeholder} disabled={disabled} spellCheck={false}
      onChange={(e) => onChange(e.target.value.trim())}
    />
    {hint && <p style={{ margin: "5px 0 0", fontSize: 11, color: C.faint }}>{hint}</p>}
  </div>
);

export const Grid: React.FC<{ children: React.ReactNode; cols?: string }> = ({ children, cols }) => (
  <div style={{ display: "grid", gap: 12, gridTemplateColumns: cols ?? "repeat(auto-fit, minmax(230px, 1fr))" }}>
    {children}
  </div>
);

export const Row: React.FC<{ k: string; children: React.ReactNode }> = ({ k, children }) => (
  <div style={{ display: "flex", gap: 12, padding: "5px 0", fontSize: 12, alignItems: "baseline" }}>
    <span style={{ color: C.faint, flex: "none", width: 150 }}>{k}</span>
    <span style={{ ...mono(12), color: C.text, wordBreak: "break-all", minWidth: 0 }}>{children}</span>
  </div>
);

export const Note: React.FC<{ tone?: "warn" | "bad" | "ok"; children: React.ReactNode }> = ({
  tone = "warn", children,
}) => (
  <p
    style={{
      margin: "12px 0 0", fontSize: 12, lineHeight: 1.5, padding: "9px 12px", borderRadius: 8,
      color: C[tone], background: tone === "ok" ? "#0d1f18" : tone === "bad" ? "#20100f" : "#1e1709",
      border: `1px solid ${tone === "ok" ? "#14402e" : tone === "bad" ? "#3f1d1b" : "#3d2f0c"}`,
    }}
  >
    {children}
  </p>
);

export const Copy: React.FC<{ value: string; what?: string }> = ({ value, what = "copied" }) => {
  const [done, setDone] = useState(false);
  return (
    <button
      style={{ ...button("ghost"), padding: "4px 10px", fontSize: 11 }}
      onClick={() => {
        void navigator.clipboard?.writeText(value);
        setDone(true);
        setTimeout(() => setDone(false), 1400);
      }}
    >
      {done ? what : "copy"}
    </button>
  );
};

/** A 32-byte digest, laid out so it can be read against a device screen. Grouped in eights, both halves on
 *  their own line: comparing 64 hex characters by eye is the step everything else depends on. */
export const Digest: React.FC<{ value: string; title?: string }> = ({ value, title }) => {
  const g = groups(value);
  const half = Math.ceil(g.length / 2);
  return (
    <div>
      {title && <span style={label}>{title}</span>}
      <div
        style={{
          ...mono(13), lineHeight: 1.7, letterSpacing: 0.5, background: "#0e0e10",
          border: `1px solid ${C.panelEdge}`, borderRadius: 8, padding: "10px 12px", color: C.link,
        }}
      >
        <div>{g.slice(0, half).trim()}</div>
        <div>{g.slice(half).trim()}</div>
      </div>
    </div>
  );
};

export const Addr: React.FC<{ value: string; full?: boolean }> = ({ value, full }) => (
  <span style={mono(12)} title={value}>{full ? value : short(value, 10, 8)}</span>
);

export const Spinner = () => (
  <span
    className="pq-spin"
    style={{
      display: "inline-block", width: 11, height: 11, borderRadius: "50%",
      border: `2px solid ${C.violet}`, borderTopColor: "transparent",
    }}
  />
);

export const bytes = (n: number) =>
  n < 1024 ? `${n} B` : `${(n / 1024).toLocaleString("en-US", { maximumFractionDigits: 1 })} kB`;

export const gas = (n: number | bigint) => Number(n).toLocaleString("en-US");
