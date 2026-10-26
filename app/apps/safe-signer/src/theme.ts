// The palette of the wallet demo (packages/ui), so the two read as one thing.
import type { CSSProperties } from "react";

export const C = {
  bg: "#0b0b0c",
  panel: "#141417",
  panelEdge: "#26262c",
  text: "#ececed",
  dim: "#9a9aa2",
  faint: "#6b6b74",
  violet: "#7c3aed",
  violetDim: "#5b21b6",
  link: "#c9aefc",
  ok: "#34d399",
  warn: "#fbbf24",
  bad: "#f87171",
} as const;

export const MONO =
  'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';
export const SANS =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif';

export const CSS = `html, body { margin: 0; background: ${C.bg}; color: ${C.text};
    font-family: ${SANS}; -webkit-font-smoothing: antialiased; }
  * { box-sizing: border-box; }
  a { color: ${C.link}; text-decoration: none; }
  a:hover { text-decoration: underline; }
  button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
    outline: 2px solid #8b5cf6; outline-offset: 2px; }
  input, textarea, select { font-family: ${MONO}; }
  ::selection { background: #4c1d95; color: #fff; }
  @keyframes pqspin { to { transform: rotate(360deg); } }
  .pq-spin { animation: pqspin 0.9s linear infinite; }
  @media (prefers-reduced-motion: reduce) { .pq-spin { animation: none; } }
`;

export const card: CSSProperties = {
  background: C.panel,
  border: `1px solid ${C.panelEdge}`,
  borderRadius: 12,
  padding: "18px 20px 20px",
};

export const label: CSSProperties = {
  display: "block",
  fontSize: 11,
  letterSpacing: 0.6,
  textTransform: "uppercase",
  color: C.faint,
  marginBottom: 6,
};

export const input: CSSProperties = {
  width: "100%",
  background: "#0e0e10",
  border: `1px solid ${C.panelEdge}`,
  borderRadius: 8,
  color: C.text,
  fontSize: 13,
  padding: "9px 11px",
};

export const button = (kind: "primary" | "ghost" | "danger" = "primary"): CSSProperties => ({
  border: kind === "primary" ? "none" : `1px solid ${C.panelEdge}`,
  borderRadius: 8,
  padding: "9px 16px",
  fontSize: 13,
  fontWeight: 600,
  fontFamily: SANS,
  cursor: "pointer",
  color: kind === "danger" ? C.bad : kind === "primary" ? "#fff" : C.text,
  background:
    kind === "primary" ? `linear-gradient(180deg, ${C.violet}, ${C.violetDim})` : "transparent",
});

export const mono = (size = 12): CSSProperties => ({ fontFamily: MONO, fontSize: size });

/** An address or a hash, shortened. Never used for a digest a signer has to compare. */
export const short = (s?: string | null, head = 6, tail = 4) =>
  s ? `${s.slice(0, head)}…${s.slice(-tail)}` : "";

export const groups = (hex: string) => (hex.replace(/^0x/, "").match(/.{1,8}/g) ?? []).join(" ");
