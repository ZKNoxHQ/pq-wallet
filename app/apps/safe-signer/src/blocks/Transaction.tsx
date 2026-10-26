// Block 2 — which transaction is being authorized.
//
// Three ways in, and they are not equally trustworthy, so the screen says which one is in use:
//   fields   the transaction is retyped here and its hash derived, then confirmed against the Safe itself
//   service  it is read from the Safe Transaction Service by nonce, then confirmed the same way
//   hash     only the hash was passed on. Everything below still works, but nobody here can say what it
//            authorizes — that has to be read in Safe{Wallet}.
import React from "react";
import { formatEther, type Address, type Hex } from "viem";
import type { ProposedTx, SafeTx } from "@zknox/pq-safe";
import { Addr, Card, Copy, Digest, Field, Grid, Note, Row, Spinner } from "../parts";
import { C, button, mono } from "../theme";

export type TxSource =
  | { mode: "fields"; to: string; value: string; data: string; nonce: string }
  | { mode: "hash"; hash: string }
  | { mode: "service"; chosen?: Hex };

export const Transaction: React.FC<{
  src: TxSource;
  onChange: (s: TxSource) => void;
  pending: ProposedTx[] | null;
  pendingError: string | null;
  loadingPending: boolean;
  onLoadPending: () => void;
  rootTx: SafeTx | null;
  rootSafeTxHash: Hex | null;
  confirmed: { onChain: Hex; agrees: boolean } | null;
  approvals: Record<Address, boolean> | null;
  sEcdsa: Address;
  sPq: Address;
  serviceAvailable: boolean;
}> = ({
  src, onChange, pending, pendingError, loadingPending, onLoadPending, rootTx, rootSafeTxHash,
  confirmed, approvals, sEcdsa, sPq, serviceAvailable,
}) => {
  const tab = (mode: TxSource["mode"], text: string) => (
    <button
      key={mode}
      onClick={() =>
        onChange(
          mode === "fields"
            ? { mode, to: "", value: "0", data: "0x", nonce: "" }
            : mode === "hash"
              ? { mode, hash: "" }
              : { mode },
        )
      }
      style={{
        ...button("ghost"),
        padding: "6px 12px",
        fontSize: 12,
        borderColor: src.mode === mode ? C.violet : C.panelEdge,
        color: src.mode === mode ? C.link : C.dim,
      }}
    >
      {text}
    </button>
  );

  return (
    <Card step={2} title="The transaction the root will execute">
      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        {tab("fields", "type it in")}
        {tab("service", "from Safe")}
        {tab("hash", "hash only")}
      </div>

      {src.mode === "fields" && (
        <Grid>
          <Field name="to" value={src.to} onChange={(to) => onChange({ ...src, to })} placeholder="0x…" />
          <Field name="value (ETH)" value={src.value} onChange={(value) => onChange({ ...src, value })} />
          <Field name="nonce" value={src.nonce} onChange={(nonce) => onChange({ ...src, nonce })}
            hint="the root's nonce for this transaction" />
          <Field name="data" value={src.data} onChange={(data) => onChange({ ...src, data })} wide
            placeholder="0x" />
        </Grid>
      )}

      {src.mode === "hash" && (
        <>
          <Field name="root safeTxHash" value={src.hash} onChange={(hash) => onChange({ mode: "hash", hash })}
            placeholder="0x…" wide />
          <Note>
            With the hash alone, this screen cannot tell you what the transaction does. Read it in
            Safe&#123;Wallet&#125; before anyone signs — every digest below is derived from these 32 bytes,
            so a wrong hash produces signatures for a transaction nobody looked at.
          </Note>
        </>
      )}

      {src.mode === "service" && (
        <>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <button style={button()} onClick={onLoadPending} disabled={loadingPending || !serviceAvailable}>
              {loadingPending ? "reading…" : "list what is pending"}
            </button>
            {loadingPending && <Spinner />}
            {!serviceAvailable && (
              <span style={{ fontSize: 12, color: C.faint }}>no Transaction Service for this chain</span>
            )}
          </div>
          {pendingError && <Note tone="bad">{pendingError}</Note>}
          {pending && pending.length === 0 && <Note>Nothing pending on the root.</Note>}
          {pending && pending.length > 0 && (
            <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
              {pending.map((p) => (
                <button
                  key={p.safeTxHash}
                  onClick={() => onChange({ mode: "service", chosen: p.safeTxHash })}
                  style={{
                    ...button("ghost"), textAlign: "left", padding: "10px 12px",
                    borderColor: src.chosen === p.safeTxHash ? C.violet : C.panelEdge,
                  }}
                >
                  <span style={{ ...mono(12), color: C.text }}>
                    nonce {String(p.tx.nonce)} · {formatEther(p.tx.value ?? 0n)} ETH →{" "}
                    <Addr value={p.tx.to} />
                  </span>
                  <span style={{ display: "block", fontSize: 11, color: C.faint, marginTop: 3 }}>
                    {p.confirmations.length} of {p.confirmationsRequired} confirmations ·{" "}
                    {((p.tx.data ?? "0x").length - 2) / 2} bytes of data
                  </span>
                </button>
              ))}
            </div>
          )}
        </>
      )}

      {rootSafeTxHash && (
        <div style={{ marginTop: 16, borderTop: `1px solid ${C.panelEdge}`, paddingTop: 14 }}>
          {rootTx && (
            <>
              <Row k="to">
                <Addr value={rootTx.to} full />
              </Row>
              <Row k="value">{formatEther(rootTx.value ?? 0n)} ETH</Row>
              <Row k="data">
                {((rootTx.data ?? "0x").length - 2) / 2 === 0
                  ? "none"
                  : `${((rootTx.data ?? "0x").length - 2) / 2} bytes`}
              </Row>
              <Row k="nonce">{String(rootTx.nonce)}</Row>
            </>
          )}
          <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginTop: 10 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <Digest value={rootSafeTxHash} title="root safeTxHash" />
            </div>
            <Copy value={rootSafeTxHash} />
          </div>
          {confirmed && !confirmed.agrees && (
            <Note tone="bad">
              The Safe computes {confirmed.onChain} for these fields, this screen computes {rootSafeTxHash}.
              Nothing below is usable until they agree — the Safe's version or domain is not what was
              assumed.
            </Note>
          )}
          {confirmed?.agrees && (
            <Note tone="ok">The Safe's own getTransactionHash returns the same 32 bytes.</Note>
          )}
          {approvals && (
            <Row k="already approved">
              S_ecdsa {approvals[sEcdsa] ? "yes" : "not yet"} · S_pq {approvals[sPq] ? "yes" : "not yet"}
            </Row>
          )}
        </div>
      )}
    </Card>
  );
};
