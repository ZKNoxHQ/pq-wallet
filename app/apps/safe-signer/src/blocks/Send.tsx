// Block 4 — what leaves, and how big it is.
//
// An 84 kB transaction is unusual enough that nobody should discover it after signing: the size, the
// EIP-7623 floor and the node's own estimate are on screen before the send button does anything. The
// transaction goes straight to an RPC — the Safe Transaction Service caps a confirmation signature at 5,000
// bytes, so this payload has no way through the API or the SDK.
import React from "react";
import { size, type Hex } from "viem";
import { calldataGas, fitsInMempool, TXPOOL_LIMIT } from "@zknox/pq-safe";
import { Card, Copy, Note, Row, Spinner, bytes, gas } from "../parts";
import { C, button, mono } from "../theme";

export type SendState =
  | { phase: "idle" }
  | { phase: "estimating" }
  | { phase: "sending" }
  | { phase: "sent"; hash: Hex }
  | { phase: "failed"; error: string };

export const Send: React.FC<{
  data: Hex | null;
  to: string | null;
  estimate: bigint | null;
  estimateError: string | null;
  state: SendState;
  ready: boolean;
  missing: number;
  canSend: boolean;
  relayer: string | null;
  explorer: string | null;
  onEstimate: () => void;
  onSend: () => void;
  onDownload: () => void;
  /** inside Safe{Wallet}: reads go through the host, broadcasting does not */
  hosted?: boolean;
  castCommand: string | null;
}> = ({
  data, to, estimate, estimateError, state, ready, missing, canSend, relayer, explorer, onEstimate,
  onSend, onDownload, hosted, castCommand,
}) => {
  const g = data ? calldataGas(data) : null;
  const fits = data ? fitsInMempool(data) : true;
  return (
    <Card step={4} title="Send S_pq's approval" note={to ? `to ${to.slice(0, 10)}…` : undefined}>
      {!ready ? (
        <p style={{ margin: 0, fontSize: 13, color: C.dim }}>
          {missing} more post-quantum {missing === 1 ? "signature" : "signatures"} and this becomes a
          transaction.
        </p>
      ) : (
        <>
          <Row k="calldata">{g && `${bytes(g.bytes)} — ${gas(g.bytes)} bytes`}</Row>
          <Row k="EIP-7623 floor">{g && `${gas(g.floor)} gas`}</Row>
          <Row k="intrinsic cost">{g && `${gas(g.intrinsic)} gas`}</Row>
          <Row k="node estimate">
            {estimate ? (
              `${gas(estimate)} gas`
            ) : state.phase === "estimating" ? (
              <Spinner />
            ) : (
              <button style={{ ...button("ghost"), padding: "3px 10px", fontSize: 11 }} onClick={onEstimate}>
                ask the node
              </button>
            )}
          </Row>
          {estimateError && <Note tone="bad">{estimateError}</Note>}

          <Note tone={fits ? "warn" : "bad"}>
            {fits ? (
              <>
                This transaction carries {g && bytes(g.bytes)} of calldata — the expanded ML-DSA-65 key of
                every signer travels in it. That is some fifty times an ordinary Safe transaction. It is
                sent straight to the RPC: no Safe API, no bundler, and no wallet UI will show it as a
                pending Safe transaction.
              </>
            ) : (
              <>
                {g && bytes(g.bytes)} is past the {bytes(TXPOOL_LIMIT)} a node will relay. geth, reth and
                nethermind all refuse it — which is what caps the threshold at three post-quantum signers on
                this path. Discard a signature, or execute in one transaction from a node you control.
              </>
            )}
          </Note>

          {hosted && (
            <Note>
              Safe&#123;Wallet&#125; proxies the reads that filled this page, but its app interface has no
              <span style={mono(12)}> eth_sendRawTransaction</span>, and its own "send" would propose a
              transaction from the Safe you are looking at — which for S_pq is the transaction being built
              here. So this last step leaves the frame: a wallet, a relayer key, or the file below.
            </Note>
          )}

          <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 14, flexWrap: "wrap" }}>
            <button style={button()} onClick={onSend} disabled={!canSend || state.phase === "sending" || !fits}>
              {state.phase === "sending" ? "sending…" : relayer ? `send from ${relayer}` : "connect a relayer"}
            </button>
            {state.phase === "sending" && <Spinner />}
            <button style={button("ghost")} onClick={onDownload} disabled={!canSend}>
              download the transaction
            </button>
            {data && <Copy value={data} what="calldata copied" />}
          </div>

          {state.phase === "sent" && (
            <Note tone="ok">
              Sent.{" "}
              {explorer ? (
                <a href={`${explorer}/tx/${state.hash}`} target="_blank" rel="noreferrer">
                  {state.hash}
                </a>
              ) : (
                <span style={mono(12)}>{state.hash}</span>
              )}
              <br />
              Once S_ecdsa has approved the same hash, the root executes with a 130-byte signature — an
              ordinary Safe transaction, from Safe&#123;Wallet&#125; or anywhere else.
            </Note>
          )}
          {state.phase === "failed" && <Note tone="bad">{state.error}</Note>}

          {castCommand && (
            <details style={{ marginTop: 14 }}>
              <summary style={{ fontSize: 12, color: C.dim, cursor: "pointer" }}>
                send it from somewhere else
              </summary>
              <p style={{ fontSize: 11, color: C.faint, margin: "8px 0 6px", lineHeight: 1.5 }}>
                The relayer pays the gas and authorizes nothing, so it can be any account anywhere. The
                calldata is {data && bytes(size(data))}; some RPC providers cap a request body below that
                (Alchemy at 2.6 MB is fine, a few are not).
              </p>
              <pre
                style={{
                  ...mono(11), background: "#0e0e10", border: `1px solid ${C.panelEdge}`, borderRadius: 8,
                  padding: "10px 12px", overflowX: "auto", margin: 0, color: C.dim,
                }}
              >
                {castCommand}
              </pre>
            </details>
          )}
        </>
      )}
    </Card>
  );
};
