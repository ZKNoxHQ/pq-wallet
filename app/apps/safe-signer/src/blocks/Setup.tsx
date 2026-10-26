// Block 1 — the arrangement. Which Safe is executing, which two Safes own it, and whether the policy that
// makes the whole thing worth doing actually holds right now.
import React, { useState } from "react";
import type { Loaded, Config } from "../session";
import type { Discovery } from "../safeApp";
import { Addr, Card, Field, Grid, Note, Row, Spinner } from "../parts";
import { C, button, mono, short } from "../theme";

export const Setup: React.FC<{
  draft: Partial<Config>;
  onChange: (c: Partial<Config>) => void;
  loaded: Loaded | null;
  error: string | null;
  busy: boolean;
  onReload: () => void;
  link: string | null;
  /** inside Safe{Wallet}: the host names the Safe and proxies the RPC */
  hosted?: boolean;
  discovery?: Discovery | null;
  safeName?: string | null;
}> = ({ draft, onChange, loaded, error, busy, onReload, link, hosted, discovery, safeName }) => {
  const set = (k: keyof Config) => (v: string) => onChange({ ...draft, [k]: v || undefined });
  const [manual, setManual] = useState(false);
  const auto = hosted && discovery?.kind === "root" && !manual;
  return (
    <Card step={1} title="The arrangement" note={loaded ? `chain ${draft.chainId}` : undefined}>
      {hosted && (
        <div style={{ marginBottom: auto ? 2 : 14 }}>
          {!discovery ? (
            <Row k="Safe{Wallet}">
              <Spinner /> reading {safeName ? short(safeName, 10, 8) : "the Safe"}
            </Row>
          ) : discovery.kind === "root" ? (
            <Note tone="ok">
              Opened on the root of a nested arrangement. Both children were found on chain, and the one
              whose owners answer <span style={mono(12)}>keyHashes()</span> is S_pq. Nothing to fill in.
            </Note>
          ) : discovery.kind === "sPq" ? (
            <Note>
              Opened on S_pq itself. Its {draft.k} of {loaded?.sPq.owners.length ?? "?"} post-quantum owners
              are known, but a Safe cannot be asked who owns it: give the root below, once.
            </Note>
          ) : (
            <Note tone="bad">
              This Safe is not part of a nested post-quantum arrangement — {discovery.reason}. Open the app
              on the root, or fill the addresses in by hand.
            </Note>
          )}
          {discovery && discovery.kind === "root" && (
            <button
              style={{ ...button("ghost"), padding: "4px 10px", fontSize: 11, marginTop: 10 }}
              onClick={() => setManual(!manual)}
            >
              {manual ? "use what was found" : "override"}
            </button>
          )}
        </div>
      )}

      {!auto && (
      <Grid>
        <Field name="root Safe" value={draft.root ?? ""} onChange={set("root")} placeholder="0x…" />
        <Field name="S_ecdsa" value={draft.sEcdsa ?? ""} onChange={set("sEcdsa")} placeholder="0x…"
          hint="the child whose owners are EOAs" />
        <Field name="S_pq" value={draft.sPq ?? ""} onChange={set("sPq")} placeholder="0x…"
          hint="the child whose owners are post-quantum clones" />
        {!hosted && (
          <Field name="RPC" value={draft.rpcUrl ?? ""} onChange={set("rpcUrl")} placeholder="https://…" />
        )}
        <Field name="threshold k" value={String(draft.k ?? "")} onChange={set("k")} />
        <Field name="lens (optional)" value={draft.lens ?? ""} onChange={set("lens")} placeholder="0x…"
          hint="ZKNOX_SafePQLens, to check the policy" />
        <Field name="PQ implementation (optional)" value={draft.pqImplementation ?? ""}
          onChange={set("pqImplementation")} placeholder="0x…" hint="factory.IMPLEMENTATION()" />
      </Grid>
      )}

      <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 14 }}>
        <button style={button()} onClick={onReload} disabled={busy}>
          {busy ? "reading…" : loaded ? "re-read" : "read the chain"}
        </button>
        {busy && <Spinner />}
        {link && (
          <a href={link} style={{ fontSize: 12, marginLeft: "auto" }}>
            link for the other holders
          </a>
        )}
      </div>

      {error && <Note tone="bad">{error}</Note>}

      {loaded && (
        <div style={{ marginTop: 16, borderTop: `1px solid ${C.panelEdge}`, paddingTop: 12 }}>
          <Row k="root">
            <Addr value={loaded.root.address} full /> · Safe {loaded.root.version} ·{" "}
            {loaded.root.threshold} of {loaded.root.owners.length} · nonce {String(loaded.root.nonce)}
          </Row>
          <Row k="S_ecdsa">
            Safe {loaded.sEcdsa.version} · {loaded.sEcdsa.threshold} of {loaded.sEcdsa.owners.length} EOAs ·
            nonce {String(loaded.sEcdsa.nonce)}
          </Row>
          <Row k="S_pq">
            Safe {loaded.sPq.version} · {loaded.sPq.threshold} of {loaded.sPq.owners.length} clones · nonce{" "}
            {String(loaded.sPq.nonce)}
          </Row>
          {loaded.violations === null ? (
            <Note>
              The policy was not checked: give a lens address and the implementation the clones are cloned
              from, and this screen can say whether a broken post-quantum verifier would still leave k
              classical signatures required.
            </Note>
          ) : loaded.violations.length === 0 ? (
            <Note tone="ok">
              The NESTED policy holds: every accepted signature set needs {draft.k} of{" "}
              {loaded.sEcdsa.owners.length} EOA owners and {draft.k} of {loaded.sPq.owners.length}{" "}
              post-quantum owners.
            </Note>
          ) : (
            <Note tone="bad">
              {loaded.violations.length === 1 ? "One thing breaks" : `${loaded.violations.length} things break`}{" "}
              the policy — signing is still possible, the guarantee is not what it claims:
              <br />
              {loaded.violations.map((v) => `— ${v}`).join("\n")}
            </Note>
          )}
          {loaded.root.owners.length === 2 &&
            !loaded.root.owners.map((o) => o.toLowerCase()).includes((draft.sPq ?? "").toLowerCase()) && (
              <Note tone="bad">
                S_pq is not an owner of the root: the root's owners are{" "}
                {loaded.root.owners.map((o) => short(o)).join(" and ")}.
              </Note>
            )}
        </div>
      )}
    </Card>
  );
};
