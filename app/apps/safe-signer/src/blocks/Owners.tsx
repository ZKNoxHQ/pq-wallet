// Block 3 — the post-quantum owners of S_pq, and the 32 bytes each one signs.
//
// The digest is the point of this screen. A holder compares it to what the device shows and nothing else;
// everything around it is there to make that comparison possible and to say, before the device comes out,
// whether this holder's key is the one the clone will accept — `keccak256(expanded key)` against the
// clone's stored `postQKeyHash`. A mismatch caught here costs a second, caught on chain it costs a
// 3.9 M gas revert.
import React, { useState } from "react";
import { keccak256, size, type Address, type Hex } from "viem";
import { MLDSA65, pasteAnswer, type PqAnswer, type PqOwnerInfo, type Signer } from "@zknox/pq-safe";
import { Addr, Card, Copy, Digest, Note, Row, Spinner, bytes } from "../parts";
import { C, button, input, label, mono, short } from "../theme";

export type Answers = Record<Address, PqAnswer>;

const Pill: React.FC<{ tone: "ok" | "warn" | "bad" | "dim"; children: React.ReactNode }> = ({ tone, children }) => (
  <span
    style={{
      ...mono(10), textTransform: "uppercase", letterSpacing: 0.6, padding: "2px 7px", borderRadius: 5,
      color: tone === "dim" ? C.faint : C[tone], background: "#0e0e10", border: `1px solid ${C.panelEdge}`,
    }}
  >
    {children}
  </span>
);

const Owner: React.FC<{
  info: PqOwnerInfo;
  digest: Hex;
  answer?: PqAnswer;
  signers: Signer[];
  onAnswer: (a: PqAnswer) => void;
  onForget: () => void;
}> = ({ info, digest, answer, signers, onAnswer, onForget }) => {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [paste, setPaste] = useState({ k1Address: "", k1Signature: "", expandedKey: "", pqSignature: "" });

  const signLocally = async (s: Signer) => {
    setErr(null);
    setBusy(s.id);
    try {
      const { postQKeyHash } = await s.keyHashes();
      if (postQKeyHash.toLowerCase() !== info.postQKeyHash.toLowerCase()) {
        throw new Error(
          `this holder's key hashes to ${short(postQKeyHash, 10, 8)}, the clone stores ${short(info.postQKeyHash, 10, 8)} — it is not an owner of this account`,
        );
      }
      onAnswer(await s.sign(info.address, digest));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const takePaste = () => {
    setErr(null);
    try {
      const a = pasteAnswer({
        owner: info.address,
        k1Address: paste.k1Address as Address,
        k1Signature: paste.k1Signature as Hex,
        expandedKey: paste.expandedKey as Hex,
        pqSignature: paste.pqSignature as Hex,
      });
      if (keccak256(a.expandedKey).toLowerCase() !== info.postQKeyHash.toLowerCase()) {
        throw new Error("the expanded key does not hash to the clone's stored postQKeyHash");
      }
      if (keccak256(a.k1Address).toLowerCase() !== info.preQKeyHash.toLowerCase()) {
        throw new Error("the k1 address does not hash to the clone's stored preQKeyHash");
      }
      onAnswer(a);
      setOpen(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const usable = info.kind === "PQ_CLONE" || (info.kind === "unknown" && info.initialized);

  return (
    <div
      style={{
        border: `1px solid ${answer ? C.violetDim : C.panelEdge}`,
        borderRadius: 10, padding: "14px 16px", background: "#101013",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <Addr value={info.address} full />
        {answer ? <Pill tone="ok">signed</Pill> : <Pill tone="dim">waiting</Pill>}
        {info.kind !== "unknown" && info.kind !== "PQ_CLONE" && <Pill tone="bad">{info.kind}</Pill>}
        {!info.initialized && <Pill tone="bad">not initialized</Pill>}
        <span style={{ marginLeft: "auto" }} />
        {answer ? (
          <button style={{ ...button("ghost"), padding: "5px 11px", fontSize: 11 }} onClick={onForget}>
            discard
          </button>
        ) : (
          <button
            style={{ ...button("ghost"), padding: "5px 11px", fontSize: 11 }}
            onClick={() => setOpen(!open)}
            disabled={!usable}
          >
            {open ? "close" : "sign"}
          </button>
        )}
      </div>

      <div style={{ marginTop: 12 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <Digest value={digest} title="this owner signs" />
          </div>
          <Copy value={digest} />
        </div>
        <p style={{ margin: "7px 0 0", fontSize: 11, color: C.faint, lineHeight: 1.5 }}>
          Check these 64 characters against the device screen before approving. Both halves of the hybrid
          signature — secp256k1 and ML-DSA-65 — are made over this one value.
        </p>
      </div>

      {answer && (
        <div style={{ marginTop: 10 }}>
          <Row k="k1 key">
            <Addr value={answer.k1Address} full />
          </Row>
          <Row k="expanded key">
            {bytes(size(answer.expandedKey))} · hashes to {short(keccak256(answer.expandedKey), 10, 8)}
          </Row>
          <Row k="ML-DSA-65 signature">{bytes(size(answer.pqSignature))}</Row>
        </div>
      )}

      {open && !answer && (
        <div style={{ marginTop: 14, borderTop: `1px solid ${C.panelEdge}`, paddingTop: 12 }}>
          {signers.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <span style={label}>software holder (development)</span>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {signers.map((s) => (
                  <button key={s.id} style={button()} onClick={() => void signLocally(s)} disabled={!!busy}>
                    {busy === s.id ? "signing…" : s.id.split(":")[0]}
                  </button>
                ))}
                {busy && <Spinner />}
              </div>
            </div>
          )}
          <span style={label}>from a device</span>
          <div style={{ display: "grid", gap: 8 }}>
            {(
              [
                ["k1 address", "k1Address", "0x… 20 bytes"],
                ["k1 signature", "k1Signature", "0x… 65 bytes"],
                ["ML-DSA-65 signature", "pqSignature", `0x… ${MLDSA65.sigBytes} bytes`],
                ["expanded ML-DSA-65 key", "expandedKey", `0x… ${MLDSA65.keyBytes} bytes`],
              ] as const
            ).map(([name, key, hint]) => (
              <label key={key} style={{ display: "block" }}>
                <span style={label}>{name}</span>
                <textarea
                  style={{ ...input, minHeight: key === "expandedKey" ? 64 : 38, resize: "vertical" }}
                  placeholder={hint}
                  value={paste[key]}
                  spellCheck={false}
                  onChange={(e) => setPaste({ ...paste, [key]: e.target.value.trim() })}
                />
              </label>
            ))}
          </div>
          <button style={{ ...button(), marginTop: 10 }} onClick={takePaste}>
            take this signature
          </button>
        </div>
      )}

      {err && <Note tone="bad">{err}</Note>}
    </div>
  );
};

export const Owners: React.FC<{
  owners: PqOwnerInfo[];
  digests: { owner: Address; digest: Hex }[];
  answers: Answers;
  signers: Signer[];
  k: number;
  pqSafeTxHash: Hex;
  onAnswer: (a: PqAnswer) => void;
  onForget: (owner: Address) => void;
}> = ({ owners, digests, answers, signers, k, pqSafeTxHash, onAnswer, onForget }) => {
  const have = Object.keys(answers).length;
  const byOwner = new Map(digests.map((d) => [d.owner.toLowerCase(), d.digest]));
  return (
    <Card
      step={3}
      title="The post-quantum owners"
      note={`${have} of ${k} needed · ${owners.length} owners`}
    >
      <div
        style={{
          height: 4, borderRadius: 2, background: "#1d1d22", overflow: "hidden", marginBottom: 16,
        }}
      >
        <div
          style={{
            height: "100%", width: `${Math.min(100, (have / Math.max(1, k)) * 100)}%`,
            background: `linear-gradient(90deg, ${C.violetDim}, ${C.violet})`, transition: "width 240ms",
          }}
        />
      </div>

      <p style={{ margin: "0 0 14px", fontSize: 12, color: C.dim, lineHeight: 1.55 }}>
        Each owner signs one EIP-712 wrap of S_pq's own transaction —{" "}
        <span style={mono(12)}>{short(pqSafeTxHash, 10, 8)}</span>, which calls{" "}
        <span style={mono(12)}>root.approveHash</span>. It is not the three-layer digest of the
        single-transaction path; handing a device the wrong one of the two produces a signature the Safe
        rejects without saying why.
      </p>

      <div style={{ display: "grid", gap: 12 }}>
        {owners.map((info) => {
          const digest = byOwner.get(info.address.toLowerCase());
          if (!digest) return null;
          return (
            <Owner
              key={info.address}
              info={info}
              digest={digest}
              answer={answers[info.address]}
              signers={signers}
              onAnswer={onAnswer}
              onForget={() => onForget(info.address)}
            />
          );
        })}
      </div>

      {have > k && (
        <Note>
          {have} signatures for a threshold of {k}: every extra one adds {bytes(41921)} to the transaction
          and some 1.1 M gas. Discard the ones you do not need.
        </Note>
      )}
    </Card>
  );
};
