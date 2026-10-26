// safe-signer — collecting post-quantum owner signatures for a Safe, which is the one thing the Safe
// interface cannot do for us.
//
// Safe{Wallet} handles the rest: it proposes the root transaction, it produces the ECDSA child's approval
// by itself (it calls that an "on-chain signature"), and it executes the root once both children have
// approved. What has no place to go is a 41,824-byte ERC-1271 signature from a post-quantum owner — the
// Transaction Service caps a confirmation at 5,000 bytes. So this page covers exactly that gap: it derives
// the digest each holder signs, takes the answers back, assembles S_pq's own transaction and sends it to an
// RPC.
//
// Everything is recomputed locally from the Safe's parameters. A digest read from a service is a digest a
// holder cannot check, and checking it against the device screen is the only thing standing between a
// signature and the wrong transaction.
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  createWalletClient, custom, formatEther, getAddress, http, isHex, parseEther,
  type Address, type Hex, type PublicClient, type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  approveHashPlan, approveHashPlanFor, confirmSafeTxHash, pendingTransactions, pqChildTransaction,
  rootApprovedSignature, safeTxHash, type ApproveHashPlan, type NestedSafe, type PqAnswer, type ProposedTx,
  type SafeTx,
} from "@zknox/pq-safe";
import { Setup } from "./blocks/Setup";
import { Transaction, type TxSource } from "./blocks/Transaction";
import { Owners, type Answers } from "./blocks/Owners";
import { Send, type SendState } from "./blocks/Send";
import { Card, Note, Row, bytes } from "./parts";
import { C, CSS, button, mono, short } from "./theme";
import {
  approvals as readApprovals, clientFor, devSigners, initialConfig, isComplete, load, service, shareLink,
  chainFor, rpcUrlFor, type Config, type Loaded,
} from "./session";
import { connectSafeApp, discover, isFramed, safeAppTransport, type Discovery, type SafeAppContext } from "./safeApp";

const env = import.meta.env as Record<string, string | undefined>;
const EXPLORERS: Record<number, string> = {
  1: "https://etherscan.io",
  11155111: "https://sepolia.etherscan.io",
  42161: "https://arbiscan.io",
};

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export default function App() {
  const [draft, setDraft] = useState<Partial<Config>>(initialConfig);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // ---- Safe{Wallet} host, when this page is loaded as a custom Safe App
  const [host, setHost] = useState<SafeAppContext | null>(null);
  const [hostState, setHostState] = useState<"looking" | "standalone" | "hosted">(
    isFramed() ? "looking" : "standalone",
  );
  const [discovery, setDiscovery] = useState<Discovery | null>(null);

  const q = new URLSearchParams(location.search);
  const [src, setSrc] = useState<TxSource>(
    q.get("hash") ? { mode: "hash", hash: q.get("hash")! } : { mode: "fields", to: "", value: "0", data: "0x", nonce: "" },
  );
  const [pending, setPending] = useState<ProposedTx[] | null>(null);
  const [pendingErr, setPendingErr] = useState<string | null>(null);
  const [loadingPending, setLoadingPending] = useState(false);

  const [confirmed, setConfirmed] = useState<{ onChain: Hex; agrees: boolean } | null>(null);
  const [approved, setApproved] = useState<Record<Address, boolean> | null>(null);
  const [answers, setAnswers] = useState<Answers>({});
  const [estimate, setEstimate] = useState<bigint | null>(null);
  const [estimateErr, setEstimateErr] = useState<string | null>(null);
  const [sendState, setSendState] = useState<SendState>({ phase: "idle" });
  const [wallet, setWallet] = useState<{ client: WalletClient; address: Address } | null>(null);

  const hosted = hostState === "hosted" && !!host;
  const cfg = isComplete(draft, hosted) ? (draft as Config) : null;
  const transport = useMemo(() => (host ? safeAppTransport(host) : undefined), [host]);
  const client: PublicClient | null = useMemo(
    () => (cfg ? clientFor(cfg, transport) : null),
    [cfg?.rpcUrl, cfg?.chainId, transport],
  );
  const signers = useMemo(devSigners, []);

  // Connect to the host once, then let it say which Safe the user is looking at and work the rest out.
  useEffect(() => {
    if (hostState !== "looking") return;
    let live = true;
    void connectSafeApp().then((ctx) => {
      if (!live) return;
      if (!ctx) return setHostState("standalone");
      setHost(ctx);
      setHostState("hosted");
      setDraft((d) => ({ ...d, chainId: ctx.info.chainId, rpcUrl: rpcUrlFor(ctx.info.chainId) }));
    });
    return () => {
      live = false;
    };
  }, [hostState]);

  useEffect(() => {
    if (!host) return;
    const probe = clientFor(
      { ...(draft as Config), chainId: host.info.chainId },
      safeAppTransport(host),
    );
    let live = true;
    void discover(probe, getAddress(host.info.safeAddress))
      .then((d) => {
        if (!live) return;
        setDiscovery(d);
        if (d.kind === "root") {
          setDraft((prev) => ({ ...prev, chainId: host.info.chainId, root: d.root, sEcdsa: d.sEcdsa, sPq: d.sPq, k: d.k }));
        } else if (d.kind === "sPq") {
          setDraft((prev) => ({ ...prev, chainId: host.info.chainId, sPq: d.sPq, k: d.k }));
        }
      })
      .catch((e) => live && setDiscovery({ kind: "unrelated", reason: msg(e) }));
    return () => {
      live = false;
    };
  }, [host]);

  // ---- the arrangement
  const reload = useCallback(async () => {
    if (!cfg || !client) {
      setLoadErr("Give the root, both children, the threshold and an RPC.");
      return;
    }
    setLoading(true);
    setLoadErr(null);
    try {
      setLoaded(await load(client, cfg));
    } catch (e) {
      setLoaded(null);
      setLoadErr(msg(e));
    } finally {
      setLoading(false);
    }
  }, [cfg, client]);

  useEffect(() => {
    if (cfg && !loaded && !loading && !loadErr) void reload();
  }, [cfg, loaded, loading, loadErr, reload]);

  // ---- the root transaction, from whichever of the three sources is in use
  const rootTx: SafeTx | null = useMemo(() => {
    if (src.mode === "fields") {
      try {
        if (!src.to || src.nonce === "") return null;
        return {
          to: getAddress(src.to),
          value: parseEther(src.value || "0"),
          data: (src.data || "0x") as Hex,
          nonce: BigInt(src.nonce),
        };
      } catch {
        return null;
      }
    }
    if (src.mode === "service") return pending?.find((p) => p.safeTxHash === src.chosen)?.tx ?? null;
    return null;
  }, [src, pending]);

  const rootSafeTxHash: Hex | null = useMemo(() => {
    if (src.mode === "hash") return isHex(src.hash) && src.hash.length === 66 ? src.hash : null;
    if (src.mode === "service") return src.chosen ?? null;
    return cfg && rootTx ? safeTxHash(cfg.root, cfg.chainId, rootTx) : null;
  }, [src, rootTx, cfg]);

  // a locally derived hash is checked against the Safe's own; everything below depends on it
  useEffect(() => {
    setConfirmed(null);
    if (!client || !cfg || !rootTx) return;
    let live = true;
    void confirmSafeTxHash(client, cfg.root, cfg.chainId, rootTx)
      .then((r) => live && setConfirmed({ onChain: r.onChain, agrees: r.agrees }))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [client, cfg?.root, cfg?.chainId, rootTx]);

  useEffect(() => {
    setApproved(null);
    if (!client || !cfg || !rootSafeTxHash) return;
    let live = true;
    void readApprovals(client, cfg, rootSafeTxHash)
      .then((a) => live && setApproved(a))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [client, cfg?.root, rootSafeTxHash]);

  const loadPending = async () => {
    if (!cfg) return;
    const s = service(cfg);
    if (!s) return;
    setLoadingPending(true);
    setPendingErr(null);
    try {
      setPending(await pendingTransactions(s, cfg.root));
    } catch (e) {
      setPendingErr(msg(e));
    } finally {
      setLoadingPending(false);
    }
  };

  // ---- the plan: S_pq's own transaction, and one digest per owner
  const nested: NestedSafe | null =
    cfg && loaded ? { ...cfg, pqOwners: loaded.sPq.owners, k: loaded.sPq.threshold } : null;

  const plan: ApproveHashPlan | null = useMemo(() => {
    if (!nested || !loaded || !rootSafeTxHash) return null;
    return rootTx
      ? approveHashPlan(nested, rootTx, loaded.sPq.nonce)
      : approveHashPlanFor(nested, rootSafeTxHash, loaded.sPq.nonce);
  }, [nested, loaded?.sPq.nonce, rootSafeTxHash, rootTx]);

  // a changed plan invalidates every answer: they were made over the previous digest
  const planKey = plan?.pqSafeTxHash ?? "";
  useEffect(() => {
    setAnswers({});
    setEstimate(null);
    setEstimateErr(null);
    setSendState({ phase: "idle" });
  }, [planKey]);

  const k = loaded?.sPq.threshold ?? cfg?.k ?? 2;
  const chosen = useMemo(() => Object.values(answers).slice(0, k), [answers, k]);
  const ready = chosen.length >= k && !!plan && !!nested;

  const built = useMemo(() => {
    if (!ready || !nested || !plan) return null;
    try {
      return pqChildTransaction(nested, plan, chosen);
    } catch {
      return null;
    }
  }, [ready, nested, plan, chosen]);

  const estimateGas = async () => {
    if (!client || !built || !cfg) return;
    setEstimateErr(null);
    setSendState({ phase: "estimating" });
    try {
      setEstimate(
        await client.estimateGas({
          account: wallet?.address ?? "0x000000000000000000000000000000000000dEaD",
          to: built.to,
          data: built.data,
        }),
      );
      setSendState({ phase: "idle" });
    } catch (e) {
      setEstimateErr(msg(e));
      setSendState({ phase: "idle" });
    }
  };

  // ---- the relayer. It pays the gas and authorizes nothing, so any account will do.
  const connect = async () => {
    const injected = (window as unknown as { ethereum?: unknown }).ethereum;
    if (!cfg) return;
    const chain = chainFor(cfg.chainId);
    if (injected) {
      const c = createWalletClient({ chain, transport: custom(injected as never) });
      const [address] = await c.requestAddresses();
      setWallet({ client: c, address });
      return;
    }
    const key = env[`VITE_RELAYER_KEY_${cfg.chainId}`] as Hex | undefined;
    if (!key) {
      setSendState({
        phase: "failed",
        error: hosted
          ? "Safe{Wallet} proxies reads but not eth_sendRawTransaction, and no wallet is reachable from this frame. Download the transaction and send it from anywhere — the relayer pays the gas and authorizes nothing."
          : "No wallet in this browser and no relayer key configured. Copy the calldata below and send it from anywhere — the relayer authorizes nothing.",
      });
      return;
    }
    // A relayer key needs somewhere to broadcast, and the host does not offer that: an RPC URL has to be
    // configured for this chain. Falling back to a chain's public default would send the transaction
    // somewhere nobody chose.
    if (!cfg.rpcUrl) {
      setSendState({
        phase: "failed",
        error: `A relayer key is configured for chain ${cfg.chainId} but no RPC to broadcast on. Set VITE_RPC_URL_${cfg.chainId}, or download the transaction and send it yourself.`,
      });
      return;
    }
    const account = privateKeyToAccount(key);
    setWallet({
      client: createWalletClient({ account, chain, transport: http(cfg.rpcUrl) }),
      address: account.address,
    });
  };

  const send = async () => {
    if (!built || !cfg) return;
    if (!wallet) return void connect();
    setSendState({ phase: "sending" });
    try {
      const hash = await wallet.client.sendTransaction({
        account: wallet.client.account ?? wallet.address,
        chain: chainFor(cfg.chainId),
        to: built.to,
        data: built.data,
      });
      setSendState({ phase: "sent", hash });
      void reload();
    } catch (e) {
      setSendState({ phase: "failed", error: msg(e) });
    }
  };

  const castCommand =
    built && cfg
      ? `cast send ${built.to} \\\n  --rpc-url ${cfg.rpcUrl || "<your RPC>"} --ledger \\\n  --data <the ${bytes((built.data.length - 2) / 2)} from the file>`
      : null;

  /** The transaction as a file the user carries out of the frame. The Safe App sandbox allows downloads,
   *  which is the only way out when neither a wallet nor a relayer key is reachable. */
  const download = () => {
    if (!built || !cfg) return;
    const payload = {
      note: "S_pq approving the root's safeTxHash. The sender is a relayer: it pays the gas and authorizes nothing.",
      chainId: cfg.chainId,
      from: "any funded account",
      to: built.to,
      value: "0x0",
      data: built.data,
      rootSafeTxHash,
      bytes: (built.data.length - 2) / 2,
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `spq-approve-${(rootSafeTxHash ?? "0x").slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };

  return (
    <>
      <style>{CSS}</style>
      <main style={{ maxWidth: 880, margin: "0 auto", padding: "36px 20px 80px" }}>
        <header style={{ marginBottom: 26 }}>
          <h1 style={{ margin: 0, fontSize: 21, fontWeight: 650, letterSpacing: -0.2 }}>
            Post-quantum signatures for a Safe
          </h1>
          <p style={{ margin: "8px 0 0", fontSize: 13, color: C.dim, lineHeight: 1.6, maxWidth: 640 }}>
            Safe&#123;Wallet&#125; proposes the transaction and executes it. This page covers the one step it
            cannot carry: the 41.8 kB signature of each post-quantum owner, which it turns into S_pq's
            approval of the root's hash.
          </p>
        </header>

        <Setup
          draft={draft}
          onChange={(c) => {
            setDraft(c);
            setLoaded(null);
            setLoadErr(null);
          }}
          loaded={loaded}
          error={loadErr}
          busy={loading}
          onReload={() => void reload()}
          link={cfg ? shareLink(cfg, rootSafeTxHash ?? undefined) : null}
          hosted={hosted}
          discovery={hosted ? discovery : null}
          safeName={host?.info.safeAddress ?? null}
        />

        {cfg && (
          <Transaction
            src={src}
            onChange={setSrc}
            pending={pending}
            pendingError={pendingErr}
            loadingPending={loadingPending}
            onLoadPending={() => void loadPending()}
            rootTx={rootTx}
            rootSafeTxHash={rootSafeTxHash}
            confirmed={confirmed}
            approvals={approved}
            sEcdsa={cfg.sEcdsa}
            sPq={cfg.sPq}
            serviceAvailable={!!service(cfg)}
          />
        )}

        {loaded && plan && (
          <Owners
            owners={loaded.owners}
            digests={plan.digests}
            answers={answers}
            signers={signers}
            k={k}
            pqSafeTxHash={plan.pqSafeTxHash}
            onAnswer={(a: PqAnswer) => setAnswers((prev) => ({ ...prev, [a.owner]: a }))}
            onForget={(owner) =>
              setAnswers((prev) => {
                const next = { ...prev };
                delete next[owner];
                return next;
              })
            }
          />
        )}

        {loaded && plan && (
          <Send
            data={built?.data ?? null}
            to={built?.to ?? null}
            estimate={estimate}
            estimateError={estimateErr}
            state={sendState}
            ready={ready}
            missing={Math.max(0, k - chosen.length)}
            canSend={!!built}
            relayer={wallet ? short(wallet.address) : null}
            explorer={EXPLORERS[cfg?.chainId ?? 0] ?? null}
            onEstimate={() => void estimateGas()}
            onSend={() => void send()}
            onDownload={download}
            hosted={hosted}
            castCommand={castCommand}
          />
        )}

        {loaded && plan && (
          <Card title="Then, in Safe{Wallet}">
            <p style={{ margin: 0, fontSize: 13, color: C.dim, lineHeight: 1.6 }}>
              Two approvals of the same hash and the root executes with a 130-byte signature: two 65-byte
              approved-hash records, nothing else. That transaction is ordinary — propose it, let
              Safe&#123;Wallet&#125; produce S_ecdsa's approval as an "on-chain signature", and execute.
            </p>
            <div style={{ marginTop: 12 }}>
              <Row k="root signature">
                {nested && `${(rootApprovedSignature(nested).length - 2) / 2} bytes`}
              </Row>
              <Row k="S_ecdsa approved">{approved?.[cfg!.sEcdsa] ? "yes" : "not yet"}</Row>
              <Row k="S_pq approved">{approved?.[cfg!.sPq] ? "yes" : "not yet"}</Row>
              {rootTx && <Row k="then the root sends">{formatEther(rootTx.value ?? 0n)} ETH</Row>}
            </div>
            {approved?.[cfg!.sEcdsa] && approved?.[cfg!.sPq] && (
              <Note tone="ok">Both children have approved. The root can execute.</Note>
            )}
          </Card>
        )}

        <footer style={{ marginTop: 30, fontSize: 11, color: C.faint, lineHeight: 1.7 }}>
          <span style={mono(11)}>ZKNOX</span> · experimental, not audited ·{" "}
          {signers.length > 0 && (
            <strong style={{ color: C.warn }}>
              software holders are loaded from the build's environment: development only.{" "}
            </strong>
          )}
          <button
            style={{ ...button("ghost"), padding: "2px 8px", fontSize: 11 }}
            onClick={() => {
              setAnswers({});
              setSendState({ phase: "idle" });
            }}
          >
            discard every signature
          </button>
        </footer>
      </main>
    </>
  );
}
