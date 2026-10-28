// The browser's half of the ECML-Signer transport.
//
// `@zknox/pq-safe` knows the APDUs and the conversions; this knows only how to carry 64-byte reports to a
// USB device. Keeping the two apart is what let the dialogue be tested without hardware
// (`packages/safe/test/ledger.test.ts`), so the part that runs here is as small as it can be.
//
// WebHID needs a user gesture for `requestDevice`, which is why `openLedger` is called from the sign
// button and not on load, and it needs a secure context: https, or localhost.
import { ApduError, CLA, STATUS_WORDS, type Apdu } from "@zknox/pq-safe";

export type LedgerLink = {
  send: Apdu;
  close: () => Promise<void>;
  /** what the browser calls the device, for the one line the page shows about it */
  name: string;
};

export const webHidAvailable = (): boolean =>
  typeof navigator !== "undefined" && !!(navigator as Navigator & { hid?: unknown }).hid;

/** Why WebHID cannot be used here, or null if it can. */
export function webHidObstacle(): string | null {
  if (typeof window === "undefined") return "no browser";
  if (window.top !== window.self) {
    return "a Safe App runs in a sandboxed frame, which is not granted USB access. Open this page in a tab of its own to sign on the device.";
  }
  if (!window.isSecureContext) return "WebHID needs a secure context: https, or localhost";
  if (!webHidAvailable()) {
    return "this browser has no WebHID. Chrome, Edge and Brave have it; Firefox and Safari do not.";
  }
  return null;
}

/** @ledgerhq/hw-transport builds its APDU frames with `Buffer`, which a browser does not have, and it
 *  touches it while the module is evaluating. An ES import would therefore run before any statement of
 *  `main.tsx` could install a polyfill — the page went black on `Buffer is not defined`. Loading both here,
 *  in order, inside a function, is the only arrangement where the polyfill can be in place in time. It
 *  also keeps a hundred kilobytes of transport out of the initial bundle, and keeps a module that fails to
 *  load from taking the whole page with it. */
async function transportModule() {
  const { Buffer } = await import("buffer");
  (globalThis as typeof globalThis & { Buffer?: unknown }).Buffer ??= Buffer;
  return (await import("@ledgerhq/hw-transport-webhid")).default;
}

/** Asks the holder to pick their device, then hands back the APDU exchange `@zknox/pq-safe` expects.
 *  Must be called from a click: the browser refuses `requestDevice` otherwise. */
export async function openLedger(): Promise<LedgerLink> {
  const obstacle = webHidObstacle();
  if (obstacle) throw new Error(obstacle);

  const TransportWebHID = await transportModule();
  const transport = await TransportWebHID.request().catch((e: unknown) => {
    const why = e instanceof Error ? e.message : String(e);
    if (/no device selected|cancell?ed/i.test(why)) throw new Error("no device was chosen");
    throw new Error(
      `${why}. Plug the device in, unlock it, open ECML-Signer, and close anything else talking to it — ` +
        `Ledger Live holds the USB interface for itself.`,
    );
  });
  return linkOf(transport);
}

/** The device this origin was already granted, without a click, or null if there is none to reopen.
 *  A wallet asked to sign long after it was connected — a transaction confirmed an hour later, a page
 *  reloaded since — has no user gesture to spend on `requestDevice`; this is what it calls first. */
export async function reopenLedger(): Promise<LedgerLink | null> {
  if (webHidObstacle()) return null;
  const TransportWebHID = await transportModule();
  const transport = await TransportWebHID.openConnected().catch(() => null);
  return transport ? linkOf(transport) : null;
}

type HidTransport = Awaited<ReturnType<Awaited<ReturnType<typeof transportModule>>["request"]>>;

function linkOf(transport: HidTransport): LedgerLink {
  const send: Apdu = async (ins, p1, p2, data = new Uint8Array(0)) => {
    // The transport returns the payload with the two status bytes appended, whatever the status.
    const res = await transport.send(CLA, ins, p1, p2, Buffer.from(data), STATUS_WORDS);
    const sw = (res[res.length - 2] << 8) | res[res.length - 1];
    if (sw !== 0x9000) throw new ApduError(ins, sw);
    return new Uint8Array(res.subarray(0, res.length - 2));
  };

  return {
    send,
    close: () => transport.close(),
    // WebHID is not in lib.dom, and one optional string is not worth a types package.
    name: (transport.device as { productName?: string } | undefined)?.productName ?? "Ledger",
  };
}
