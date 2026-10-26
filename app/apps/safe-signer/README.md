# safe-signer

The one step Safe{Wallet} cannot carry.

Safe{Wallet} proposes the root transaction, produces the ECDSA child's approval by itself (it calls that an
"on-chain signature") and executes the root once both children have approved. What has nowhere to go is a
post-quantum owner's ERC-1271 signature: 41,824 bytes, where the Transaction Service caps a confirmation at
5,000. This page covers exactly that gap, and nothing else.

Four blocks, in the order the work happens:

1. **the arrangement** — root, `S_ecdsa`, `S_pq`, read from the chain, with the NESTED policy checked
   through `ZKNOX_SafePQLens` when a lens address is given;
2. **the transaction** — typed in, read from the Safe Transaction Service by nonce, or pasted as a bare
   `safeTxHash`. A derived hash is confirmed against the Safe's own `getTransactionHash` before anything
   below it is shown;
3. **the owners** — one 32-byte digest each, set in a size meant to be read against a device screen, with
   the holder's key checked against the clone's stored `postQKeyHash` before the device comes out;
4. **send** — the assembled transaction, its 84 kB, its EIP-7623 floor and the node's own estimate, all on
   screen before the button does anything.

Then the root executes from Safe{Wallet} with a 130-byte signature, like any other Safe transaction.

Everything is derived locally. A digest read from a service is a digest nobody can check, and that
comparison against the device screen is the only thing standing between a signature and the wrong
transaction.

## Running it

```
cp .env.example .env            # or put the arrangement in the URL
make safe-signer                # http://localhost:5174
```

Against a local chain, with the whole arrangement — Safe singletons included — deployed for you:

```
make anvil                      # terminal 1
make safe-deploy-local          # terminal 2: prints the .env to paste
make safe-signer
```

`VITE_HOLDER_SEEDS` puts software holders on the page so the flow can be walked without hardware. The
footer says so in yellow whenever it is set; it belongs to a development build and nowhere else.

The arrangement travels in the URL (`?root=…&sEcdsa=…&sPq=…&k=2&chainId=11155111&hash=…`), which is how one
holder sends another exactly what they are looking at. Nothing secret goes that way.

## Inside Safe{Wallet}

Serve the page anywhere over https, then in Safe{Wallet}: **Apps → My custom apps → Add custom Safe App**,
paste the URL, tick the terms. There is no review and no listing — `AddCustomAppModal` fetches
`<url>/manifest.json`, needs `name`, `description` and an icon, and that is the whole gate. Serve the
manifest with `Access-Control-Allow-Origin: *`, since it is fetched cross-origin.

Open the app **on the root Safe** and nothing has to be typed:

- `sdk.safe.getInfo()` names the Safe, the chain, its owners and its nonce;
- the two children are read from the chain and told apart by asking their owners for `keyHashes()`;
- every later read goes through the host's RPC proxy, so there is no RPC field and no URL to leak.

Opened on `S_pq` instead, the child is recognised but the root is not: a Safe cannot be asked who owns it,
so the root is given once. Opened anywhere else, the app says which of the two it is looking at rather than
guessing.

What the frame cannot do is **broadcast**. The Safe Apps SDK exposes `eth_call`, `eth_estimateGas` and the
rest of the read methods, and no `eth_sendRawTransaction`; the host's own `sendTransactions` would propose a
transaction *from the Safe you are looking at*, which for `S_pq` is the transaction being built. So the last
step leaves the frame: a wallet, a relayer key with `VITE_RPC_URL_<chainId>`, or "download the transaction"
and send it from anywhere. The relayer pays the gas and authorizes nothing, so it can be any account.

### Trying the frame without app.safe.global

`public/host.html` is a development host: it answers the Safe Apps protocol by reading the Safe straight
from an RPC, and frames the app with the same sandbox attributes Safe{Wallet} uses.

```
make anvil && make safe-deploy-local && make safe-signer
# http://localhost:5174/host.html?safe=<the root>&rpc=http://127.0.0.1:8545
```

It signs nothing, proposes nothing and enforces no permission. It exists so the hosted path is exercised
rather than assumed.

## Why this is enough, and no fork is needed

The Transaction Service turns an on-chain `ApproveHash` event into an ordinary 65-byte confirmation
(`history/indexers/tx_processor.py`, `SafeSignatureApprovedHash`). So once `S_pq` has approved, the root's
queue in Safe{Wallet} reads "2 of 2" by itself and offers Execute, with nothing forked and no post-quantum
signature anywhere near the API — which is just as well, since `MultisigConfirmation.signature` is a column
capped at 5,000 bytes and one post-quantum signature is 41,824.

## What it does not do

- Distribute anything. Holders are reached by sending them the link; nothing is stored anywhere.
- Execute the root. That is an ordinary Safe transaction and belongs in Safe{Wallet}.
- The single-transaction path (`ExecNestedTx`): the digest for it is computed and tested, but the 84 kB root
  signature it produces has no interface that will carry it.

Experimental, not audited.
