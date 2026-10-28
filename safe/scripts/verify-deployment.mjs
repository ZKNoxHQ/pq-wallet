#!/usr/bin/env node
// Checks that what is live on a chain is what this repository builds, byte for byte. Needs Node 22 and a
// `forge build --ast` of the safe/ directory to compare with; nothing to install.
//
//   cd safe && forge build --ast
//   node scripts/verify-deployment.mjs --rpc <url> [--origin-root <path>] [--build <safe dir>] [--root <safe>]
//                                      [--deployments <dir>] [--block <n>] [--report <file>] [--require-exact]
//
// `make safe-verify-deployed RPC=… ORIGIN_ROOT=…` does all of it at the commit that recorded the deployments.
//
// Reads `deployments/<chainId>-pq65.json` (and `<chainId>-root.json` when present) from the build directory,
// then, for every contract ZKNOX deployed:
//
//   code    the runtime bytecode on chain, with each immutable masked, equals the compiled one
//   links   each immutable holds the address it should (the verifier its helper, the implementation its
//           two verifiers, the lens the canonical Safe contracts...)
//   exact   the CBOR trailer, i.e. the IPFS hash of the compiler metadata, equals the one this build produces:
//           every source file (by keccak256), the compiler version and every setting are then the deployed ones
//
// and, from the root Safe down: proxy code and singleton, owners, thresholds, modules, guards, handler, the
// post-quantum owners as ERC-1167 clones of the verified implementation, and the canonical Safe contracts
// against the code hashes Safe publishes.
//
// Why --origin-root. Foundry writes two auto-detected remappings (erc4626-tests, halmos-cheatcodes, from
// openzeppelin-contracts' own submodules) as absolute paths, and the metadata records remappings. The
// bytecode does not depend on them; its metadata hash does. Pass the absolute path of the repository on the
// machine that compiled the deployment and the expected metadata is rewritten to it before hashing.
//
// Every read is pinned to one block, printed at the top, so a report says what was true at that block.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// ------------------------------------------------------------------ arguments

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`)
  return i >= 0 ? args[i + 1] : fallback
}
const flag = (name) => args.includes(`--${name}`)
const RPC = opt('rpc')
if (!RPC) {
  console.error('usage: verify-deployment.mjs --rpc <url> [--origin-root <path>] [--build <safe dir>] [--root <safe>] [--deployments <dir>] [--block <n>] [--report <file>] [--require-exact]')
  process.exit(2)
}
const here = dirname(fileURLToPath(import.meta.url))
const BUILD = resolve(opt('build', resolve(here, '..')))
const LOCAL_ROOT = resolve(BUILD, '..')
const ORIGIN_ROOT = resolve(opt('origin-root', LOCAL_ROOT))
const OUT = join(BUILD, 'out')
/** the records being checked; by default the build's own, which at the recording commit are the same files */
const DEPLOYMENTS = resolve(opt('deployments', join(BUILD, 'deployments')))
const HELPER_HEX = join(LOCAL_ROOT, 'lib/ETHDILITHIUM/test/f1600_170.hex')

// ------------------------------------------------------------------ bytes

/** Keccak-256, here so that the script needs nothing but Node: node:crypto has SHA3-256, whose padding
 *  differs. BigInt lanes; slow, and more than fast enough for a few hundred kilobytes of code. */
const M64 = (1n << 64n) - 1n
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14].map(BigInt)
const RC = (() => {
  const rc = []
  let r = 1
  for (let i = 0; i < 24; i++) {
    let c = 0n
    for (let j = 0; j < 7; j++) {
      r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
      if (r & 2) c ^= 1n << ((1n << BigInt(j)) - 1n)
    }
    rc.push(c)
  }
  return rc
})()
const rotl = (x, n) => (n === 0n ? x : ((x << n) | (x >> (64n - n))) & M64)
function f1600(s) {
  for (let round = 0; round < 24; round++) {
    const c = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20])
    for (let x = 0; x < 5; x++) {
      const d = c.at((x + 4) % 5) ^ rotl(c.at((x + 1) % 5), 1n)
      for (let y = 0; y < 25; y += 5) s[x + y] ^= d
    }
    const b = new Array(25)
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x + 5 * y])
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 25; y += 5) s[x + y] = b[x + y] ^ (~b[((x + 1) % 5) + y] & M64 & b[((x + 2) % 5) + y])
    }
    s[0] ^= RC[round]
  }
}
function keccak_256(bytes) {
  const rate = 136
  const padded = new Uint8Array(Math.floor(bytes.length / rate + 1) * rate)
  padded.set(bytes)
  padded[bytes.length] ^= 0x01
  padded[padded.length - 1] ^= 0x80
  const s = new Array(25).fill(0n)
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n
      for (let k = 7; k >= 0; k--) lane = (lane << 8n) | BigInt(padded[off + 8 * i + k])
      s[i] ^= lane
    }
    f1600(s)
  }
  const out = new Uint8Array(32)
  for (let i = 0; i < 4; i++) for (let k = 0; k < 8; k++) out[8 * i + k] = Number((s[i] >> BigInt(8 * k)) & 0xffn)
  return out
}

const hexToBytes = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'))
const toHex = (b) => `0x${Buffer.from(b).toString('hex')}`
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])
const keccak = (b) => toHex(keccak_256(typeof b === 'string' ? new TextEncoder().encode(b) : b))
const selector = (sig) => keccak(sig).slice(0, 10)
const word = (v) => BigInt(v).toString(16).padStart(64, '0')
const addrOf = (w) => `0x${w.slice(-40)}`.toLowerCase()
const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '-')
const same = (a, b) => !!a && !!b && a.toLowerCase() === b.toLowerCase()
/** EIP-55, for the report only: every comparison above is on lower case. */
function checksum(a) {
  const lower = a.toLowerCase().replace(/^0x/, '')
  const h = keccak(lower).slice(2)
  return `0x${[...lower].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join('')}`
}

/** CIDv0 of a file as `ipfs add` would produce it for one chunk: what solc embeds for its metadata. */
function cidv0(bytes) {
  const varint = (n) => {
    const out = []
    do {
      let x = n & 0x7f
      n >>>= 7
      if (n) x |= 0x80
      out.push(x)
    } while (n)
    return out
  }
  if (bytes.length > 262144) throw new Error('metadata larger than one IPFS chunk')
  const unixfs = [0x08, 0x02, 0x12, ...varint(bytes.length), ...bytes, 0x18, ...varint(bytes.length)]
  const node = Uint8Array.from([0x0a, ...varint(unixfs.length), ...unixfs])
  return Uint8Array.from([0x12, 0x20, ...createHash('sha256').update(node).digest()])
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58(bytes) {
  let n = BigInt(toHex(bytes))
  let s = ''
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s
    n /= 58n
  }
  for (const b of bytes) {
    if (b !== 0) break
    s = `1${s}`
  }
  return s
}

/** The CBOR trailer solc appends: its length is the last two bytes. */
function trailer(code) {
  const len = (code.at(-2) << 8) | code.at(-1)
  const cbor = code.slice(code.length - 2 - len, code.length - 2)
  const i = Buffer.from(cbor).indexOf(Buffer.from([0x64, 0x69, 0x70, 0x66, 0x73, 0x58, 0x22]))
  const j = Buffer.from(cbor).indexOf(Buffer.from([0x64, 0x73, 0x6f, 0x6c, 0x63, 0x43]))
  return {
    start: code.length - 2 - len,
    ipfs: i >= 0 ? cbor.slice(i + 7, i + 7 + 34) : null,
    solc: j >= 0 ? [...cbor.slice(j + 6, j + 9)].join('.') : null,
  }
}

// ------------------------------------------------------------------ metadata

/** solc writes its metadata with sorted keys and no whitespace; this writes it the same way. */
const canon = (v) =>
  Array.isArray(v)
    ? `[${v.map(canon).join(',')}]`
    : v && typeof v === 'object'
      ? `{${Object.keys(v)
          .sort()
          .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
          .join(',')}}`
      : JSON.stringify(v)

/** The same metadata with every source renamed by its keccak256: a contract compiled inside another one's
 *  compilation (the implementation, created by the factory) knows its files under that unit's names. */
function renameSources(rawMetadata, names) {
  const m = JSON.parse(rawMetadata)
  const renamed = {}
  for (const [k, v] of Object.entries(m.sources)) renamed[names.get(v.keccak256) ?? k] = v
  const [[target, contract]] = Object.entries(m.settings.compilationTarget)
  m.sources = renamed
  m.settings.compilationTarget = { [names.get(JSON.parse(rawMetadata).sources[target].keccak256) ?? target]: contract }
  return canon(m)
}

/** The metadata hash the deploying machine produced: this build's metadata with its absolute root replaced
 *  by the origin root, re-serialised the way solc writes it, hashed the way solc embeds it. */
function expectedCid(rawMetadata) {
  const m = JSON.parse(rawMetadata)
  if (canon(m) !== rawMetadata) throw new Error('the metadata does not re-serialise to itself; cannot rewrite it')
  const move = (s) => s.split(`${LOCAL_ROOT}/`).join(`${ORIGIN_ROOT}/`)
  const rekey = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [move(k), v]))
  m.settings.remappings = m.settings.remappings.map(move)
  m.settings.compilationTarget = rekey(m.settings.compilationTarget)
  m.sources = rekey(m.sources)
  return cidv0(new TextEncoder().encode(canon(m)))
}

// ------------------------------------------------------------------ artifacts

function artifact(contract, source) {
  const dir = join(OUT, `${source.split('/').at(-1)}`)
  if (!existsSync(dir)) throw new Error(`no ${dir}: run \`forge build --ast\` in ${BUILD}`)
  for (const f of readdirSync(dir).filter((n) => n.startsWith(contract) && n.endsWith('.json'))) {
    const a = JSON.parse(readFileSync(join(dir, f), 'utf8'))
    const target = a.metadata?.settings?.compilationTarget ?? {}
    if (target[source] === contract || target[resolve(BUILD, source)] === contract) {
      if (!a.ast) throw new Error(`${contract}: the artifact has no AST; build with \`forge build --ast\``)
      return a
    }
  }
  throw new Error(`no artifact for ${contract} compiled from ${source} in ${dir}`)
}

/** Immutable names, from the AST: `immutableReferences` only knows AST ids. */
function immutableNames(a) {
  const ids = new Set(Object.keys(a.deployedBytecode.immutableReferences ?? {}).map(Number))
  const names = new Map()
  const walk = (n) => {
    if (Array.isArray(n)) n.forEach(walk)
    else if (n && typeof n === 'object') {
      if (n.nodeType === 'VariableDeclaration' && ids.has(n.id)) names.set(String(n.id), n.name)
      Object.values(n).forEach(walk)
    }
  }
  walk(a.ast)
  return names
}

// ------------------------------------------------------------------ chain

let BLOCK = 'latest'
let rpcId = 0
async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  })
  const body = await res.json()
  if (body.error) throw new Error(`${method}: ${body.error.message}`)
  return body.result
}
const code = async (a) => hexToBytes(await rpc('eth_getCode', [a, BLOCK]))
const slot = async (a, s) => rpc('eth_getStorageAt', [a, s, BLOCK])
const call = async (to, sig, ...words) =>
  (await rpc('eth_call', [{ to, data: selector(sig) + words.map(word).join('') }, BLOCK])).slice(2)
const callAddress = async (to, sig) => addrOf(await call(to, sig))
const callUint = async (to, sig, ...w) => BigInt(`0x${(await call(to, sig, ...w)).slice(0, 64)}`)
const wordsOf = (hex) => hex.match(/.{64}/g) ?? []
function decodeAddresses(hex, at = 0) {
  const w = wordsOf(hex)
  const off = Number(BigInt(`0x${w[at]}`)) / 32
  const n = Number(BigInt(`0x${w[off]}`))
  return w.slice(off + 1, off + 1 + n).map(addrOf)
}
function decodeString(hex) {
  const w = wordsOf(hex)
  const off = Number(BigInt(`0x${w[0]}`)) * 2
  const n = Number(BigInt(`0x${hex.slice(off, off + 64)}`))
  return Buffer.from(hex.slice(off + 64, off + 64 + 2 * n), 'hex').toString('utf8')
}

// ------------------------------------------------------------------ comparison

/** On-chain runtime against an expected one: immutables masked and read back, then the code, then the CBOR. */
function compare(onChain, expected, names, wantCid) {
  if (onChain.length === 0) return { status: 'MISMATCH', detail: 'no code at this address' }
  if (onChain.length !== expected.bytes.length) {
    return { status: 'MISMATCH', detail: `${onChain.length} bytes on chain, ${expected.bytes.length} built` }
  }
  const masked = onChain.slice()
  const immutables = {}
  for (const [id, refs] of Object.entries(expected.immutableReferences ?? {})) {
    let value
    for (const { start, length } of refs) {
      const v = onChain.slice(start, start + length)
      if (value && !eq(value, v)) return { status: 'MISMATCH', detail: `immutable ${names.get(id)} differs between its copies` }
      value = v
      masked.fill(0, start, start + length)
    }
    immutables[names.get(id) ?? id] = addrOf(toHex(value).slice(2))
  }
  const t = trailer(expected.bytes)
  const body = t.start
  for (let i = 0; i < body; i++) {
    if (masked[i] !== expected.bytes[i]) return { status: 'MISMATCH', detail: `code differs from byte ${i}`, immutables }
  }
  const got = trailer(onChain)
  const exact = got.ipfs && wantCid && eq(got.ipfs, wantCid)
  return {
    status: exact ? 'exact' : 'code',
    immutables,
    metadata: got.ipfs ? base58(got.ipfs) : null,
    expectedMetadata: wantCid ? base58(wantCid) : null,
    solc: got.solc,
  }
}

// ------------------------------------------------------------------ the checks

const rows = []
let failed = false
const record = (name, address, result, detail) => {
  // a byte-level mismatch says where; what the immutables hold is secondary then
  const why = result.status === 'MISMATCH' && result.detail ? result.detail : detail
  rows.push({ name, address: checksum(address), ...result, detail: why })
  if (result.status === 'MISMATCH' || result.status === 'FAIL') failed = true
  if (flag('require-exact') && result.status === 'code') failed = true
}
const link = (result, name, want, label) => {
  const got = result.immutables?.[name]
  if (!same(got, want)) {
    result.status = 'FAIL'
    return `${name} = ${got ?? '?'}, expected ${label} ${want}`
  }
  return `${name} = ${label} ${short(want)}`
}

/** Safe 1.5.0, `@safe-global/safe-deployments` 1.37.65, canonical deployment, the same on every chain. */
const SAFE = {
  Safe: ['0xFf51A5898e281Db6DfC7855790607438dF2ca44b', '0xdda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2'],
  SafeL2: ['0xEdd160fEBBD92E350D4D398fb636302fccd67C7e', '0x180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc'],
  SafeProxyFactory: ['0x14F2982D601c9458F93bd70B218933A6f8165e7b', '0x967dae4cda22b0c9ef7f31b010bdc1ceb0af9904b0c3dc060b5302e4c18a4529'],
  CompatibilityFallbackHandler: ['0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4', '0x3c6a85bcf7b563daa624b884b4e9a1b9fa5371edde7be945d998071a48f28bbc'],
}
/** ZKNOX_dilithium65.F1600_CODEHASH: the verifier refuses any other helper at construction. */
const F1600_CODEHASH = '0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b'
const SENTINEL = '0x0000000000000000000000000000000000000001'

async function main() {
  const chainId = Number(await rpc('eth_chainId', []))
  const head = await rpc('eth_getBlockByNumber', [opt('block') ? `0x${BigInt(opt('block')).toString(16)}` : 'latest', false])
  BLOCK = head.number
  const stackFile = join(DEPLOYMENTS, `${chainId}-pq65.json`)
  if (!existsSync(stackFile)) throw new Error(`no ${stackFile}`)
  const stack = JSON.parse(readFileSync(stackFile, 'utf8'))
  const rootFile = join(DEPLOYMENTS, `${chainId}-root.json`)
  const rootAddr = opt('root') ?? (existsSync(rootFile) ? JSON.parse(readFileSync(rootFile, 'utf8')).root : null)

  let commit = '?'
  try {
    commit = execFileSync('git', ['-C', LOCAL_ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
  } catch {}

  // ---- the five contracts compiled here, and the helper
  const mldsa = artifact('ZKNOX_dilithium65', '../lib/ETHDILITHIUM/src/ZKNOX_dilithium65.sol')
  const k1 = artifact('ECDSAk1Verifier', '../lib/InterfaceVerifier/src/VerifierECDSAk1.sol')
  const factory = artifact('ZKNOX_PQFactory7702', '../contracts/src/ZKNOX_PQFactory7702.sol')
  const account = artifact('ZKNOX_PQAccount7702', '../contracts/src/ZKNOX_PQAccount7702.sol')
  const lens = artifact('ZKNOX_SafePQLens', 'src/ZKNOX_SafePQLens.sol')
  const s = mldsa.metadata.settings
  const header = {
    chainId,
    block: Number(BigInt(BLOCK)),
    time: new Date(Number(BigInt(head.timestamp)) * 1000).toISOString(),
    commit,
    compiler: `solc ${mldsa.metadata.compiler.version}, viaIR ${s.viaIR}, runs ${s.optimizer.runs}, evm ${s.evmVersion}`,
    originRoot: ORIGIN_ROOT,
  }

  const runtimeOf = (a) => ({ bytes: hexToBytes(a.deployedBytecode.object), immutableReferences: a.deployedBytecode.immutableReferences })

  // helper: raw bytecode, no compiler involved
  {
    const want = hexToBytes(readFileSync(HELPER_HEX, 'utf8').trim())
    const got = await code(stack.f1600Helper)
    const ok = eq(got, want)
    const h = keccak(got)
    record('Keccak-f1600 helper', stack.f1600Helper, { status: ok && h === F1600_CODEHASH ? 'exact' : 'MISMATCH' },
      ok ? `${got.length} bytes = lib/ETHDILITHIUM/test/f1600_170.hex, codehash ${short(h)} = F1600_CODEHASH` : `${got.length} bytes, not the file`)
  }

  {
    const r = compare(await code(stack.mldsa65Verifier), runtimeOf(mldsa), immutableNames(mldsa), expectedCid(mldsa.rawMetadata))
    record('ZKNOX_dilithium65', stack.mldsa65Verifier, r, link(r, 'f1600Helper', stack.f1600Helper, 'helper'))
  }
  {
    const r = compare(await code(stack.k1Verifier), runtimeOf(k1), immutableNames(k1), expectedCid(k1.rawMetadata))
    record('ECDSAk1Verifier', stack.k1Verifier, r, 'no immutable')
  }
  {
    const r = compare(await code(stack.factory), runtimeOf(factory), immutableNames(factory), expectedCid(factory.rawMetadata))
    const d = link(r, 'IMPLEMENTATION', stack.pqImplementation, 'implementation')
    const version = decodeString(await call(stack.factory, 'VERSION()'))
    record('ZKNOX_PQFactory7702', stack.factory, r, `${d}, VERSION "${version}"`)
  }

  // implementation: created by the factory's constructor, so compiled inside the factory's compilation,
  // where its source file carries the factory unit's name. Its expected runtime is the one embedded in the
  // factory's creation code, and its metadata is renamed accordingly.
  {
    const standalone = runtimeOf(account)
    const body = standalone.bytes.slice(0, trailer(standalone.bytes).start)
    const init = hexToBytes(factory.bytecode.object)
    const at = Buffer.from(init).indexOf(Buffer.from(body))
    if (at < 0) throw new Error('the account runtime is not inside the factory creation code')
    const embedded = { bytes: init.slice(at, at + standalone.bytes.length), immutableReferences: standalone.immutableReferences }
    const names = new Map(Object.entries(JSON.parse(factory.rawMetadata).sources).map(([k, v]) => [v.keccak256, k]))
    const asInFactory = renameSources(account.rawMetadata, names)
    // the renaming is right only if, before any root rewrite, it hashes to what this build embedded
    if (!eq(cidv0(new TextEncoder().encode(asInFactory)), trailer(embedded.bytes).ipfs)) {
      throw new Error('cannot reconstruct the metadata of the account as compiled inside the factory')
    }
    const r = compare(await code(stack.pqImplementation), embedded, immutableNames(account), expectedCid(asInFactory))
    const d = [
      link(r, 'ENTRY_POINT', stack.entryPoint, 'EntryPoint v0.8'),
      link(r, 'PRE_QUANTUM_VERIFIER', stack.k1Verifier, 'ECDSAk1Verifier'),
      link(r, 'POST_QUANTUM_VERIFIER', stack.mldsa65Verifier, 'ZKNOX_dilithium65'),
      link(r, 'FACTORY', stack.factory, 'factory'),
    ].join('; ')
    const onChainImpl = await callAddress(stack.factory, 'IMPLEMENTATION()')
    if (!same(onChainImpl, stack.pqImplementation)) {
      r.status = 'FAIL'
      record('ZKNOX_PQAccount7702', stack.pqImplementation, r, `factory.IMPLEMENTATION() = ${onChainImpl}`)
    } else record('ZKNOX_PQAccount7702', stack.pqImplementation, r, d)
  }

  {
    const r = compare(await code(stack.lens), runtimeOf(lens), immutableNames(lens), expectedCid(lens.rawMetadata))
    const d = [
      link(r, 'SAFE_SINGLETON', SAFE.Safe[0], 'Safe 1.5.0'),
      link(r, 'SAFE_SINGLETON_L2', SAFE.SafeL2[0], 'SafeL2 1.5.0'),
      link(r, 'FALLBACK_HANDLER', SAFE.CompatibilityFallbackHandler[0], 'handler 1.5.0'),
    ].join('; ')
    record('ZKNOX_SafePQLens', stack.lens, r, d)
  }

  // ---- canonical Safe contracts, against Safe's published code hashes
  for (const [name, [address, hash]] of Object.entries(SAFE)) {
    const h = keccak(await code(address))
    record(`${name} 1.5.0`, address, { status: h === hash ? 'canonical' : 'MISMATCH' }, h === hash ? 'code hash = safe-deployments 1.37.65' : `code hash ${h}`)
  }

  // ---- the arrangement, from the root down
  if (rootAddr) {
    const creation = decodeBytes(await call(SAFE.SafeProxyFactory[0], 'proxyCreationCode()'))
    const proxyRuntime = async (singleton) =>
      hexToBytes(await rpc('eth_call', [{ data: creation + word(singleton) }, BLOCK]))

    const describeSafe = async (label, address) => {
      const c = await code(address)
      const singleton = addrOf((await slot(address, '0x0')).slice(2))
      const isL1 = same(singleton, SAFE.Safe[0])
      const isL2 = same(singleton, SAFE.SafeL2[0])
      const proxyOk = (isL1 || isL2) && eq(c, await proxyRuntime(singleton))
      const version = decodeString(await call(address, 'VERSION()'))
      const owners = decodeAddresses(await call(address, 'getOwners()'))
      const threshold = Number(await callUint(address, 'getThreshold()'))
      const modules = decodeAddresses(await call(address, 'getModulesPaginated(address,uint256)', SENTINEL, 10))
      const handler = addrOf((await slot(address, keccak('fallback_manager.handler.address'))).slice(2))
      const guard = addrOf((await slot(address, keccak('guard_manager.guard.address'))).slice(2))
      const moduleGuard = addrOf((await slot(address, keccak('module_manager.module_guard.address'))).slice(2))
      const problems = []
      if (!proxyOk) problems.push(`proxy code or singleton ${singleton} is not canonical 1.5.0`)
      if (version !== '1.5.0') problems.push(`VERSION ${version}`)
      if (modules.length) problems.push(`${modules.length} module(s)`)
      if (!same(handler, SAFE.CompatibilityFallbackHandler[0])) problems.push(`handler ${handler}`)
      if (BigInt(guard) !== 0n) problems.push(`guard ${guard}`)
      if (BigInt(moduleGuard) !== 0n) problems.push(`module guard ${moduleGuard}`)
      return { label, address, owners, threshold, problems, kind: isL2 ? 'SafeL2' : 'Safe' }
    }

    const root = await describeSafe('root', rootAddr)
    const kids = await Promise.all(root.owners.map((o) => describeSafe('child', o)))
    const cloneRuntime = (impl) => hexToBytes(`0x363d3d373d3d3d363d73${impl.slice(2).toLowerCase()}5af43d82803e903d91602b57fd5bf3`)

    let sPq = null
    let sEcdsa = null
    const holders = []
    for (const kid of kids) {
      const codes = await Promise.all(kid.owners.map(code))
      if (codes.every((c) => c.length === 0)) sEcdsa = kid
      else if (codes.every((c) => eq(c, cloneRuntime(stack.pqImplementation)))) {
        sPq = kid
        for (const o of kid.owners) {
          const kh = wordsOf(await call(o, 'keyHashes()'))
          holders.push({ clone: o, preQKeyHash: `0x${kh[0]}`, postQKeyHash: `0x${kh[1]}` })
        }
      }
    }
    const rootProblems = [...root.problems]
    if (root.threshold !== 2 || root.owners.length !== 2) rootProblems.push(`${root.threshold} of ${root.owners.length}`)
    if (!sEcdsa) rootProblems.push('no child whose owners are all plain EOAs')
    if (!sPq) rootProblems.push(`no child whose owners are all clones of ${stack.pqImplementation}`)
    record('root Safe', root.address, { status: rootProblems.length ? 'FAIL' : 'ok' },
      rootProblems.length ? rootProblems.join('; ') : `${root.kind} 1.5.0 proxy, 2 of {S_ecdsa, S_pq}, no module, no guard, canonical handler`)
    if (sEcdsa) {
      record('S_ecdsa', sEcdsa.address, { status: sEcdsa.problems.length ? 'FAIL' : 'ok' },
        sEcdsa.problems.join('; ') || `${sEcdsa.kind} 1.5.0 proxy, ${sEcdsa.threshold} of ${sEcdsa.owners.length} EOAs without code`)
    }
    if (sPq) {
      record('S_pq', sPq.address, { status: sPq.problems.length ? 'FAIL' : 'ok' },
        sPq.problems.join('; ') || `${sPq.kind} 1.5.0 proxy, ${sPq.threshold} of ${sPq.owners.length} ERC-1167 clones of the implementation`)
      for (const h of holders) {
        const initialized = BigInt(h.postQKeyHash) !== 0n
        record('  post-quantum owner', h.clone, { status: initialized ? 'ok' : 'FAIL' },
          `keccak256(k1 address) ${short(h.preQKeyHash)}, keccak256(ML-DSA-65 key) ${short(h.postQKeyHash)}`)
      }
    }
    if (sEcdsa && sPq) {
      const k = BigInt(sPq.threshold)
      const v = await callUint(stack.lens, 'nestedViolations(address,address,address,uint256,address)', root.address, sEcdsa.address, sPq.address, k, stack.pqImplementation)
      record('NESTED policy', stack.lens, { status: v === 0n ? 'ok' : 'FAIL' },
        v === 0n ? `lens.nestedViolations(root, S_ecdsa, S_pq, ${k}, implementation) = 0` : `violations bitfield ${v}`)
    }
    header.holders = holders
  }

  // ---- report
  console.log(`chain ${chainId}, block ${header.block} (${header.time})`)
  console.log(`build ${BUILD} at ${commit.slice(0, 7)}, ${header.compiler}`)
  console.log(`metadata expected as compiled under ${ORIGIN_ROOT}`)
  console.log('')
  const w = Math.max(...rows.map((r) => r.name.length))
  for (const r of rows) console.log(`${r.name.padEnd(w)}  ${r.address}  ${r.status.padEnd(9)}  ${r.detail}`)
  const partial = rows.filter((r) => r.status === 'code')
  if (partial.length) {
    console.log('')
    console.log(`${partial.length} contract(s) match in code but not in metadata. The deployed metadata hash is printed`)
    console.log('below; it differs when the deploying build sat under another root (--origin-root) or another commit.')
    for (const r of partial) console.log(`  ${r.name}: on chain ${r.metadata}, this build ${r.expectedMetadata}`)
  }
  if (opt('report')) writeFileSync(opt('report'), `${JSON.stringify({ ...header, results: rows }, null, 2)}\n`)
  process.exit(failed ? 1 : 0)
}

function decodeBytes(hex) {
  const w = wordsOf(hex)
  const off = Number(BigInt(`0x${w[0]}`)) * 2
  const n = Number(BigInt(`0x${hex.slice(off, off + 64)}`))
  return `0x${hex.slice(off + 64, off + 64 + 2 * n)}`
}

main().catch((e) => {
  console.error(e.message)
  process.exit(2)
})
