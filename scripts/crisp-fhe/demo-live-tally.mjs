// SPDX-License-Identifier: LGPL-3.0-only
//
// CRISP-QES — automated 2-voter LIVE-TALLY climb demo (0 -> 1 -> 2).
//
// Proves the demo-only "Recalculate tally" feature climbs as real votes land:
//   recalc=[0,0] (n=0) -> vote Cats -> recalc=[1,0] (n=1) -> vote Dogs -> recalc=[1,1] (n=2)
// on ONE web-visible round that stays OPEN throughout (each recalc is a fresh,
// non-destructive threshold decryption via POST /rounds/tally-now).
//
// This is the 2-voter generalisation of examples/CRISP/tests/qes-e2e.mjs: that
// driver pins a 1-leaf synthetic tree and casts 1 vote (a 2nd from the same
// secret reuses the nullifier -> double-vote reject). For a 0->1->2 climb we need
// TWO distinct enrollment secrets -> a 2-leaf depth-20 Pedersen-Merkle tree ->
// the root pinned on-chain via setEnrollmentRoot + BallotRegistry.createRound ->
// each voter votes with their own leaf + Merkle path.
//
// The Merkle hashing matches circuits/bin/crisp_qes/src/merkle.nr exactly:
//   node = pedersen_hash_with_separator([left, right], hashIndex=0), depth 20,
//   leaf = enrollment_secret (the circuit walks compute_root over the secret).
// 2-leaf tree: leaf0=s1 (left), leaf1=s2 (right) -> they are siblings at level 0.
//   path1 = [s2, zero[1], .., zero[19]], indices1 = [0,0,..,0]
//   path2 = [s1, zero[1], .., zero[19]], indices2 = [1,0,..,0]
// where zero[i] is the all-zeros subtree root at level i (zero[0]=0,
// zero[i]=pedersen([zero[i-1],zero[i-1]],0)); genesis zero[20] is the canonical
// 0x1b49e706af69da35927cdf2b28b02fb2647245ac0ccbc376d062031185d3cd84.
//
// RUNS INSIDE the fhe container (node/tsx + the cli + the in-container
// crisp-sdk/mask-daemon packages). It is `docker cp`'d into /app and run via:
//   node --import tsx /app/demo-live-tally.mjs
// Imports are anchored at the in-container crisp-sdk package (same trick the
// driver uses), so cwd does not matter.
//
// Config (env, all optional):
//   RPC_URL          default http://127.0.0.1:8545
//   COORDINATOR_URL  default http://127.0.0.1:4000
//   E3_PROGRAM_ADDRESS  (CRISP_QES_PROGRAM) — REQUIRED in this stack (no deployed_contracts.json on the fhe image at the live addr)
//   BALLOT_REGISTRY  REQUIRED — so the web /rounds page shows the round
//   PRIVATE_KEY      default anvil[0] (= owner of setEnrollmentRoot + BallotRegistry operator)
//   CLI_BIN          default /app/examples/CRISP/target/release/cli
//   ROUND_TITLE      default "Cats or dogs?"
//   ROUND_OPTS       default "Cats,Dogs"
//   ROUND_DAYS       default 30 (BallotRegistry deadline; unrelated to E3 input window)
//   COMMITTEE_KEY_TIMEOUT_S default 180

import { execFileSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, resolve } from 'node:path'
import { createRequire } from 'node:module'

const __dirname = dirname(fileURLToPath(import.meta.url))
// Anchor imports at the in-container crisp-sdk package (viem/@crisp-e3/sdk/@aztec/bb.js
// are transitive deps there). Allow override for a different layout.
const CRISP_ROOT = process.env.CRISP_ROOT ?? '/app/examples/CRISP'
const anchor = createRequire(resolve(CRISP_ROOT, 'packages/crisp-sdk/package.json'))
const imp = async (spec) => import(pathToFileURL(anchor.resolve(spec)).href)

const { createPublicClient, createWalletClient, http } = await imp('viem')
const { privateKeyToAccount } = await imp('viem/accounts')
const { generateCircuitInputsImpl, generateProof, encodeSolidityProof } = await imp('@crisp-e3/sdk')
const { BarretenbergSync } = await imp('@aztec/bb.js')

// ───────────────────────────── config ──────────────────────────────────────
const RPC_URL = process.env.RPC_URL ?? 'http://127.0.0.1:8545'
const COORDINATOR_URL = (process.env.COORDINATOR_URL ?? 'http://127.0.0.1:4000').replace(/\/+$/, '')
const PRIVATE_KEY = process.env.PRIVATE_KEY ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const CLI_BIN = process.env.CLI_BIN ?? resolve(CRISP_ROOT, 'target/release/cli')
const PROGRAM_ADDRESS = process.env.E3_PROGRAM_ADDRESS
const BALLOT_REGISTRY = process.env.BALLOT_REGISTRY
const ROUND_TITLE = process.env.ROUND_TITLE ?? 'Cats or dogs?'
const ROUND_OPTS = (process.env.ROUND_OPTS ?? 'Cats,Dogs').split(',').map((s) => s.trim())
const ROUND_DAYS = Number(process.env.ROUND_DAYS ?? 30)
const COMMITTEE_KEY_TIMEOUT_S = Number(process.env.COMMITTEE_KEY_TIMEOUT_S ?? 180)

const NUM_OPTIONS = ROUND_OPTS.length
const TREE_DEPTH = 20
const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n // ASCII "v2-pen-no1"
const FR_MAX = 1n << 254n
const GENESIS_ROOT = 0x1b49e706af69da35927cdf2b28b02fb2647245ac0ccbc376d062031185d3cd84n

if (!PROGRAM_ADDRESS) throw new Error('E3_PROGRAM_ADDRESS (CRISP_QES_PROGRAM) is required')
if (!BALLOT_REGISTRY) throw new Error('BALLOT_REGISTRY is required (so the web /rounds page shows the round)')
if (NUM_OPTIONS !== 2) throw new Error(`this demo expects exactly 2 options (got ${NUM_OPTIONS})`)

// ───────────────────────────── ABIs ────────────────────────────────────────
const QES_PROGRAM_ABI = [
  { type: 'function', name: 'setEnrollmentRoot', stateMutability: 'nonpayable', inputs: [{ name: 'e3Id', type: 'uint256' }, { name: 'root', type: 'uint256' }], outputs: [] },
  { type: 'function', name: 'getSlotIndex', stateMutability: 'view', inputs: [{ name: 'e3Id', type: 'uint256' }, { name: 'nullifier', type: 'bytes32' }], outputs: [{ name: '', type: 'int40' }] },
  { type: 'function', name: 'enclave', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
]
const BALLOT_ABI = [
  { type: 'function', name: 'createRound', stateMutability: 'nonpayable', inputs: [
    { name: 'e3Id', type: 'uint256' }, { name: 'title', type: 'string' }, { name: 'options', type: 'string[]' },
    { name: 'enrollmentRoot', type: 'bytes32' }, { name: 'deadline', type: 'uint64' } ], outputs: [] },
]
const ENCLAVE_ABI = [
  { type: 'function', name: 'getE3Stage', stateMutability: 'view', inputs: [{ name: 'e3Id', type: 'uint256' }], outputs: [{ name: '', type: 'uint8' }] },
]
const E3_STAGE = ['None', 'Requested', 'CommitteeFinalized', 'KeyPublished', 'CiphertextReady', 'Complete', 'Failed']

// ───────────────────────────── helpers ─────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let _stage = 0
const stage = (label) => console.log(`\n=== STAGE ${++_stage}: ${label} ===`)
const ok = (msg) => console.log(`  ✓ ${msg}`)

function bigintToBE32(v) {
  if (v < 0n) throw new Error('pedersen: negative field element')
  if (v >= FR_MAX) throw new Error('pedersen: input exceeds Fr range')
  const out = new Uint8Array(32)
  let x = v
  for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n }
  return out
}
function be32ToBigInt(b) {
  let acc = 0n
  for (let i = 0; i < b.length; i++) acc = (acc << 8n) | BigInt(b[i])
  return acc
}
function nullifierToBytes32(n) {
  const h = n.toString(16)
  if (h.length > 64) throw new Error('nullifier exceeds bytes32')
  return '0x' + h.padStart(64, '0')
}
function rootToBytes32(v) {
  const h = v.toString(16)
  if (h.length > 64) throw new Error('root exceeds bytes32')
  return '0x' + h.padStart(64, '0')
}
async function postJson(path, body) {
  return fetch(`${COORDINATOR_URL}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
}
async function getCommitteeKeyFromCoordinator(e3Id) {
  const res = await postJson('/state/lite', { round_id: e3Id })
  if (!res.ok) return null
  const json = await res.json()
  const pk = json.committee_public_key
  if (!pk || pk.length === 0 || (pk.length === 1 && Number(pk[0]) === 0)) return null
  return new Uint8Array(pk.map((b) => Number(b)))
}
function randomSecret() {
  return (be32ToBigInt(crypto.getRandomValues(new Uint8Array(31))) % (FR_MAX - 1n)) + 1n
}
async function tallyNow(e3Id) {
  const res = await postJson('/rounds/tally-now', { round_id: e3Id })
  const text = await res.text()
  if (!res.ok) throw new Error(`tally-now failed (http ${res.status}): ${text}`)
  return JSON.parse(text)
}
async function activeSlots(e3Id) {
  const res = await postJson('/qes/active-slots', { round_id: e3Id })
  if (!res.ok) throw new Error(`/qes/active-slots failed (http ${res.status})`)
  const raw = await res.json()
  return raw.map((sl) => ({ nullifier: sl.nullifier, ciphertext: new Uint8Array(sl.ciphertext) }))
}

// ───────────────────────────── main ────────────────────────────────────────
async function main() {
  const account = privateKeyToAccount(PRIVATE_KEY)
  const chain = { id: 31337, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [RPC_URL] } } }
  const publicClient = createPublicClient({ chain, transport: http(RPC_URL) })
  const walletClient = createWalletClient({ account, chain, transport: http(RPC_URL) })

  console.log('CRISP-QES 2-voter live-tally climb demo')
  console.log(`  RPC_URL         = ${RPC_URL}`)
  console.log(`  COORDINATOR_URL = ${COORDINATOR_URL}`)
  console.log(`  E3_PROGRAM      = ${PROGRAM_ADDRESS}`)
  console.log(`  BALLOT_REGISTRY = ${BALLOT_REGISTRY}`)
  console.log(`  title="${ROUND_TITLE}" options=[${ROUND_OPTS.join(',')}] (n=${NUM_OPTIONS})`)

  const bb = await BarretenbergSync.initSingleton()
  const pedersen = (inputs, hashIndex = 0) => {
    const { hash } = bb.pedersenHash({ inputs: inputs.map(bigintToBE32), hashIndex })
    return be32ToBigInt(hash)
  }
  // zero[0..depth] subtree roots (zero[0]=0, zero[i]=H(zero[i-1],zero[i-1])).
  const zeros = [0n]
  for (let i = 1; i <= TREE_DEPTH; i++) zeros[i] = pedersen([zeros[i - 1], zeros[i - 1]], 0)
  if (zeros[TREE_DEPTH] !== GENESIS_ROOT) {
    throw new Error(`zero-tree[${TREE_DEPTH}] != canonical genesis (got ${rootToBytes32(zeros[TREE_DEPTH])})`)
  }
  const nullifierOf = (s, petitionId) => pedersen([s, petitionId, DOMAIN_PETITION_V2], 0)
  // recompute a root from a leaf + path + indices (mirrors merkle.nr compute_root).
  const rootFromPath = (leaf, path, indices) => {
    let cur = leaf
    for (let d = 0; d < TREE_DEPTH; d++) {
      const sib = path[d]
      cur = indices[d] === 1 ? pedersen([sib, cur], 0) : pedersen([cur, sib], 0)
    }
    return cur
  }

  // ── STAGE 1: build the 2-leaf tree (leaf0=s1 left, leaf1=s2 right; siblings).
  stage('build 2-leaf depth-20 Pedersen-Merkle tree')
  const s1 = randomSecret()
  const s2 = randomSecret()
  // Level-0 parent over the two leaves; higher levels pad with zero subtrees.
  const tail = zeros.slice(1, TREE_DEPTH) // zero[1..19] (length 19)
  const path1 = [s2, ...tail]            // voter1 is the LEFT child at level 0
  const idx1 = [0, ...new Array(TREE_DEPTH - 1).fill(0)]
  const path2 = [s1, ...tail]            // voter2 is the RIGHT child at level 0
  const idx2 = [1, ...new Array(TREE_DEPTH - 1).fill(0)]
  const root1 = rootFromPath(s1, path1, idx1)
  const root2 = rootFromPath(s2, path2, idx2)
  if (root1 !== root2) throw new Error(`2-leaf paths disagree on root: ${rootToBytes32(root1)} vs ${rootToBytes32(root2)}`)
  const root = root1
  if (root === GENESIS_ROOT) throw new Error('computed root == genesis (leaves not populated)')
  ok(`tree built, root=${rootToBytes32(root).slice(0, 14)}… (2 distinct leaves verified)`)

  const voter1 = { s: s1, path: path1, indices: idx1 }
  const voter2 = { s: s2, path: path2, indices: idx2 }

  // ── STAGE 2: open a round, pin root, register on BallotRegistry (web-visible).
  stage('open round (cli init -n 2) + setEnrollmentRoot + BallotRegistry.createRound')
  let e3Id
  const out = execFileSync(CLI_BIN, ['init', '--num-options', String(NUM_OPTIONS)], {
    cwd: CRISP_ROOT, env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? 'info' },
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'],
  })
  const lines = out.trim().split('\n').map((l) => l.trim()).filter(Boolean)
  e3Id = Number(lines[lines.length - 1])
  if (!Number.isInteger(e3Id) || e3Id < 0) throw new Error(`could not parse e3Id from cli output: "${lines[lines.length - 1]}"`)
  const PETITION_ID = BigInt(e3Id) // contract binds pub[6]=e3Id; prover must match
  ok(`round created, e3Id=${e3Id}`)

  let hash = await walletClient.writeContract({
    address: PROGRAM_ADDRESS, abi: QES_PROGRAM_ABI, functionName: 'setEnrollmentRoot', args: [BigInt(e3Id), root],
  })
  await publicClient.waitForTransactionReceipt({ hash })
  ok(`enrollment root pinned on-chain (e3Id=${e3Id})`)

  const nowTs = Number((await publicClient.getBlock()).timestamp)
  const deadline = BigInt(nowTs + ROUND_DAYS * 86400)
  hash = await walletClient.writeContract({
    address: BALLOT_REGISTRY, abi: BALLOT_ABI, functionName: 'createRound',
    args: [BigInt(e3Id), ROUND_TITLE, ROUND_OPTS, rootToBytes32(root), deadline],
  })
  await publicClient.waitForTransactionReceipt({ hash })
  ok(`BallotRegistry.createRound("${ROUND_TITLE}") — round is now web-visible`)

  // ── STAGE 3: wait for committee key (DKG ~80s).
  stage('wait for committee key (DKG)')
  const enclave = await publicClient.readContract({ address: PROGRAM_ADDRESS, abi: QES_PROGRAM_ABI, functionName: 'enclave' })
  let publicKey = null
  const dlKey = Date.now() + COMMITTEE_KEY_TIMEOUT_S * 1000
  while (Date.now() < dlKey) {
    const st = Number(await publicClient.readContract({ address: enclave, abi: ENCLAVE_ABI, functionName: 'getE3Stage', args: [BigInt(e3Id)] }))
    publicKey = await getCommitteeKeyFromCoordinator(e3Id)
    if (publicKey) { ok(`committee key published (stage=${E3_STAGE[st] ?? st})`); break }
    console.log(`  … waiting (stage=${E3_STAGE[st] ?? st})`)
    await sleep(5000)
  }
  if (!publicKey) throw new Error(`committee key not published within ${COMMITTEE_KEY_TIMEOUT_S}s`)

  // ── recalc helper closure over e3Id.
  const recalc = async (label, want) => {
    const t = await tallyNow(e3Id)
    const counts = t.counts.map((x) => Number(x))
    console.log(`  RECALC [${label}] -> counts=[${counts.join(',')}] n_votes=${t.n_votes}`)
    const okShape = counts.length === want.length && counts.every((v, i) => v === want[i]) && Number(t.n_votes) === want.reduce((a, b) => a + b, 0)
    if (!okShape) throw new Error(`recalc [${label}] mismatch: got counts=[${counts.join(',')}] n_votes=${t.n_votes}, want counts=[${want.join(',')}]`)
    ok(`recalc [${label}] == [${want.join(',')}] (n_votes=${t.n_votes})`)
    return t
  }

  // ── STAGE 4: recalc on empty round -> [0,0].
  stage('recalc (0 votes) -> assert [0,0]')
  await recalc('empty', [0, 0])

  // ── vote helper: build + broadcast a real fold vote for one voter.
  const castVote = async (voter, vote, who) => {
    const nullifier = nullifierOf(voter.s, PETITION_ID)
    const proofInputs = {
      previousCiphertext: undefined, vote, publicKey,
      enrollmentSecret: voter.s, merklePath: voter.path, merklePathIndices: voter.indices,
      enrollmentRoot: root, nullifier, petitionId: PETITION_ID, isMaskVote: false,
    }
    console.log(`  ${who}: generating fold proof (~130s)…`)
    const t0 = Date.now()
    const { circuitInputs, encryptedVote } = await generateCircuitInputsImpl(proofInputs)
    const proof = await generateProof(circuitInputs)
    const realProof = { ...proof, encryptedVote }
    console.log(`  ${who}: proof generated in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
    const encoded = encodeSolidityProof(realProof, false)
    const res = await postJson('/qes/broadcast', {
      round_id: e3Id, encoded_proof: encoded, enrollment_root: root.toString(),
    })
    const body = await res.json().catch(async () => ({ raw: await res.text().catch(() => '') }))
    if (!res.ok || body.status !== 'success') throw new Error(`${who} broadcast rejected (http ${res.status}): ${JSON.stringify(body)}`)
    const slotIdx = await publicClient.readContract({ address: PROGRAM_ADDRESS, abi: QES_PROGRAM_ABI, functionName: 'getSlotIndex', args: [BigInt(e3Id), nullifierToBytes32(nullifier)] })
    if (Number(slotIdx) < 0) throw new Error(`${who}: on-chain getSlotIndex returned ${slotIdx} (slot not created)`)
    const slots = await activeSlots(e3Id)
    if (!slots.find((sl) => BigInt(sl.nullifier) === nullifier)) throw new Error(`${who}: nullifier absent from /qes/active-slots`)
    ok(`${who} vote accepted (slot index=${slotIdx}, vote=[${vote.join(',')}])`)
  }

  // ── STAGE 5: voter1 casts Cats [1,0].
  stage('voter1 casts Cats [1,0]')
  await castVote(voter1, [1, 0], 'voter1')

  // ── STAGE 6: recalc -> [1,0].
  stage('recalc (1 vote) -> assert [1,0]')
  await recalc('after voter1', [1, 0])

  // ── STAGE 7: voter2 casts Dogs [0,1].
  stage('voter2 casts Dogs [0,1]')
  await castVote(voter2, [0, 1], 'voter2')

  // ── STAGE 8: recalc -> [1,1].
  stage('recalc (2 votes) -> assert [1,1]')
  await recalc('after voter2', [1, 1])

  console.log(`\nALL STAGES PASSED — live tally climbed 0 -> 1 -> 2 on e3Id=${e3Id}.`)
  console.log(`E3_ID=${e3Id}`)
}

main().then(() => process.exit(0)).catch((e) => { console.error(`\n✗ FAILED: ${e?.stack ?? e}`); process.exit(1) })
