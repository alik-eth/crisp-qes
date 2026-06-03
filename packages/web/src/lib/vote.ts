import type { Hex } from 'viem'

/** Build a one-hot ballot vector: 1 at `index`, 0 elsewhere. */
export function oneHotVote(index: number, numOptions: number): number[] {
  if (!Number.isInteger(index) || index < 0 || index >= numOptions) {
    throw new Error(`option ${index} out of range 0..${numOptions - 1}`)
  }
  return Array.from({ length: numOptions }, (_, i) => (i === index ? 1 : 0))
}

export type VoteWitness = {
  optionIndex: number
  numOptions: number
  /** committee BFV public key (from Enclave.getE3(e3Id).committeePublicKey) */
  publicKey: Uint8Array
  /** the enrolled secret (Merkle leaf), 20-deep path + indices against the round's root */
  enrollmentSecret: bigint
  merklePath: bigint[]
  merklePathIndices: number[]
  enrollmentRoot: bigint
  /** per-round nullifier = pedersen([enrollment_secret, e3Id, DOMAIN_PETITION_V2]) */
  nullifier: bigint
  e3Id: bigint
}

export type VotePayload = { encoded: Hex; nullifier: bigint; encryptedVote: Uint8Array }

/**
 * Encrypt + prove a real (non-mask) ballot and ABI-encode it for
 * CRISPQESProgram.publishInput. The enclave vote SDK is imported dynamically so
 * this module (and the pure `oneHotVote` above) loads without the SDK present;
 * the SDK + its WASM are wired into the web build in Task 4.0.
 */
export async function buildVotePayload(w: VoteWitness): Promise<VotePayload> {
  // @ts-expect-error '@crisp-e3/sdk' is added to the web build in Task 4.0 (SDK + WASM wiring).
  const { generateCircuitInputsImpl, generateProof, encodeSolidityProof } = await import('@crisp-e3/sdk')
  const vote = oneHotVote(w.optionIndex, w.numOptions)
  const { circuitInputs, encryptedVote } = await generateCircuitInputsImpl({
    vote,
    publicKey: w.publicKey,
    enrollmentSecret: w.enrollmentSecret,
    merklePath: w.merklePath,
    merklePathIndices: w.merklePathIndices,
    enrollmentRoot: w.enrollmentRoot,
    nullifier: w.nullifier,
    petitionId: w.e3Id, // contract forces pub[6] == e3Id
    isMaskVote: false,
  })
  const proof = await generateProof(circuitInputs)
  return { encoded: encodeSolidityProof(proof, false), nullifier: w.nullifier, encryptedVote }
}
