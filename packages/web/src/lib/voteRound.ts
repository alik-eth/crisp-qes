import { createPublicClient, http, type Address } from 'viem'

/** A CRISP FHE voting round, as surfaced to the UI. */
export type VoteRound = {
  e3Id: bigint
  question: string
  options: string[]
  numOptions: number
  enrollmentRoot: `0x${string}`
  deadline: bigint
  isOpen: (nowSec: number) => boolean
}

/** The on-chain BallotRegistry.Round struct shape (as returned by viem). */
export type RawRound = {
  question: string
  optionLabels: readonly string[]
  enrollmentRoot: string
  deadline: bigint
  numOptions: number
  exists: boolean
}

/** Map an on-chain Round struct (+ its e3Id) to the UI shape. */
export function parseRound(e3Id: bigint, raw: RawRound): VoteRound {
  return {
    e3Id,
    question: raw.question,
    options: [...raw.optionLabels],
    numOptions: raw.numOptions,
    enrollmentRoot: raw.enrollmentRoot as `0x${string}`,
    deadline: raw.deadline,
    isOpen: (nowSec: number) => raw.exists && BigInt(nowSec) < raw.deadline,
  }
}

export const BALLOT_REGISTRY_ABI = [
  { type: 'function', name: 'roundCount', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'roundIds', stateMutability: 'view', inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }] },
  {
    type: 'function',
    name: 'getRound',
    stateMutability: 'view',
    inputs: [{ type: 'uint256' }],
    outputs: [
      {
        type: 'tuple',
        components: [
          { name: 'question', type: 'string' },
          { name: 'optionLabels', type: 'string[]' },
          { name: 'enrollmentRoot', type: 'bytes32' },
          { name: 'deadline', type: 'uint64' },
          { name: 'numOptions', type: 'uint32' },
          { name: 'exists', type: 'bool' },
        ],
      },
    ],
  },
] as const

/** Read all rounds from the BallotRegistry on the operator chain. */
export async function fetchRounds(rpcUrl: string, ballotRegistry: Address): Promise<VoteRound[]> {
  const client = createPublicClient({ transport: http(rpcUrl) })
  const count = (await client.readContract({
    address: ballotRegistry,
    abi: BALLOT_REGISTRY_ABI,
    functionName: 'roundCount',
  })) as bigint

  const rounds: VoteRound[] = []
  for (let i = 0n; i < count; i++) {
    const e3Id = (await client.readContract({
      address: ballotRegistry,
      abi: BALLOT_REGISTRY_ABI,
      functionName: 'roundIds',
      args: [i],
    })) as bigint
    const raw = (await client.readContract({
      address: ballotRegistry,
      abi: BALLOT_REGISTRY_ABI,
      functionName: 'getRound',
      args: [e3Id],
    })) as unknown as RawRound
    rounds.push(parseRound(e3Id, raw))
  }
  return rounds
}
