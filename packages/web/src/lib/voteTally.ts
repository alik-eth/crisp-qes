export type OptionResult = { label: string; count: bigint }

/** Zip option labels with their decoded vote counts. */
export function toResults(labels: string[], counts: bigint[]): OptionResult[] {
  if (labels.length !== counts.length) throw new Error('labels/counts length mismatch')
  return labels.map((label, i) => ({ label, count: counts[i]! }))
}

/** The option with the most votes (null on an empty/tied-at-zero tally). */
export function winningOption(results: OptionResult[]): OptionResult | null {
  let best: OptionResult | null = null
  for (const r of results) {
    if (r.count > 0n && (best === null || r.count > best.count)) best = r
  }
  return best
}

/**
 * Read the decoded per-option tally for a finished round from
 * CRISPQESProgram.decodeTally(e3Id). `readDecodeTally` is injected (a viem
 * readContract bound to the program) so this stays pure + unit-testable.
 */
export async function fetchTally(
  readDecodeTally: (e3Id: bigint) => Promise<readonly bigint[]>,
  e3Id: bigint,
): Promise<bigint[]> {
  const raw = await readDecodeTally(e3Id)
  return raw.map((x) => BigInt(x))
}
