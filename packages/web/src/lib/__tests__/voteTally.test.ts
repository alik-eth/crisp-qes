import { describe, it, expect, vi } from 'vitest'
import { toResults, winningOption, fetchTally } from '../voteTally'

describe('toResults', () => {
  it('zips labels with counts', () => {
    expect(toResults(['Cats', 'Dogs', 'Both'], [4n, 7n, 1n])).toEqual([
      { label: 'Cats', count: 4n },
      { label: 'Dogs', count: 7n },
      { label: 'Both', count: 1n },
    ])
  })
  it('throws on length mismatch', () => {
    expect(() => toResults(['A'], [1n, 2n])).toThrow()
  })
})

describe('winningOption', () => {
  it('returns the highest-count option', () => {
    expect(winningOption([{ label: 'A', count: 4n }, { label: 'B', count: 7n }])).toEqual({ label: 'B', count: 7n })
  })
  it('returns null when all zero', () => {
    expect(winningOption([{ label: 'A', count: 0n }, { label: 'B', count: 0n }])).toBeNull()
  })
})

describe('fetchTally', () => {
  it('normalizes the contract result to bigint[]', async () => {
    const read = vi.fn(async (_e3Id: bigint) => [1n, 2n, 3n] as readonly bigint[])
    expect(await fetchTally(read, 5n)).toEqual([1n, 2n, 3n])
    expect(read).toHaveBeenCalledWith(5n)
  })
})
