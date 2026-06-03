import { describe, it, expect } from 'vitest'
import { oneHotVote } from '../vote'

describe('oneHotVote', () => {
  it('builds a one-hot vector of length numOptions', () => {
    expect(oneHotVote(2, 3)).toEqual([0, 0, 1])
    expect(oneHotVote(0, 3)).toEqual([1, 0, 0])
    expect(oneHotVote(1, 2)).toEqual([0, 1])
  })
  it('rejects out-of-range or non-integer selection', () => {
    expect(() => oneHotVote(3, 3)).toThrow()
    expect(() => oneHotVote(-1, 3)).toThrow()
    expect(() => oneHotVote(1.5, 3)).toThrow()
  })
})
