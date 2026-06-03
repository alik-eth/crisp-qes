import { describe, it, expect } from 'vitest'
import { parseRound } from '../voteRound'

describe('parseRound', () => {
  it('maps an on-chain Round struct + e3Id to the UI shape', () => {
    const raw = {
      question: 'Cats or dogs?',
      optionLabels: ['Cats', 'Dogs', 'Both'] as const,
      enrollmentRoot: '0x1b49',
      deadline: 1893456000n,
      numOptions: 3,
      exists: true,
    }
    const r = parseRound(42n, raw)
    expect(r.e3Id).toBe(42n)
    expect(r.options).toEqual(['Cats', 'Dogs', 'Both'])
    expect(r.numOptions).toBe(3)
    expect(r.enrollmentRoot).toBe('0x1b49')
    expect(r.deadline).toBe(1893456000n)
  })

  it('isOpen reflects the deadline', () => {
    const raw = {
      question: 'q',
      optionLabels: ['A', 'B'] as const,
      enrollmentRoot: '0x00',
      deadline: 1893456000n,
      numOptions: 2,
      exists: true,
    }
    const r = parseRound(1n, raw)
    expect(r.isOpen(1893000000)).toBe(true)
    expect(r.isOpen(1893456001)).toBe(false)
  })

  it('a non-existent round is never open', () => {
    const raw = {
      question: '',
      optionLabels: [] as const,
      enrollmentRoot: '0x00',
      deadline: 9999999999n,
      numOptions: 0,
      exists: false,
    }
    expect(parseRound(7n, raw).isOpen(0)).toBe(false)
  })
})
