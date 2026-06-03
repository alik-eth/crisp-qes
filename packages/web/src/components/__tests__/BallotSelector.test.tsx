// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { BallotSelector } from '../BallotSelector'

afterEach(cleanup)

describe('BallotSelector', () => {
  it('selects exactly one option (one-hot) and reports its index', () => {
    const onSelect = vi.fn()
    render(<BallotSelector options={['Cats', 'Dogs', 'Both']} onSelect={onSelect} />)

    fireEvent.click(screen.getByText('Dogs'))
    expect(onSelect).toHaveBeenLastCalledWith(1)

    fireEvent.click(screen.getByText('Both'))
    expect(onSelect).toHaveBeenLastCalledWith(2)

    // only the last-clicked option is selected
    expect(screen.getByText('Both').getAttribute('aria-checked')).toBe('true')
    expect(screen.getByText('Dogs').getAttribute('aria-checked')).toBe('false')
    expect(screen.getByText('Cats').getAttribute('aria-checked')).toBe('false')
  })

  it('renders one radio per option', () => {
    render(<BallotSelector options={['A', 'B']} onSelect={() => {}} />)
    expect(screen.getAllByRole('radio')).toHaveLength(2)
  })
})
