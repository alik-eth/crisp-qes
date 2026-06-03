import { useState } from 'react'

/** One-hot ballot option selector (exactly one selectable at a time). */
export function BallotSelector({
  options,
  onSelect,
}: {
  options: string[]
  onSelect: (index: number) => void
}) {
  const [selected, setSelected] = useState<number | null>(null)
  return (
    <div role="radiogroup" className="ballot-selector">
      {options.map((label, i) => (
        <button
          key={i}
          type="button"
          role="radio"
          aria-pressed={selected === i}
          aria-checked={selected === i}
          className={selected === i ? 'ballot-option selected' : 'ballot-option'}
          onClick={() => {
            setSelected(i)
            onSelect(i)
          }}
        >
          {label}
        </button>
      ))}
    </div>
  )
}
