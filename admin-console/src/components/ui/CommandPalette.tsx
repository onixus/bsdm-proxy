import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Command, Search } from 'lucide-react'
import { useLanguage } from '../../lib/i18n'
import { getNavigationItems } from '../../navigation/menu'

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const navigate = useNavigate()
  const [lang] = useLanguage()

  const items = useMemo(() => getNavigationItems(lang), [lang])

  const filtered = useMemo(() => {
    const value = query.toLowerCase().trim()
    if (!value) return items

    return items.filter((item) =>
      [item.label, item.description, item.to, ...(item.keywords ?? [])]
        .join(' ')
        .toLowerCase()
        .includes(value)
    )
  }, [items, query])

  useEffect(() => {
    if (!open) {
      setQuery('')
      setSelectedIndex(0)
    }
  }, [open])

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        window.dispatchEvent(new CustomEvent('toggle-command-palette'))
      }

      if (!open) return

      if (event.key === 'Escape') onClose()
      if (event.key === 'ArrowDown') {
        event.preventDefault()
        setSelectedIndex((index) => Math.min(index + 1, filtered.length - 1))
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault()
        setSelectedIndex((index) => Math.max(index - 1, 0))
      }
      if (event.key === 'Enter' && filtered[selectedIndex]) {
        navigate(filtered[selectedIndex].to)
        onClose()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [filtered, navigate, onClose, open, selectedIndex])

  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 p-4 pt-16 backdrop-blur-sm sm:pt-24"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="animate-modal-pop flex w-full max-w-xl flex-col overflow-hidden rounded-xl border border-border bg-surface-1 shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-border bg-surface-0/50 px-4 py-3">
          <Search className="size-5 shrink-0 text-text-secondary" />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search navigation..."
            className="w-full bg-transparent text-sm text-text-primary outline-none placeholder:text-text-secondary"
          />
          <kbd className="hidden rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] font-mono sm:inline">
            ESC
          </kbd>
        </div>

        <div className="max-h-96 overflow-y-auto p-2">
          {filtered.map((item, index) => {
            const Icon = item.icon
            return (
              <button
                key={item.to}
                type="button"
                onMouseEnter={() => setSelectedIndex(index)}
                onClick={() => {
                  navigate(item.to)
                  onClose()
                }}
                className={`group flex w-full items-center justify-between gap-3 rounded-lg p-2.5 text-left transition-colors ${
                  index === selectedIndex ? 'bg-surface-2' : 'hover:bg-surface-2'
                }`}
              >
                <div className="flex min-w-0 items-center gap-3">
                  <Icon className="size-4 shrink-0 text-text-secondary group-hover:text-accent" />
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-text-primary">{item.label}</p>
                    <p className="truncate text-xs text-text-secondary">{item.description}</p>
                  </div>
                </div>
                <ArrowRight className="size-3.5 text-text-secondary" />
              </button>
            )
          })}
        </div>

        <div className="border-t border-border bg-surface-0/30 px-4 py-2 text-[11px] text-text-secondary">
          <Command className="mr-1 inline size-3" /> ↑↓ navigate · Enter open · Esc close
        </div>
      </div>
    </div>
  )
}
