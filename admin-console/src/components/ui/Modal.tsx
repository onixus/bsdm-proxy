import { useEffect, useState, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { Button } from './Button'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  wide?: boolean
}

export function Modal({ open, onClose, title, children, footer, wide }: ModalProps) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-black/70 p-0 sm:items-center sm:p-4"
      onClick={onClose}
      role="presentation"
    >
      <div
        className={`flex max-h-[90vh] w-full flex-col rounded-t-xl border border-border bg-surface-1 shadow-2xl sm:rounded-xl ${wide ? 'sm:max-w-3xl' : 'sm:max-w-lg'}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3 sm:px-6">
          <h2 id="modal-title" className="text-lg font-semibold text-text-primary">
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="touch-target flex items-center justify-center rounded-md p-2 text-text-secondary hover:bg-surface-2 hover:text-text-primary"
            aria-label="Close"
          >
            <X className="size-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-4 py-4 sm:px-6">{children}</div>
        {footer && (
          <div className="flex flex-wrap gap-2 border-t border-border px-4 py-3 sm:px-6">
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}

export function CodePreview({ content }: { content: string }) {
  return (
    <pre className="overflow-x-auto rounded-md border border-border bg-surface-0 p-4 font-mono text-xs leading-relaxed text-success whitespace-pre-wrap">
      {content}
    </pre>
  )
}

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      variant="secondary"
      onClick={() =>
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1500)
        })
      }
    >
      {copied ? 'Copied ✓' : 'Copy'}
    </Button>
  )
}
