import { useEffect, useState, type ReactNode } from 'react'
import { X, Check, Copy } from 'lucide-react'
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
      className="fixed inset-0 z-50 flex items-end justify-center bg-black/80 backdrop-blur-md p-0 sm:items-center sm:p-4 transition-opacity"
      onClick={onClose}
      role="presentation"
    >
      <div
        className={`animate-modal-pop flex max-h-[90vh] w-full flex-col rounded-t-2xl border border-border bg-surface-1/95 shadow-2xl backdrop-blur-xl sm:rounded-2xl ${wide ? 'sm:max-w-3xl' : 'sm:max-w-lg'}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        <div className="flex items-center justify-between border-b border-border/80 px-5 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <h2 id="modal-title" className="text-lg font-bold text-text-primary tracking-tight">
              {title}
            </h2>
            <span className="hidden sm:inline-flex items-center rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
              ESC
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="touch-target flex items-center justify-center rounded-lg p-2 text-text-secondary hover:bg-surface-2 hover:text-text-primary transition-colors cursor-pointer"
            aria-label="Close"
          >
            <X className="size-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-5 sm:px-6">{children}</div>
        {footer && (
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border/80 px-5 py-3.5 bg-surface-1/50 rounded-b-2xl sm:px-6">
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}



export function CodePreview({ content }: { content: string }) {
  return (
    <pre className="overflow-x-auto rounded-md border border-border bg-surface-0 p-4 font-mono text-xs leading-relaxed text-success whitespace-pre-wrap select-all">
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
          window.setTimeout(() => setCopied(false), 2000)
        })
      }
    >
      {copied ? (
        <>
          <Check className="size-4 text-success" />
          <span>Copied!</span>
        </>
      ) : (
        <>
          <Copy className="size-4" />
          <span>Copy</span>
        </>
      )}
    </Button>
  )
}

