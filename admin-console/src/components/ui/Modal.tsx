import { useEffect, useState, type ReactNode } from 'react'
import { X, Check, Copy } from 'lucide-react'
import { useT } from '../../lib/i18n'
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
  const t = useT()

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
        className={`animate-modal-pop flex max-h-[92vh] w-full flex-col sm:max-h-[88vh] rounded-t-2xl border border-border bg-surface-1/95 shadow-2xl backdrop-blur-xl sm:rounded-2xl ${wide ? 'sm:max-w-4xl' : 'sm:max-w-xl'}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        <div className="flex items-center justify-between gap-3 border-b border-border/80 px-5 py-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <h2 id="modal-title" className="truncate text-base font-bold tracking-tight text-text-primary sm:text-lg">
              {title}
            </h2>
            <span className="hidden sm:inline-flex items-center rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
              ESC
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="touch-target flex shrink-0 cursor-pointer items-center justify-center rounded-lg p-2 text-text-secondary transition-colors hover:bg-surface-2 hover:text-text-primary"
            aria-label={t.ui.close}
            title={t.ui.close}
          >
            <X className="size-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-5 sm:px-6">{children}</div>
        {footer && (
          <div className="flex flex-col-reverse gap-2 border-t border-border/80 bg-surface-1/50 px-5 py-3.5 sm:flex-row sm:flex-wrap sm:items-center sm:justify-end sm:rounded-b-2xl sm:px-6">
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
  const t = useT()
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
          <span>{t.ui.copied}</span>
        </>
      ) : (
        <>
          <Copy className="size-4" />
          <span>{t.ui.copy}</span>
        </>
      )}
    </Button>
  )
}

