import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react'

export type ToastKind = 'success' | 'error' | 'warning' | 'info'

interface ToastItem {
  id: number
  kind: ToastKind
  message: string
}

interface ToastContextValue {
  toast: (kind: ToastKind, message: string) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}

const kindStyles: Record<ToastKind, { box: string; Icon: typeof Info }> = {
  success: { box: 'border-success/40 text-success', Icon: CheckCircle2 },
  error: { box: 'border-danger/40 text-danger', Icon: XCircle },
  warning: { box: 'border-warning/40 text-warning', Icon: AlertTriangle },
  info: { box: 'border-border text-text-primary', Icon: Info },
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const nextId = useRef(0)

  const dismiss = useCallback((id: number) => {
    setItems((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const toast = useCallback(
    (kind: ToastKind, message: string) => {
      const id = ++nextId.current
      setItems((prev) => [...prev.slice(-4), { id, kind, message }])
      window.setTimeout(() => dismiss(id), kind === 'error' ? 8000 : 4000)
    },
    [dismiss],
  )

  const value = useMemo(() => ({ toast }), [toast])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-4 z-[60] flex flex-col items-center gap-2.5 px-4 sm:items-end sm:pr-6">
        {items.map(({ id, kind, message }) => {
          const { box, Icon } = kindStyles[kind]
          return (
            <div
              key={id}
              role="status"
              className={`animate-modal-pop pointer-events-auto flex w-full max-w-md items-start gap-3 rounded-xl border bg-surface-1/95 p-3.5 shadow-2xl backdrop-blur-xl transition-all ${box}`}
            >
              <Icon className="mt-0.5 size-5 shrink-0" />
              <p className="flex-1 text-sm font-medium text-text-primary leading-snug">{message}</p>
              <button
                type="button"
                className="rounded-lg p-1 text-text-secondary hover:bg-surface-2 hover:text-text-primary transition-colors cursor-pointer"
                onClick={() => dismiss(id)}
                aria-label="Dismiss"
              >
                <X className="size-4" />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

