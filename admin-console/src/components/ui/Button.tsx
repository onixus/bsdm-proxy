import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Loader2 } from 'lucide-react'

type Variant = 'primary' | 'primary-glow' | 'secondary' | 'ghost' | 'danger' | 'outline'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  isLoading?: boolean
  loadingText?: string
  children: ReactNode
}

const variants: Record<Variant, string> = {
  primary: 'bg-accent hover:bg-accent-hover text-white border-transparent shadow-sm hover:shadow-md',
  'primary-glow': 'bg-accent hover:bg-accent-hover text-white border-transparent shadow-glow-accent',
  secondary: 'bg-surface-2 hover:bg-surface-3 text-text-primary border-border/80 hover:border-accent/40 shadow-xs',
  ghost: 'bg-transparent hover:bg-surface-2 text-text-secondary hover:text-text-primary border-transparent',
  danger: 'bg-danger/20 hover:bg-danger/30 text-danger border-danger/40 shadow-xs',
  outline: 'bg-transparent hover:bg-surface-2 text-text-primary border-border hover:border-accent/50',
}

export function Button({
  variant = 'primary',
  isLoading = false,
  loadingText,
  disabled,
  className = '',
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      type="button"
      disabled={disabled || isLoading}
      className={`touch-target inline-flex items-center justify-center gap-2 rounded-lg border px-4 py-2 text-sm font-semibold transition-all active:scale-[0.97] cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 disabled:active:scale-100 ${variants[variant]} ${className}`}
      {...props}
    >
      {isLoading ? (
        <>
          <Loader2 className="size-4 animate-spin shrink-0" />
          <span>{loadingText || children}</span>
        </>
      ) : (
        children
      )}
    </button>
  )
}


