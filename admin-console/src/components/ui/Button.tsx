import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  children: ReactNode
}

const variants: Record<Variant, string> = {
  primary: 'bg-accent hover:bg-accent-hover text-white border-transparent',
  secondary: 'bg-surface-2 hover:bg-surface-3 text-text-primary border-border',
  ghost: 'bg-transparent hover:bg-surface-2 text-text-secondary border-transparent',
  danger: 'bg-danger/20 hover:bg-danger/30 text-danger border-danger/40',
}

export function Button({ variant = 'primary', className = '', children, ...props }: ButtonProps) {
  return (
    <button
      type="button"
      className={`touch-target inline-flex items-center justify-center gap-2 rounded-md border px-4 py-2 text-sm font-semibold transition-colors disabled:opacity-50 ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}
