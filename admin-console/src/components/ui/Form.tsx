import type { InputHTMLAttributes } from 'react'

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  envKey?: string
  badge?: string
  hint?: string
}

export function Input({ label, envKey, badge, hint, id, className = '', ...props }: InputProps) {
  const inputId = id ?? label.toLowerCase().replace(/\s+/g, '-')
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center justify-between gap-1">
        <label htmlFor={inputId} className="block text-sm font-semibold text-text-primary">
          {label}
        </label>
        <div className="flex items-center gap-1.5">
          {envKey && (
            <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] font-medium text-text-secondary border border-border">
              {envKey}
            </span>
          )}
          {badge && (
            <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-semibold text-accent border border-accent/20">
              {badge}
            </span>
          )}
        </div>
      </div>
      <input
        id={inputId}
        className={`touch-target w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary placeholder:text-text-secondary focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 ${className}`}
        {...props}
      />
      {hint && <p className="text-xs leading-relaxed text-text-secondary">{hint}</p>}
    </div>
  )
}

interface SelectProps extends InputHTMLAttributes<HTMLSelectElement> {
  label: string
  envKey?: string
  badge?: string
  options: { value: string; label: string }[]
  hint?: string
}

export function Select({ label, envKey, badge, options, hint, id, className = '', ...props }: SelectProps) {
  const selectId = id ?? label.toLowerCase().replace(/\s+/g, '-')
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center justify-between gap-1">
        <label htmlFor={selectId} className="block text-sm font-semibold text-text-primary">
          {label}
        </label>
        <div className="flex items-center gap-1.5">
          {envKey && (
            <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] font-medium text-text-secondary border border-border">
              {envKey}
            </span>
          )}
          {badge && (
            <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-semibold text-accent border border-accent/20">
              {badge}
            </span>
          )}
        </div>
      </div>
      <select
        id={selectId}
        className={`touch-target w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 ${className}`}
        {...props}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {hint && <p className="text-xs leading-relaxed text-text-secondary">{hint}</p>}
    </div>
  )
}

interface CheckboxProps {
  label: string
  envKey?: string
  badge?: string
  checked: boolean
  onChange: (checked: boolean) => void
  hint?: string
  id?: string
}

export function Checkbox({ label, envKey, badge, checked, onChange, hint, id }: CheckboxProps) {
  const cbId = id ?? label.toLowerCase().replace(/\s+/g, '-')
  return (
    <div className="space-y-1 rounded-lg border border-border/50 bg-surface-0/50 p-3 hover:bg-surface-0">
      <div className="flex items-start justify-between gap-2">
        <label htmlFor={cbId} className="flex min-h-[var(--touch-min)] cursor-pointer items-center gap-3 text-sm font-medium text-text-primary">
          <input
            id={cbId}
            type="checkbox"
            checked={checked}
            onChange={(e) => onChange(e.target.checked)}
            className="size-5 shrink-0 accent-accent"
          />
          <span>{label}</span>
        </label>
        <div className="flex items-center gap-1.5">
          {envKey && (
            <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] font-medium text-text-secondary border border-border">
              {envKey}
            </span>
          )}
          {badge && (
            <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-semibold text-accent border border-accent/20">
              {badge}
            </span>
          )}
        </div>
      </div>
      {hint && <p className="pl-8 text-xs leading-relaxed text-text-secondary">{hint}</p>}
    </div>
  )
}

export function FormSection({ title, badge, description, children }: { title: string; badge?: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="space-y-4 rounded-xl border border-border/80 bg-surface-1/80 p-5 shadow-sm">
      <div className="border-b border-border/60 pb-3">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-base font-bold text-accent">{title}</h3>
          {badge && (
            <span className="rounded-full bg-accent/10 px-2.5 py-0.5 text-xs font-semibold text-accent border border-accent/30">
              {badge}
            </span>
          )}
        </div>
        {description && <p className="mt-1 text-xs text-text-secondary">{description}</p>}
      </div>
      <div className="space-y-4">
        {children}
      </div>
    </section>
  )
}

export function FormGrid({ children }: { children: React.ReactNode }) {
  return <div className="grid gap-4 sm:grid-cols-2 items-start">{children}</div>
}

export function FormField({
  label,
  required,
  children,
}: {
  label: string
  required?: boolean
  children: React.ReactNode
}) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-semibold text-text-primary">
        {label} {required && <span className="text-accent">*</span>}
      </label>
      {children}
    </div>
  )
}
