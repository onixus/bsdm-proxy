import { useState } from 'react'
import { BookOpen, ChevronDown, ChevronUp } from 'lucide-react'
import { translations, type Language } from '../../lib/i18n'

export function PoliciesHelp({ lang }: { lang: Language }) {
  const tr = translations[lang]
  const [open, setOpen] = useState(true)
  const sections = [
    { title: tr.policies.helpCatTitle, body: tr.policies.helpCatBody },
    { title: tr.policies.helpCatalogTitle, body: tr.policies.helpCatalogBody },
    { title: tr.policies.helpDomainTitle, body: tr.policies.helpDomainBody },
    { title: tr.policies.helpButtonsTitle, body: tr.policies.helpButtonsBody },
    { title: tr.policies.helpPriorityTitle, body: tr.policies.helpPriorityBody },
  ]

  return (
    <section className="rounded-2xl border border-border/80 bg-surface-1/70 p-5">
      <button
        type="button"
        className="flex w-full items-center justify-between gap-3 text-left"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span className="flex items-center gap-2 text-sm font-bold text-text-primary">
          <BookOpen className="size-4 text-accent" />
          {tr.policies.helpTitle}
        </span>
        <span className="inline-flex items-center gap-1 text-xs font-semibold text-text-secondary">
          {open ? tr.policies.helpHide : tr.policies.helpShow}
          {open ? <ChevronUp className="size-4" /> : <ChevronDown className="size-4" />}
        </span>
      </button>
      {open && (
        <div className="mt-4 space-y-4">
          <p className="text-sm leading-relaxed text-text-secondary">{tr.policies.helpIntro}</p>
          <ol className="space-y-3">
            {sections.map((section, index) => (
              <li key={section.title} className="rounded-xl border border-border/60 bg-surface-0/60 p-3">
                <p className="text-sm font-semibold text-text-primary">
                  <span className="mr-2 font-mono text-xs text-accent">{index + 1}.</span>
                  {section.title}
                </p>
                <p className="mt-1.5 text-sm leading-relaxed text-text-secondary">{section.body}</p>
              </li>
            ))}
          </ol>
          <p className="text-xs text-text-secondary">
            docs/features/acl-console.md · docs/features/acl-policy.md · docs/features/categorization.md
          </p>
        </div>
      )}
    </section>
  )
}
