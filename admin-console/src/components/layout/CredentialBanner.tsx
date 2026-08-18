import { Link } from 'react-router-dom'
import { KeyRound } from 'lucide-react'
import { useT } from '../../lib/i18n'

interface CredentialBannerProps {
  visible: boolean
}

export function CredentialBanner({ visible }: CredentialBannerProps) {
  const t = useT()

  if (!visible) return null

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-warning/30 bg-warning/10 px-4 py-2.5 text-sm text-warning sm:px-6">
      <div className="flex min-w-0 items-start gap-2">
        <KeyRound className="mt-0.5 size-4 shrink-0" />
        <span className="min-w-0">
          <strong>{t.banner.readOnlyTitle}</strong> {t.banner.readOnlyBody}
        </span>
      </div>
      <Link
        to="/settings?tab=api"
        className="touch-target inline-flex shrink-0 items-center rounded-md border border-warning/40 bg-warning/10 px-3 text-xs font-bold transition-colors hover:bg-warning/20"
      >
        {t.banner.attachToken}
      </Link>
    </div>
  )
}
