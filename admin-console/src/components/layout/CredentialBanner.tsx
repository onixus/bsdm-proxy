import { Link } from 'react-router-dom'
import { KeyRound } from 'lucide-react'

interface CredentialBannerProps {
  visible: boolean
}

export function CredentialBanner({ visible }: CredentialBannerProps) {
  if (!visible) return null

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-warning/30 bg-warning/10 px-4 py-2.5 text-sm text-warning sm:px-6">
      <div className="flex items-center gap-2">
        <KeyRound className="size-4 shrink-0" />
        <span>
          <strong>Read-only safety mode.</strong> Mutating API requests are blocked until a token is attached.
        </span>
      </div>
      <Link
        to="/settings?tab=api"
        className="rounded-md border border-warning/40 bg-warning/10 px-3 py-1.5 text-xs font-bold transition-colors hover:bg-warning/20"
      >
        Attach API token
      </Link>
    </div>
  )
}
