import type { ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import { FrozenModuleBanner } from '../ui/DataState'
import { useLanguage } from '../../lib/i18n'
import { localizedRouteScope } from '../../lib/routeCopy'

/**
 * Wraps deep-linked experimental pages so operators never mistake them for
 * supported Hybrid pilot UI.
 */
export function FrozenRouteShell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation()
  const [lang] = useLanguage()
  const { route, title } = localizedRouteScope(pathname, lang)

  return (
    <div className="space-y-4">
      <FrozenModuleBanner feature={title} note={route.frozenNote} />
      <div className="opacity-95">{children}</div>
    </div>
  )
}
