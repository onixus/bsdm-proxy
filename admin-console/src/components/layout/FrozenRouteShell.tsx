import type { ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import { FrozenModuleBanner } from '../ui/DataState'
import { resolveRouteScope } from '../../lib/routeScope'

/**
 * Wraps deep-linked experimental pages so operators never mistake them for
 * supported Hybrid pilot UI.
 */
export function FrozenRouteShell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation()
  const scope = resolveRouteScope(pathname)

  return (
    <div className="space-y-4">
      <FrozenModuleBanner feature={scope.title} note={scope.frozenNote} />
      <div className="opacity-95">{children}</div>
    </div>
  )
}
