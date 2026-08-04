/**
 * Operator UI route maturity for Hybrid pilot honesty.
 *
 * Supported routes match primary navigation and day-1 pilot surfaces.
 * Frozen routes remain deep-linkable for developers but must never look
 * like production-ready operator features (scope freeze).
 */

export type RouteMaturity = 'supported' | 'frozen'

export interface RouteScope {
  path: string
  maturity: RouteMaturity
  title: string
  category: string
  /** Short product-status note for frozen routes. */
  frozenNote?: string
}

export const ROUTE_SCOPES: RouteScope[] = [
  { path: '/', maturity: 'supported', title: 'Dashboard', category: 'Monitoring' },
  { path: '/logs', maturity: 'supported', title: 'Proxy Logs', category: 'Monitoring' },
  { path: '/analytics', maturity: 'supported', title: 'Analytics', category: 'Monitoring' },
  { path: '/threat-scores', maturity: 'supported', title: 'Threat Scores', category: 'Monitoring' },
  {
    path: '/security',
    maturity: 'supported',
    title: 'Data Security',
    category: 'Security',
  },
  { path: '/policies', maturity: 'supported', title: 'ACL Policies', category: 'Security' },
  { path: '/rpz', maturity: 'supported', title: 'RPZ DNS', category: 'Security' },
  {
    path: '/devices',
    maturity: 'supported',
    title: 'Agent Devices',
    category: 'Security',
  },
  { path: '/users', maturity: 'supported', title: 'Users', category: 'System' },
  { path: '/settings', maturity: 'supported', title: 'Console Settings', category: 'System' },
  {
    path: '/wasm',
    maturity: 'frozen',
    title: 'Wasm Plugins',
    category: 'Experimental',
    frozenNote: 'WASM request hooks are Experimental (Frozen) in project-status.md.',
  },
  {
    path: '/cluster',
    maturity: 'frozen',
    title: 'Cluster Mesh',
    category: 'Experimental',
    frozenNote: 'Global session / threat-sync mesh is scaffolding only (Frozen).',
  },
  {
    path: '/ai-cache',
    maturity: 'frozen',
    title: 'AI Semantic Cache',
    category: 'Experimental',
    frozenNote: 'AI semantic cache UI is Beta/experimental; not pilot day-1.',
  },
  {
    path: '/amneziawg',
    maturity: 'frozen',
    title: 'AmneziaWG',
    category: 'Experimental',
    frozenNote: 'AmneziaWG / BSDM Connect is Frozen until Agent Contract work completes.',
  },
]

export function resolveRouteScope(pathname: string): RouteScope {
  const exact = ROUTE_SCOPES.find((r) => r.path === pathname)
  if (exact) return exact
  return {
    path: pathname,
    maturity: 'supported',
    title: 'BSDM Console',
    category: 'System',
  }
}

export function isFrozenPath(pathname: string): boolean {
  return resolveRouteScope(pathname).maturity === 'frozen'
}

export const FROZEN_PATHS = ROUTE_SCOPES.filter((r) => r.maturity === 'frozen').map((r) => r.path)
