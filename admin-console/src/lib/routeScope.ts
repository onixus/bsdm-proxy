/**
 * Operator UI route maturity for Hybrid pilot honesty.
 *
 * Supported routes match primary navigation and day-1 pilot surfaces.
 * Frozen routes remain deep-linkable for developers but must never look
 * like production-ready operator features (scope freeze).
 */

export type RouteMaturity = 'supported' | 'frozen'

/**
 * Keys into `translations[lang].routes` — keeps breadcrumbs translatable.
 * Declared structurally (not derived from the copy module) so this file stays
 * dependency-free and unit-testable under plain node.
 * `lib/routeCopy.ts` asserts at compile time that the copy actually has them.
 */
export type RouteTitleKey =
  | 'dashboard'
  | 'logs'
  | 'analytics'
  | 'threatScores'
  | 'security'
  | 'policies'
  | 'rpz'
  | 'devices'
  | 'users'
  | 'settings'
  | 'wasm'
  | 'cluster'
  | 'aiCache'
  | 'amneziawg'
  | 'fallback'

export type RouteCategoryKey = 'monitoring' | 'security' | 'system' | 'experimental'

export interface RouteScope {
  path: string
  maturity: RouteMaturity
  /** English fallback label; the UI renders the translated `titleKey`. */
  title: string
  category: string
  titleKey: RouteTitleKey
  categoryKey: RouteCategoryKey
  /** Short product-status note for frozen routes. */
  frozenNote?: string
}

export const ROUTE_SCOPES: RouteScope[] = [
  { path: '/', maturity: 'supported', title: 'Dashboard', category: 'Monitoring', titleKey: 'dashboard', categoryKey: 'monitoring' },
  { path: '/logs', maturity: 'supported', title: 'Proxy Logs', category: 'Monitoring', titleKey: 'logs', categoryKey: 'monitoring' },
  { path: '/analytics', maturity: 'supported', title: 'Analytics', category: 'Monitoring', titleKey: 'analytics', categoryKey: 'monitoring' },
  { path: '/threat-scores', maturity: 'supported', title: 'Threat Scores', category: 'Monitoring', titleKey: 'threatScores', categoryKey: 'monitoring' },
  { path: '/security', maturity: 'supported', title: 'Data Security', category: 'Security', titleKey: 'security', categoryKey: 'security' },
  { path: '/policies', maturity: 'supported', title: 'ACL Policies', category: 'Security', titleKey: 'policies', categoryKey: 'security' },
  { path: '/rpz', maturity: 'supported', title: 'RPZ DNS', category: 'Security', titleKey: 'rpz', categoryKey: 'security' },
  { path: '/devices', maturity: 'supported', title: 'Agent Devices', category: 'Security', titleKey: 'devices', categoryKey: 'security' },
  { path: '/users', maturity: 'supported', title: 'Users', category: 'System', titleKey: 'users', categoryKey: 'system' },
  { path: '/settings', maturity: 'supported', title: 'Console Settings', category: 'System', titleKey: 'settings', categoryKey: 'system' },
  {
    path: '/wasm',
    maturity: 'frozen',
    title: 'Wasm Plugins',
    category: 'Experimental',
    titleKey: 'wasm',
    categoryKey: 'experimental',
    frozenNote: 'WASM request hooks are Experimental (Frozen) in project-status.md.',
  },
  {
    path: '/cluster',
    maturity: 'frozen',
    title: 'Cluster Mesh',
    category: 'Experimental',
    titleKey: 'cluster',
    categoryKey: 'experimental',
    frozenNote: 'Global session / threat-sync mesh is scaffolding only (Frozen).',
  },
  {
    path: '/ai-cache',
    maturity: 'frozen',
    title: 'AI Semantic Cache',
    category: 'Experimental',
    titleKey: 'aiCache',
    categoryKey: 'experimental',
    frozenNote: 'AI semantic cache UI is Beta/experimental; not pilot day-1.',
  },
  {
    path: '/amneziawg',
    maturity: 'frozen',
    title: 'AmneziaWG',
    category: 'Experimental',
    titleKey: 'amneziawg',
    categoryKey: 'experimental',
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
    titleKey: 'fallback',
    categoryKey: 'system',
  }
}

export function isFrozenPath(pathname: string): boolean {
  return resolveRouteScope(pathname).maturity === 'frozen'
}

export const FROZEN_PATHS = ROUTE_SCOPES.filter((r) => r.maturity === 'frozen').map((r) => r.path)
