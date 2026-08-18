import { translations, type Language } from './i18n'
import { resolveRouteScope, type RouteCategoryKey, type RouteTitleKey } from './routeScope'

/** Compile-time guarantee that every route key has copy in both languages. */
type RouteCopy = (typeof translations)[Language]['routes']
type _AssertTitles = RouteTitleKey extends Exclude<keyof RouteCopy, 'categories'> ? true : never
type _AssertCategories = RouteCategoryKey extends keyof RouteCopy['categories'] ? true : never
export type RouteCopyContract = [_AssertTitles, _AssertCategories]

/**
 * Breadcrumb-ready route info in the operator's language. The English fields on
 * RouteScope stay as a fallback for non-UI callers (tests, docs tooling).
 */
export function localizedRouteScope(pathname: string, lang: Language) {
  const route = resolveRouteScope(pathname)
  const t = translations[lang]

  return {
    route,
    t,
    title: t.routes[route.titleKey],
    category: t.routes.categories[route.categoryKey],
  }
}
