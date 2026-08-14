import type { AclRule } from '../../api/acl'

export type CategoryGroup = 'security' | 'content' | 'apps' | 'network' | 'other'

export interface AclCategoryDef {
  /** Value stored in `rule_type.Category` and compared to `Category::acl_name()`. */
  id: string
  group: CategoryGroup
  label: { en: string; ru: string }
  defaultPriority: number
  /** UT1 directory name(s) that map to this ACL id. Empty = engine-only (RKN, aliases). */
  ut1: string[]
}

/** Known ACL names. This is a static catalog, not a live UT1 inventory. */
export const ACL_CATEGORIES: AclCategoryDef[] = [
  { id: 'malware', group: 'security', label: { en: 'Malware', ru: 'Вредоносное ПО' }, defaultPriority: 180, ut1: ['malware', 'cryptojacking', 'stalkerware'] },
  { id: 'phishing', group: 'security', label: { en: 'Phishing', ru: 'Фишинг' }, defaultPriority: 180, ut1: ['phishing'] },
  { id: 'spyware', group: 'security', label: { en: 'Spyware', ru: 'Шпионское ПО' }, defaultPriority: 180, ut1: [] },
  { id: 'hacking', group: 'security', label: { en: 'Hacking', ru: 'Взлом' }, defaultPriority: 180, ut1: ['hacking', 'ddos'] },
  { id: 'rkn', group: 'security', label: { en: 'RKN registry', ru: 'Реестр РКН' }, defaultPriority: 180, ut1: [] },
  { id: 'adult', group: 'content', label: { en: 'Adult', ru: 'Для взрослых' }, defaultPriority: 150, ut1: ['adult'] },
  { id: 'gambling', group: 'content', label: { en: 'Gambling', ru: 'Азартные игры' }, defaultPriority: 150, ut1: ['gambling'] },
  { id: 'violence', group: 'content', label: { en: 'Violence', ru: 'Насилие' }, defaultPriority: 150, ut1: ['agressif'] },
  { id: 'weapons', group: 'content', label: { en: 'Weapons / warez', ru: 'Оружие / warez' }, defaultPriority: 150, ut1: ['dangerous_material', 'warez'] },
  { id: 'drugs', group: 'content', label: { en: 'Drugs', ru: 'Наркотики' }, defaultPriority: 150, ut1: ['drogue'] },
  { id: 'social', group: 'apps', label: { en: 'Social networks', ru: 'Социальные сети' }, defaultPriority: 140, ut1: ['social_networks'] },
  { id: 'filehosting', group: 'apps', label: { en: 'Cloud / file hosting', ru: 'Облачные хранилища' }, defaultPriority: 140, ut1: ['filehosting'] },
  { id: 'chat', group: 'apps', label: { en: 'Chat / messengers', ru: 'Чаты / мессенджеры' }, defaultPriority: 140, ut1: ['chat'] },
  { id: 'webmail', group: 'apps', label: { en: 'Webmail', ru: 'Веб-почта' }, defaultPriority: 140, ut1: ['webmail'] },
  { id: 'download', group: 'apps', label: { en: 'Downloads', ru: 'Загрузки' }, defaultPriority: 140, ut1: ['download'] },
  { id: 'dating', group: 'apps', label: { en: 'Dating', ru: 'Знакомства' }, defaultPriority: 140, ut1: ['dating'] },
  { id: 'vpn', group: 'network', label: { en: 'VPN', ru: 'VPN' }, defaultPriority: 140, ut1: ['vpn'] },
  { id: 'doh', group: 'network', label: { en: 'DNS-over-HTTPS', ru: 'DNS-over-HTTPS' }, defaultPriority: 140, ut1: ['doh'] },
  { id: 'redirector', group: 'network', label: { en: 'Redirectors', ru: 'Редиректоры' }, defaultPriority: 140, ut1: ['redirector', 'strict_redirector', 'strong_redirector'] },
  { id: 'tracker', group: 'network', label: { en: 'Trackers', ru: 'Трекеры' }, defaultPriority: 140, ut1: [] },
  { id: 'shortener', group: 'network', label: { en: 'URL shorteners', ru: 'Сокращатели ссылок' }, defaultPriority: 140, ut1: ['shortener'] },
  { id: 'adv', group: 'network', label: { en: 'Advertising', ru: 'Реклама' }, defaultPriority: 140, ut1: ['publicite', 'marketingware'] },
  { id: 'news', group: 'other', label: { en: 'News', ru: 'Новости' }, defaultPriority: 120, ut1: ['press'] },
  { id: 'education', group: 'other', label: { en: 'Education', ru: 'Образование' }, defaultPriority: 120, ut1: ['child', 'liste_bu'] },
  { id: 'finance', group: 'other', label: { en: 'Finance', ru: 'Финансы' }, defaultPriority: 120, ut1: ['bank', 'financial'] },
  { id: 'shopping', group: 'other', label: { en: 'Shopping', ru: 'Покупки' }, defaultPriority: 120, ut1: ['shopping'] },
  { id: 'entertainment', group: 'other', label: { en: 'Entertainment', ru: 'Развлечения' }, defaultPriority: 120, ut1: ['audio-video', 'games', 'manga'] },
  { id: 'sports', group: 'other', label: { en: 'Sports', ru: 'Спорт' }, defaultPriority: 120, ut1: ['sports'] },
  { id: 'technology', group: 'other', label: { en: 'Technology', ru: 'Технологии' }, defaultPriority: 120, ut1: ['ai'] },
  { id: 'business', group: 'other', label: { en: 'Business', ru: 'Бизнес' }, defaultPriority: 120, ut1: ['jobsearch'] },
  { id: 'government', group: 'other', label: { en: 'Government', ru: 'Госуслуги' }, defaultPriority: 120, ut1: ['arjel'] },
  { id: 'health', group: 'other', label: { en: 'Health', ru: 'Здоровье' }, defaultPriority: 120, ut1: [] },
  { id: 'forums', group: 'other', label: { en: 'Forums', ru: 'Форумы' }, defaultPriority: 120, ut1: ['forums'] },
  { id: 'blog', group: 'other', label: { en: 'Blogs', ru: 'Блоги' }, defaultPriority: 120, ut1: ['blog'] },
  { id: 'fakenews', group: 'other', label: { en: 'Fake news', ru: 'Фейковые новости' }, defaultPriority: 140, ut1: ['fakenews'] },
]

export const CATEGORY_GROUP_ORDER: CategoryGroup[] = ['security', 'content', 'apps', 'network', 'other']

export function categoryOfRule(rule: AclRule): string | null {
  const raw = rule.rule_type ?? {}
  const value = raw.Category ?? raw.category
  return typeof value === 'string' && value.trim() ? value.trim().toLowerCase() : null
}

export function isCategoryRule(rule: AclRule): boolean {
  return categoryOfRule(rule) !== null
}

export function findCategoryDef(id: string): AclCategoryDef | undefined {
  const slug = id.trim().toLowerCase()
  return ACL_CATEGORIES.find((item) => item.id === slug)
}

export function categoryRuleId(category: string): string {
  const slug = category
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return `block-${slug || 'category'}`
}

export function allocateCategoryRuleId(category: string, existingIds: Iterable<string>): string {
  const taken = new Set(existingIds)
  const base = categoryRuleId(category)
  if (!taken.has(base)) return base
  let n = 2
  while (taken.has(`${base}-${n}`)) n += 1
  return `${base}-${n}`
}

export function defaultCategoryRule(
  category: string,
  existingIds: Iterable<string>,
  lang: 'en' | 'ru' = 'en',
): AclRule {
  const slug = category.trim().toLowerCase()
  const def = findCategoryDef(slug)
  const label = def ? def.label[lang] : slug
  return {
    id: allocateCategoryRuleId(slug, existingIds),
    name: lang === 'ru' ? `Блок: ${label}` : `Block ${label}`,
    enabled: true,
    priority: def?.defaultPriority ?? 140,
    action: 'deny',
    rule_type: { Category: slug },
    comment: null,
  }
}

export function withCategory(rule: AclRule, category: string): AclRule {
  return {
    ...rule,
    rule_type: { Category: category.trim().toLowerCase() },
  }
}

/** Catalog rows plus any Category rules whose slug is not in the built-in list. */
export function categoryRows(rules: AclRule[]): { def: AclCategoryDef; rules: AclRule[] }[] {
  const byCategory = new Map<string, AclRule[]>()
  for (const rule of rules) {
    const slug = categoryOfRule(rule)
    if (!slug) continue
    const list = byCategory.get(slug) ?? []
    list.push(rule)
    byCategory.set(slug, list)
  }

  const rows: { def: AclCategoryDef; rules: AclRule[] }[] = ACL_CATEGORIES.map((def) => ({
    def,
    rules: byCategory.get(def.id) ?? [],
  }))

  for (const [slug, extra] of byCategory) {
    if (findCategoryDef(slug)) continue
    rows.push({
      def: {
        id: slug,
        group: 'other',
        label: { en: slug, ru: slug },
        defaultPriority: 140,
        ut1: [],
      },
      rules: extra,
    })
  }
  return rows
}

export type CategoryRow = { def: AclCategoryDef; rules: AclRule[] }

/** Only categories that already have an ACL Category rule. */
export function liveCategoryRows(rules: AclRule[]): CategoryRow[] {
  return categoryRows(rules).filter((row) => row.rules.length > 0)
}

/** Catalog entries with no Category rule yet — not live policy. */
export function unusedCatalog(rules: AclRule[]): AclCategoryDef[] {
  const used = new Set(rules.map(categoryOfRule).filter((id): id is string => Boolean(id)))
  return ACL_CATEGORIES.filter((def) => !used.has(def.id))
}
