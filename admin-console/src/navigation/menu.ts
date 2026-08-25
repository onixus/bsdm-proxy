import type { ComponentType } from 'react'
import {
  BarChart3,
  Brain,
  Laptop,
  LayoutDashboard,
  Lock,
  Radio,
  ScrollText,
  Settings,
  Shield,
  ShieldAlert,
  User,
} from 'lucide-react'
import type { Language } from '../lib/i18n'
import { translations } from '../lib/i18n'

export interface NavigationItem {
  to: string
  label: string
  description: string
  icon: ComponentType<{ className?: string }>
  end?: boolean
  keywords?: string[]
}

export interface NavigationGroup {
  id: string
  title: string
  items: NavigationItem[]
}

const descriptions = {
  ru: {
    dashboard: 'Состояние системы и ключевые показатели',
    logs: 'Прокси-трафик, решения политик и события',
    analytics: 'Агрегации трафика и статистика',
    threats: 'ML оценки угроз и аномалии',
    security: 'CASB, DLP и защита данных',
    policies: 'ACL правила и ограничения',
    rpz: 'DNS Response Policy Zone',
    devices: 'Агенты и устройства — Lab-only, не для продакшена',
    amneziawg: 'Туннель AmneziaWG и пиры — Lab-only, не для продакшена',
    users: 'Пользователи и роли',
    settings: 'Конфигурация и управление нодой',
  },
  en: {
    dashboard: 'System health and key indicators',
    logs: 'Proxy traffic, decisions and events',
    analytics: 'Traffic aggregates and statistics',
    threats: 'ML threat scores and anomalies',
    security: 'CASB, DLP and data protection',
    policies: 'ACL rules and restrictions',
    rpz: 'DNS Response Policy Zone',
    devices: 'Agents and connected devices — lab-only, not for production',
    amneziawg: 'AmneziaWG obfuscated tunnel and peers — lab-only, not for production',
    users: 'Users and roles',
    settings: 'Configuration and node management',
  },
} satisfies Record<Language, Record<string, string>>

export function getNavigationGroups(lang: Language): NavigationGroup[] {
  const t = translations[lang]
  const d = descriptions[lang]

  return [
    {
      id: 'monitoring',
      title: lang === 'ru' ? 'Мониторинг' : 'Monitoring',
      items: [
        { to: '/', label: t.nav.dashboard, description: d.dashboard, icon: LayoutDashboard, end: true },
        { to: '/logs', label: t.nav.logs, description: d.logs, icon: ScrollText, keywords: ['traffic'] },
        { to: '/analytics', label: t.nav.analytics, description: d.analytics, icon: BarChart3 },
        { to: '/threat-scores', label: t.nav.threatScores, description: d.threats, icon: Brain, keywords: ['ml'] },
      ],
    },
    {
      id: 'security',
      title: lang === 'ru' ? 'Безопасность' : 'Security',
      items: [
        { to: '/security', label: t.nav.security, description: d.security, icon: ShieldAlert },
        { to: '/policies', label: t.nav.policies, description: d.policies, icon: Shield },
        { to: '/rpz', label: t.nav.rpz, description: d.rpz, icon: Radio },
        { to: '/devices', label: t.nav.devices, description: d.devices, icon: Laptop },
        { to: '/amneziawg', label: t.nav.amneziawg, description: d.amneziawg, icon: Lock, keywords: ['vpn', 'tunnel', 'awg'] },
      ],
    },
    {
      id: 'system',
      title: lang === 'ru' ? 'Система' : 'System',
      items: [
        { to: '/users', label: t.nav.users, description: d.users, icon: User },
        { to: '/settings', label: t.nav.settings, description: d.settings, icon: Settings },
      ],
    },
  ]
}

export function getNavigationItems(lang: Language) {
  return getNavigationGroups(lang).flatMap((group) => group.items)
}
