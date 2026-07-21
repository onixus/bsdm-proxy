import { apiFetch, aclClient } from './client'

export type RpzListFormat = 'rpz-zone' | 'hosts' | 'domain-list'
export type RpzAction = 'NXDOMAIN' | 'NODATA' | 'PASSTHRU' | 'DROP' | 'SINKHOLE'
export type RpzListSource = 'upload' | 'url_feed' | 'inline'

export interface RpzList {
  id: string
  name: string
  description: string
  source: RpzListSource
  format: RpzListFormat
  url?: string
  defaultAction: RpzAction
  ruleCount: number
  active: boolean
  priority: number
  lastUpdated: string
  syncError?: string | null
  tags: string[]
}

export interface RpzRule {
  id: string
  listId: string
  listName: string
  domain: string
  action: RpzAction
  targetIp?: string
  targetCname?: string
  comment?: string
  createdAt: string
}

export interface DnsSinkholeConfig {
  enabled: boolean
  defaultAction: RpzAction
  sinkholeIpv4: string
  sinkholeIpv6: string
  sinkholeCname: string
  logBlocks: boolean
  wildcardMatching: boolean
  upstreamDns: string[]
  dohEnabled: boolean
  dohBind: string
  dohPath: string
  dotEnabled: boolean
  dotBind: string
}

export interface RpzTestResult {
  domain: string
  matched: boolean
  matchedRule?: {
    domain: string
    action: RpzAction
    listId: string
    listName: string
  }
  appliedAction: RpzAction
  targetResponse: string
  durationMs: number
}

export interface RpzStats {
  totalLists: number
  activeLists: number
  totalRules: number
  blocked24h: number
  dohQueries24h: number
  dotQueries24h: number
  topDomains: {
    domain: string
    count: number
    action: RpzAction
    category: string
  }[]
}

export interface AddRpzListInput {
  name: string
  description: string
  source: RpzListSource
  format: RpzListFormat
  url?: string
  content?: string
  defaultAction: RpzAction
  priority: number
}

// Memory cache for runtime additions in UI demo mode
let memoryLists: RpzList[] | null = null
let memoryConfig: DnsSinkholeConfig | null = null
let memoryRules: RpzRule[] | null = null

export async function fetchRpzLists(): Promise<RpzList[]> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<RpzList[]>('/api/dns/rpz/lists', { baseUrl, token })
  } catch {
    if (!memoryLists) {
      memoryLists = getMockLists()
    }
    return memoryLists
  }
}

export async function addRpzList(input: AddRpzListInput): Promise<RpzList> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<RpzList>('/api/dns/rpz/lists', {
      baseUrl,
      token,
      method: 'POST',
      body: input,
    })
  } catch {
    const parsedRules = input.content ? parseContentRuleCount(input.content) : 1500
    const newList: RpzList = {
      id: `rpz-${Date.now()}`,
      name: input.name,
      description: input.description,
      source: input.source,
      format: input.format,
      url: input.url,
      defaultAction: input.defaultAction,
      ruleCount: parsedRules,
      active: true,
      priority: input.priority || 10,
      lastUpdated: new Date().toISOString(),
      tags: [input.format, input.source],
    }
    if (!memoryLists) memoryLists = getMockLists()
    memoryLists.unshift(newList)
    return newList
  }
}

export async function toggleRpzList(id: string, active: boolean): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/dns/rpz/lists/${encodeURIComponent(id)}/toggle`, {
      baseUrl,
      token,
      method: 'POST',
      body: { active },
    })
  } catch {
    if (!memoryLists) memoryLists = getMockLists()
    const item = memoryLists.find((l) => l.id === id)
    if (item) item.active = active
  }
}

export async function syncRpzList(id: string): Promise<RpzList> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<RpzList>(`/api/dns/rpz/lists/${encodeURIComponent(id)}/sync`, {
      baseUrl,
      token,
      method: 'POST',
    })
  } catch {
    if (!memoryLists) memoryLists = getMockLists()
    const item = memoryLists.find((l) => l.id === id)
    if (item) {
      item.lastUpdated = new Date().toISOString()
      item.ruleCount += Math.floor(Math.random() * 50) - 20
      delete item.syncError
    }
    return item || getMockLists()[0]
  }
}

export async function deleteRpzList(id: string): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/dns/rpz/lists/${encodeURIComponent(id)}`, {
      baseUrl,
      token,
      method: 'DELETE',
    })
  } catch {
    if (!memoryLists) memoryLists = getMockLists()
    memoryLists = memoryLists.filter((l) => l.id !== id)
  }
}

export async function fetchSinkholeConfig(): Promise<DnsSinkholeConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<DnsSinkholeConfig>('/api/dns/sinkhole/config', { baseUrl, token })
  } catch {
    if (!memoryConfig) {
      memoryConfig = {
        enabled: true,
        defaultAction: 'SINKHOLE',
        sinkholeIpv4: '0.0.0.0',
        sinkholeIpv6: '::',
        sinkholeCname: 'sinkhole.bsdm-proxy.local',
        logBlocks: true,
        wildcardMatching: true,
        upstreamDns: ['1.1.1.1', '8.8.8.8'],
        dohEnabled: true,
        dohBind: '0.0.0.0:8443',
        dohPath: '/dns-query',
        dotEnabled: true,
        dotBind: '0.0.0.0:853',
      }
    }
    return memoryConfig
  }
}

export async function updateSinkholeConfig(config: DnsSinkholeConfig): Promise<DnsSinkholeConfig> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<DnsSinkholeConfig>('/api/dns/sinkhole/config', {
      baseUrl,
      token,
      method: 'PUT',
      body: config,
    })
  } catch {
    memoryConfig = { ...config }
    return memoryConfig
  }
}

export async function testDomainQuery(domain: string): Promise<RpzTestResult> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<RpzTestResult>(`/api/dns/rpz/test?domain=${encodeURIComponent(domain)}`, {
      baseUrl,
      token,
      method: 'POST',
    })
  } catch {
    return mockTestQuery(domain)
  }
}

export async function fetchRpzStats(): Promise<RpzStats> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<RpzStats>('/api/dns/rpz/stats', { baseUrl, token })
  } catch {
    const lists = await fetchRpzLists()
    const active = lists.filter((l) => l.active)
    const totalRules = active.reduce((acc, l) => acc + l.ruleCount, 0)
    return {
      totalLists: lists.length,
      activeLists: active.length,
      totalRules,
      blocked24h: 142850,
      dohQueries24h: 68420,
      dotQueries24h: 31200,
      topDomains: [
        { domain: 'tracker.adtech-analytics.com', count: 32410, action: 'SINKHOLE', category: 'Ads & Telemetry' },
        { domain: 'malware-drop.badsite.ru', count: 18920, action: 'NXDOMAIN', category: 'Malware' },
        { domain: 'phish-verify-bank.account-login.cc', count: 12400, action: 'NXDOMAIN', category: 'Phishing' },
        { domain: 'crypto-miner-pool.hash.xyz', count: 8750, action: 'DROP', category: 'Coinminer' },
        { domain: 'c2-server.botnet-cmd.org', count: 6100, action: 'NXDOMAIN', category: 'Command & Control' },
      ],
    }
  }
}

export async function fetchCustomRules(): Promise<RpzRule[]> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<RpzRule[]>('/api/dns/rpz/rules/custom', { baseUrl, token })
  } catch {
    if (!memoryRules) {
      memoryRules = [
        {
          id: 'rule-1',
          listId: 'custom-inline',
          listName: 'Custom Overrides',
          domain: 'bad-actor.example.com',
          action: 'NXDOMAIN',
          comment: 'Block test actor domain',
          createdAt: '2026-07-20T10:00:00Z',
        },
        {
          id: 'rule-2',
          listId: 'custom-inline',
          listName: 'Custom Overrides',
          domain: 'internal-safe.corp.local',
          action: 'PASSTHRU',
          comment: 'Whitelist internal lookup',
          createdAt: '2026-07-21T08:30:00Z',
        },
      ]
    }
    return memoryRules
  }
}

export async function addCustomRule(domain: string, action: RpzAction, comment?: string): Promise<RpzRule> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<RpzRule>('/api/dns/rpz/rules/custom', {
      baseUrl,
      token,
      method: 'POST',
      body: { domain, action, comment },
    })
  } catch {
    const newRule: RpzRule = {
      id: `rule-${Date.now()}`,
      listId: 'custom-inline',
      listName: 'Custom Overrides',
      domain,
      action,
      comment,
      createdAt: new Date().toISOString(),
    }
    if (!memoryRules) memoryRules = []
    memoryRules.unshift(newRule)
    return newRule
  }
}

export async function deleteCustomRule(id: string): Promise<void> {
  const { baseUrl, token } = aclClient()
  try {
    await apiFetch(`/api/dns/rpz/rules/custom/${encodeURIComponent(id)}`, {
      baseUrl,
      token,
      method: 'DELETE',
    })
  } catch {
    if (!memoryRules) memoryRules = []
    memoryRules = memoryRules.filter((r) => r.id !== id)
  }
}

function parseContentRuleCount(content: string): number {
  const lines = content.split('\n').filter((l) => {
    const trimmed = l.trim()
    return trimmed.length > 0 && !trimmed.startsWith('#') && !trimmed.startsWith(';')
  })
  return Math.max(lines.length, 1)
}

function getMockLists(): RpzList[] {
  return [
    {
      id: 'rpz-abuse-malware',
      name: 'Abuse.ch URLhaus RPZ Feed',
      description: 'Active malware payload domains updated hourly via BIND RPZ format',
      source: 'url_feed',
      format: 'rpz-zone',
      url: 'https://urlhaus.abuse.ch/downloads/rpz/',
      defaultAction: 'NXDOMAIN',
      ruleCount: 84320,
      active: true,
      priority: 100,
      lastUpdated: '2026-07-21T12:00:00Z',
      tags: ['Malware', 'ThreatIntel', 'AutoSync'],
    },
    {
      id: 'rpz-stevenblack-hosts',
      name: 'StevenBlack Unified Hosts',
      description: 'Consolidated hosts list blocking adware, malware, and spam sites',
      source: 'url_feed',
      format: 'hosts',
      url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
      defaultAction: 'SINKHOLE',
      ruleCount: 154210,
      active: true,
      priority: 90,
      lastUpdated: '2026-07-21T06:00:00Z',
      tags: ['AdBlock', 'Hosts', 'Community'],
    },
    {
      id: 'rpz-phishing-feed',
      name: 'OpenPhish Domain Feed',
      description: 'Zero-day credential phishing domains feed',
      source: 'url_feed',
      format: 'domain-list',
      url: 'https://openphish.com/feed.txt',
      defaultAction: 'NXDOMAIN',
      ruleCount: 9850,
      active: true,
      priority: 95,
      lastUpdated: '2026-07-21T13:30:00Z',
      tags: ['Phishing', 'ZeroDay'],
    },
    {
      id: 'rpz-custom-upload',
      name: 'Corporate Compliance Blocklist 2026',
      description: 'Uploaded list of restricted categories and illegal gambling domains',
      source: 'upload',
      format: 'domain-list',
      defaultAction: 'SINKHOLE',
      ruleCount: 120,
      active: true,
      priority: 80,
      lastUpdated: '2026-07-19T14:20:00Z',
      tags: ['Corporate', 'Uploaded', 'Custom'],
    },
    {
      id: 'rpz-internal-overrides',
      name: 'Internal Domain Exclusions',
      description: 'Custom inline rules for white-listing internal microservices and testing',
      source: 'inline',
      format: 'rpz-zone',
      defaultAction: 'PASSTHRU',
      ruleCount: 2,
      active: true,
      priority: 150,
      lastUpdated: '2026-07-21T08:30:00Z',
      tags: ['Whitelist', 'Override'],
    },
  ]
}

function mockTestDomain(domain: string): RpzTestResult {
  const cleanDomain = domain.toLowerCase().trim()
  if (cleanDomain.includes('malware') || cleanDomain.includes('badsite')) {
    return {
      domain: cleanDomain,
      matched: true,
      matchedRule: {
        domain: cleanDomain,
        action: 'NXDOMAIN',
        listId: 'rpz-abuse-malware',
        listName: 'Abuse.ch URLhaus RPZ Feed',
      },
      appliedAction: 'NXDOMAIN',
      targetResponse: 'NXDOMAIN (Name Error)',
      durationMs: 1.2,
    }
  }

  if (cleanDomain.includes('adtech') || cleanDomain.includes('tracker') || cleanDomain.includes('ad')) {
    return {
      domain: cleanDomain,
      matched: true,
      matchedRule: {
        domain: cleanDomain,
        action: 'SINKHOLE',
        listId: 'rpz-stevenblack-hosts',
        listName: 'StevenBlack Unified Hosts',
      },
      appliedAction: 'SINKHOLE',
      targetResponse: 'A 0.0.0.0 / AAAA ::',
      durationMs: 0.8,
    }
  }

  if (cleanDomain.includes('phish')) {
    return {
      domain: cleanDomain,
      matched: true,
      matchedRule: {
        domain: cleanDomain,
        action: 'NXDOMAIN',
        listId: 'rpz-phishing-feed',
        listName: 'OpenPhish Domain Feed',
      },
      appliedAction: 'NXDOMAIN',
      targetResponse: 'NXDOMAIN (Name Error)',
      durationMs: 1.5,
    }
  }

  if (cleanDomain.includes('internal') || cleanDomain.includes('corp')) {
    return {
      domain: cleanDomain,
      matched: true,
      matchedRule: {
        domain: cleanDomain,
        action: 'PASSTHRU',
        listId: 'rpz-internal-overrides',
        listName: 'Internal Domain Exclusions',
      },
      appliedAction: 'PASSTHRU',
      targetResponse: 'PASSTHRU (Allowed to Upstream DNS)',
      durationMs: 0.5,
    }
  }

  return {
    domain: cleanDomain,
    matched: false,
    appliedAction: 'PASSTHRU',
    targetResponse: 'Allowed (Resolved via Upstream 1.1.1.1)',
    durationMs: 0.4,
  }
}
