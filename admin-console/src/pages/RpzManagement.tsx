import { useState, useEffect, useTransition } from 'react'
import {
  ShieldAlert,
  Upload,
  Link,
  Plus,
  RefreshCw,
  Search,
  CheckCircle2,
  XCircle,
  Settings,
  Trash2,
  Globe,
  Radio,
  Database,
  ShieldCheck,
} from 'lucide-react'

import {
  fetchRpzLists,
  addRpzList,
  toggleRpzList,
  syncRpzList,
  deleteRpzList,
  fetchSinkholeConfig,
  updateSinkholeConfig,
  testDomainQuery,
  fetchRpzStats,
  fetchCustomRules,
  addCustomRule,
  deleteCustomRule,
  type RpzList,
  type RpzRule,
  type DnsSinkholeConfig,
  type RpzTestResult,
  type RpzStats,
  type RpzAction,
  type RpzListFormat,
} from '../api/rpz'

import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { FormField } from '../components/ui/Form'
import { PageHeader } from '../components/ui/PageHeader'
import { EmptyState, PreviewBanner, SkeletonRows } from '../components/ui/DataState'
import { fmt, useT } from '../lib/i18n'

/** Shared control styling so RPZ inputs match the rest of the console. */
const controlClass =
  'touch-target w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary placeholder:text-text-secondary focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20'

export function RpzManagementPage() {
  const t = useT()
  const [, startTransition] = useTransition()
  const [lists, setLists] = useState<RpzList[]>([])
  const [customRules, setCustomRules] = useState<RpzRule[]>([])
  const [sinkholeConfig, setSinkholeConfig] = useState<DnsSinkholeConfig | null>(null)
  const [stats, setStats] = useState<RpzStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'lists' | 'rules' | 'top'>('lists')

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('')
  const [filterFormat, setFilterFormat] = useState<string>('all')

  // Tester state
  const [testDomainInput, setTestDomainInput] = useState('')
  const [testResult, setTestResult] = useState<RpzTestResult | null>(null)
  const [testing, setTesting] = useState(false)

  // Syncing state tracker
  const [syncingId, setSyncingId] = useState<string | null>(null)

  // Modals state
  const [uploadModalOpen, setUploadModalOpen] = useState(false)
  const [urlModalOpen, setUrlModalOpen] = useState(false)
  const [ruleModalOpen, setRuleModalOpen] = useState(false)
  const [configModalOpen, setConfigModalOpen] = useState(false)

  // Form inputs for Upload Modal
  const [uploadName, setUploadName] = useState('')
  const [uploadDesc, setUploadDesc] = useState('')
  const [uploadFormat, setUploadFormat] = useState<RpzListFormat>('rpz-zone')
  const [uploadAction, setUploadAction] = useState<RpzAction>('NXDOMAIN')
  const [uploadContent, setUploadContent] = useState('')
  const [uploadFileName, setUploadFileName] = useState('')

  // Form inputs for Feed Modal
  const [feedName, setFeedName] = useState('')
  const [feedDesc, setFeedDesc] = useState('')
  const [feedUrl, setFeedUrl] = useState('')
  const [feedFormat, setFeedFormat] = useState<RpzListFormat>('rpz-zone')
  const [feedAction, setFeedAction] = useState<RpzAction>('NXDOMAIN')

  // Form inputs for Custom Rule Modal
  const [ruleDomain, setRuleDomain] = useState('')
  const [ruleAction, setRuleAction] = useState<RpzAction>('NXDOMAIN')
  const [ruleComment, setRuleComment] = useState('')

  // Sinkhole Config Form
  const [cfgEnabled, setCfgEnabled] = useState(true)
  const [cfgAction, setCfgAction] = useState<RpzAction>('SINKHOLE')
  const [cfgIpv4, setCfgIpv4] = useState('0.0.0.0')
  const [cfgIpv6, setCfgIpv6] = useState('::')
  const [cfgCname, setCfgCname] = useState('')
  const [cfgLogBlocks, setCfgLogBlocks] = useState(true)
  const [cfgWildcard, setCfgWildcard] = useState(true)

  const loadData = async () => {
    setLoading(true)
    try {
      const [l, r, cfg, st] = await Promise.all([
        fetchRpzLists(),
        fetchCustomRules(),
        fetchSinkholeConfig(),
        fetchRpzStats(),
      ])
      setLists(l)
      setCustomRules(r)
      setSinkholeConfig(cfg)
      setStats(st)

      if (cfg) {
        setCfgEnabled(cfg.enabled)
        setCfgAction(cfg.defaultAction)
        setCfgIpv4(cfg.sinkholeIpv4)
        setCfgIpv6(cfg.sinkholeIpv6)
        setCfgCname(cfg.sinkholeCname)
        setCfgLogBlocks(cfg.logBlocks)
        setCfgWildcard(cfg.wildcardMatching)
      }
    } catch (err) {
      console.error('Failed loading RPZ data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleTestDomain = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!testDomainInput.trim()) return
    setTesting(true)
    try {
      const result = await testDomainQuery(testDomainInput)
      setTestResult(result)
    } finally {
      setTesting(false)
    }
  }

  const handleToggleList = async (id: string, currentActive: boolean) => {
    const nextState = !currentActive
    setLists((prev) => prev.map((item) => (item.id === id ? { ...item, active: nextState } : item)))
    await toggleRpzList(id, nextState)
    const st = await fetchRpzStats()
    setStats(st)
  }

  const handleSyncList = async (id: string) => {
    setSyncingId(id)
    try {
      const updated = await syncRpzList(id)
      setLists((prev) => prev.map((item) => (item.id === id ? updated : item)))
    } finally {
      setSyncingId(null)
    }
  }

  const handleDeleteList = async (id: string) => {
    if (!window.confirm('Remove this RPZ list?')) return
    setLists((prev) => prev.filter((l) => l.id !== id))
    await deleteRpzList(id)
    const st = await fetchRpzStats()
    setStats(st)
  }

  const handleFileUploadChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploadFileName(file.name)
    if (!uploadName) {
      setUploadName(file.name.replace(/\.[^/.]+$/, ''))
    }
    const reader = new FileReader()
    reader.onload = (event) => {
      const text = event.target?.result as string
      setUploadContent(text || '')
      // Auto detect format
      if (text.includes('IN CNAME') || text.includes('$TTL') || text.includes('SOA')) {
        setUploadFormat('rpz-zone')
      } else if (text.includes('127.0.0.1') || text.includes('0.0.0.0')) {
        setUploadFormat('hosts')
      } else {
        setUploadFormat('domain-list')
      }
    }
    reader.readAsText(file)
  }

  const handleCreateUploadList = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!uploadName || !uploadContent) return
    const newList = await addRpzList({
      name: uploadName,
      description: uploadDesc || `Uploaded file ${uploadFileName}`,
      source: 'upload',
      format: uploadFormat,
      content: uploadContent,
      defaultAction: uploadAction,
      priority: 50,
    })
    setLists((prev) => [newList, ...prev])
    setUploadModalOpen(false)
    resetUploadForm()
    const st = await fetchRpzStats()
    setStats(st)
  }

  const resetUploadForm = () => {
    setUploadName('')
    setUploadDesc('')
    setUploadContent('')
    setUploadFileName('')
    setUploadFormat('rpz-zone')
    setUploadAction('NXDOMAIN')
  }

  const handleCreateUrlFeed = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!feedName || !feedUrl) return
    const newList = await addRpzList({
      name: feedName,
      description: feedDesc || `Remote feed from ${feedUrl}`,
      source: 'url_feed',
      format: feedFormat,
      url: feedUrl,
      defaultAction: feedAction,
      priority: 90,
    })
    setLists((prev) => [newList, ...prev])
    setUrlModalOpen(false)
    resetFeedForm()
    const st = await fetchRpzStats()
    setStats(st)
  }

  const resetFeedForm = () => {
    setFeedName('')
    setFeedDesc('')
    setFeedUrl('')
    setFeedFormat('rpz-zone')
    setFeedAction('NXDOMAIN')
  }

  const handleAddCustomRule = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!ruleDomain.trim()) return
    const newRule = await addCustomRule(ruleDomain.trim(), ruleAction, ruleComment)
    setCustomRules((prev) => [newRule, ...prev])
    setRuleModalOpen(false)
    setRuleDomain('')
    setRuleComment('')
  }

  const handleDeleteRule = async (id: string) => {
    setCustomRules((prev) => prev.filter((r) => r.id !== id))
    await deleteCustomRule(id)
  }

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault()
    const updated = await updateSinkholeConfig({
      enabled: cfgEnabled,
      defaultAction: cfgAction,
      sinkholeIpv4: cfgIpv4,
      sinkholeIpv6: cfgIpv6,
      sinkholeCname: cfgCname,
      logBlocks: cfgLogBlocks,
      wildcardMatching: cfgWildcard,
      upstreamDns: sinkholeConfig?.upstreamDns || ['1.1.1.1'],
      dohEnabled: sinkholeConfig?.dohEnabled ?? false,
      dohBind: sinkholeConfig?.dohBind ?? '0.0.0.0:443',
      dohPath: sinkholeConfig?.dohPath ?? '/dns-query',
      dotEnabled: sinkholeConfig?.dotEnabled ?? false,
      dotBind: sinkholeConfig?.dotBind ?? '0.0.0.0:853',
    })
    setSinkholeConfig(updated)
    setConfigModalOpen(false)
  }

  const filteredLists = lists.filter((l) => {
    const matchSearch =
      l.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      l.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      l.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchFormat = filterFormat === 'all' || l.format === filterFormat
    return matchSearch && matchFormat
  })

  return (
    <div className="space-y-6">
      <PreviewBanner feature={t.rpz.previewFeature} />
      <PageHeader
        title={t.rpz.title}
        subtitle={t.rpz.subtitle}
        badge={<Radio className="size-6 text-accent" />}
        actions={
          <>
            <Button variant="secondary" onClick={() => setConfigModalOpen(true)}>
              <Settings className="size-4" />
              {t.rpz.sinkholeConfig}
            </Button>
            <Button variant="secondary" onClick={() => setUrlModalOpen(true)}>
              <Link className="size-4" />
              {t.rpz.addFeedUrl}
            </Button>
            <Button variant="primary" onClick={() => setUploadModalOpen(true)}>
              <Upload className="size-4" />
              {t.rpz.uploadList}
            </Button>
          </>
        }
      />

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Sinkhole Status Card */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              {t.rpz.kpiStatus}
            </span>
            <button
              type="button"
              onClick={async () => {
                if (!sinkholeConfig) return
                const nextState = !sinkholeConfig.enabled
                const updated = await updateSinkholeConfig({ ...sinkholeConfig, enabled: nextState })
                setSinkholeConfig(updated)
                setCfgEnabled(nextState)
              }}
              className={`rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors ${
                sinkholeConfig?.enabled
                  ? 'bg-success/20 text-success hover:bg-success/30'
                  : 'bg-danger/20 text-danger hover:bg-danger/30'
              }`}
            >
              {sinkholeConfig?.enabled ? t.rpz.kpiActive : t.rpz.kpiPaused}
            </button>
          </div>
          <div className="mt-3 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <span className="text-2xl font-bold text-text-primary">
              {sinkholeConfig?.enabled ? t.rpz.kpiProtected : t.rpz.kpiDisabled}
            </span>
            <span className="text-xs text-text-secondary">
              {t.rpz.kpiAction}{' '}
              <strong className="text-accent">{sinkholeConfig?.defaultAction || 'SINKHOLE'}</strong>
            </span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            IP: {sinkholeConfig?.sinkholeIpv4 || '0.0.0.0'}
          </div>
        </div>

        {/* Active Rules Card */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              {t.rpz.kpiRules}
            </span>
            <Database className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <span className="text-2xl font-bold text-text-primary">
              {stats ? stats.totalRules.toLocaleString() : '0'}
            </span>
            <span className="text-xs text-success font-medium flex items-center">
              <ShieldCheck className="size-3.5 mr-0.5 inline" /> {stats?.activeLists || 0} {t.rpz.kpiActiveFeeds}
            </span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            {fmt(t.rpz.kpiAcrossZones, { count: stats?.totalLists || 0 })}
          </div>
        </div>

        {/* Blocked Queries 24h Card */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              {t.rpz.kpiBlocks}
            </span>
            <ShieldAlert className="size-4 text-warning" />
          </div>
          <div className="mt-3 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <span className="text-2xl font-bold text-text-primary">
              {stats ? stats.blocked24h.toLocaleString() : '0'}
            </span>
            <span className="text-xs text-text-secondary">{t.rpz.kpiQueries}</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            {t.rpz.kpiSinkholed}
          </div>
        </div>

        {/* Sync & Health Card */}
        <div className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              {t.rpz.kpiSync}
            </span>
            <RefreshCw className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <span className="text-2xl font-bold text-success">{t.rpz.kpiHealthy}</span>
            <span className="text-xs text-text-secondary">{t.rpz.kpiAutoSync}</span>
          </div>
          <div className="mt-2 text-xs text-text-secondary">
            {t.rpz.kpiLastUpdated}
          </div>
        </div>
      </div>

      {/* Encrypted DNS Gateways Panel (DoH & DoT) */}
      <div className="rounded-xl border border-border bg-surface-1 p-5 shadow-sm space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-success" />
            <h2 className="text-base font-semibold text-text-primary">{t.rpz.dohDotTitle}</h2>
          </div>
          <span className="rounded-full bg-success/20 px-2.5 py-0.5 text-xs font-bold text-success">
            {t.rpz.dohDotBadge}
          </span>
        </div>
        <p className="text-xs text-text-secondary">
          {t.rpz.dohDotDesc}
        </p>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {/* DoH Card */}
          <div className="rounded-lg border border-border bg-surface-0 p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-accent uppercase">DoH (DNS-over-HTTPS)</span>
              <span className="rounded bg-success/20 px-2 py-0.5 text-[10px] font-bold text-success">RFC 8484</span>
            </div>
            <div className="font-mono text-sm font-bold text-text-primary">
              https://{sinkholeConfig?.dohBind || '0.0.0.0:8443'}{sinkholeConfig?.dohPath || '/dns-query'}
            </div>
            <div className="flex justify-between text-xs text-text-secondary pt-1 border-t border-border/50">
              <span>
                {t.rpz.encryptedQueries24h}{' '}
                <strong className="font-mono text-text-primary">
                  {stats?.dohQueries24h?.toLocaleString() || '68,420'}
                </strong>
              </span>
              <span className="text-success font-semibold">GET / POST wireformat</span>
            </div>
          </div>

          {/* DoT Card */}
          <div className="rounded-lg border border-border bg-surface-0 p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-accent uppercase">DoT (DNS-over-TLS)</span>
              <span className="rounded bg-success/20 px-2 py-0.5 text-[10px] font-bold text-success">RFC 7858</span>
            </div>
            <div className="font-mono text-sm font-bold text-text-primary">
              tls://{sinkholeConfig?.dotBind || '0.0.0.0:853'}
            </div>
            <div className="flex justify-between text-xs text-text-secondary pt-1 border-t border-border/50">
              <span>
                {t.rpz.encryptedQueries24h}{' '}
                <strong className="font-mono text-text-primary">
                  {stats?.dotQueries24h?.toLocaleString() || '31,200'}
                </strong>
              </span>
              <span className="text-success font-semibold">TCP 853 TLS 2-byte frame</span>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive RPZ Query Simulator Widget */}
      <div className="rounded-xl border border-border bg-surface-1 p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <Globe className="size-5 text-accent" />
          <h2 className="text-base font-semibold text-text-primary">{t.rpz.testerTitle}</h2>
        </div>
        <p className="text-xs text-text-secondary mb-4">
          {t.rpz.testerDesc}
        </p>

        <form onSubmit={handleTestDomain} className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-secondary" />
            <input
              type="text"
              placeholder={t.rpz.testerPlaceholder}
              aria-label={t.rpz.testerPlaceholder}
              value={testDomainInput}
              onChange={(e) => setTestDomainInput(e.target.value)}
              className={`${controlClass} py-2 pl-9 pr-3`}
            />
          </div>
          <Button type="submit" disabled={testing}>
            {testing ? <RefreshCw className="size-4 animate-spin" /> : <Search className="size-4" />}
            {t.rpz.testerSubmit}
          </Button>
        </form>

        {testResult && (
          <div
            className={`mt-4 rounded-md border p-4 transition-all ${
              testResult.matched
                ? 'border-accent/40 bg-accent/10'
                : 'border-success/40 bg-success/10'
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-3">
              <div className="flex items-center gap-2">
                {testResult.matched ? (
                  <XCircle className="size-5 text-accent" />
                ) : (
                  <CheckCircle2 className="size-5 text-success" />
                )}
                <span className="font-mono text-sm font-bold text-text-primary">{testResult.domain}</span>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`rounded-full px-2.5 py-0.5 text-xs font-bold ${
                    testResult.matched ? 'bg-accent/20 text-accent' : 'bg-success/20 text-success'
                  }`}
                >
                  {testResult.appliedAction}
                </span>
                <span className="text-xs text-text-secondary font-mono">
                  {testResult.durationMs}ms
                </span>
              </div>
            </div>

            <div className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
              <div>
                <span className="text-text-secondary">{t.rpz.testerTargetResponse} </span>
                <span className="font-mono font-medium text-text-primary">{testResult.targetResponse}</span>
              </div>
              <div>
                <span className="text-text-secondary">{t.rpz.testerMatchingList} </span>
                <span className="font-medium text-text-primary">
                  {testResult.matchedRule ? testResult.matchedRule.listName : t.rpz.testerNoMatch}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Tabs Header */}
      <div className="flex flex-col justify-between gap-2 border-b border-border sm:flex-row sm:items-center">
        <div className="scrollbar-stable -mb-px flex gap-4 overflow-x-auto" role="tablist">
          <button
            type="button"
            onClick={() => setActiveTab('lists')}
            className={`touch-target whitespace-nowrap border-b-2 px-1 py-3 text-sm font-semibold transition-colors ${
              activeTab === 'lists'
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            {t.rpz.tabLists} ({lists.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('rules')}
            className={`touch-target whitespace-nowrap border-b-2 px-1 py-3 text-sm font-semibold transition-colors ${
              activeTab === 'rules'
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            {t.rpz.tabRules} ({customRules.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('top')}
            className={`touch-target whitespace-nowrap border-b-2 px-1 py-3 text-sm font-semibold transition-colors ${
              activeTab === 'top'
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            {t.rpz.tabTop}
          </button>
        </div>

        {activeTab === 'lists' && (
          <div className="flex items-center gap-2 py-2">
            <input
              type="text"
              placeholder={t.rpz.searchLists}
              aria-label={t.rpz.searchLists}
              value={searchQuery}
              onChange={(e) => startTransition(() => setSearchQuery(e.target.value))}
              className="min-w-0 flex-1 rounded-md border border-border bg-surface-0 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-secondary focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 sm:flex-none"
            />
            <select
              value={filterFormat}
              onChange={(e) => setFilterFormat(e.target.value)}
              aria-label={t.rpz.colFormat}
              className="shrink-0 rounded-md border border-border bg-surface-0 px-2 py-1.5 text-xs text-text-primary focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
            >
              <option value="all">{t.rpz.allFormats}</option>
              <option value="rpz-zone">{t.rpz.formatRpzZone}</option>
              <option value="hosts">{t.rpz.formatHosts}</option>
              <option value="domain-list">{t.rpz.formatDomainList}</option>
            </select>
          </div>
        )}

        {activeTab === 'rules' && (
          <div className="py-2">
            <Button variant="secondary" onClick={() => setRuleModalOpen(true)}>
              <Plus className="size-4" />
              {t.rpz.addDomainRule}
            </Button>
          </div>
        )}
      </div>

      {/* Tab 1: RPZ Feeds & Lists */}
      {activeTab === 'lists' && (
        <div className="space-y-4">
          {loading ? (
            <SkeletonRows rows={5} />
          ) : filteredLists.length === 0 ? (
            <div className="rounded-lg border border-border bg-surface-1">
              <EmptyState message={t.rpz.noLists} icon={Search} />
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border bg-surface-1">
              <table className="w-full min-w-[900px] text-left text-sm">
                <thead className="border-b border-border bg-surface-2 text-xs uppercase text-text-secondary">
                  <tr>
                    <th className="whitespace-nowrap px-4 py-3">{t.rpz.colListName}</th>
                    <th className="whitespace-nowrap px-4 py-3">{t.rpz.colFormat}</th>
                    <th className="whitespace-nowrap px-4 py-3">{t.rpz.colRuleCount}</th>
                    <th className="whitespace-nowrap px-4 py-3">{t.rpz.colAction}</th>
                    <th className="whitespace-nowrap px-4 py-3">{t.rpz.colLastUpdated}</th>
                    <th className="whitespace-nowrap px-4 py-3">{t.rpz.colStatus}</th>
                    <th className="whitespace-nowrap px-4 py-3 text-right">{t.rpz.colActions}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border text-text-primary">
                  {filteredLists.map((list) => (
                    <tr key={list.id} className="hover:bg-surface-2/50 transition-colors">
                      <td className="px-4 py-3">
                        <div className="font-semibold text-text-primary">{list.name}</div>
                        <div className="text-xs text-text-secondary line-clamp-1">{list.description}</div>
                        {list.url && (
                          <div className="mt-0.5 text-xs text-accent font-mono truncate max-w-xs">
                            {list.url}
                          </div>
                        )}
                        <div className="mt-1 flex flex-wrap gap-1">
                          {list.tags.map((t) => (
                            <span
                              key={t}
                              className="rounded border border-border bg-surface-0 px-1.5 py-0.5 text-[10px] text-text-secondary"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-surface-2 px-2 py-1 text-xs font-mono font-medium text-text-secondary">
                          {list.format}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono font-bold text-text-primary">
                        {list.ruleCount.toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-accent/15 px-2 py-0.5 text-xs font-bold text-accent">
                          {list.defaultAction}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-text-secondary">
                        {new Date(list.lastUpdated).toLocaleDateString()}{' '}
                        {new Date(list.lastUpdated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => handleToggleList(list.id, list.active)}
                          className={`rounded-full px-2.5 py-0.5 text-xs font-bold transition-colors ${
                            list.active
                              ? 'bg-success/20 text-success hover:bg-success/30'
                              : 'bg-surface-3 text-text-secondary hover:bg-surface-2'
                          }`}
                        >
                          {list.active ? t.rpz.listActive : t.rpz.listDisabled}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {list.source === 'url_feed' && (
                            <button
                              type="button"
                              onClick={() => handleSyncList(list.id)}
                              disabled={syncingId === list.id}
                              className="rounded p-1.5 text-text-secondary hover:bg-surface-2 hover:text-text-primary"
                              title={t.rpz.forceSync}
                              aria-label={t.rpz.forceSync}
                            >
                              <RefreshCw
                                className={`size-4 ${syncingId === list.id ? 'animate-spin text-accent' : ''}`}
                              />
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => handleDeleteList(list.id)}
                            className="rounded p-1.5 text-danger/70 hover:bg-danger/20 hover:text-danger"
                            title={t.rpz.deleteList}
                            aria-label={t.rpz.deleteList}
                          >
                            <Trash2 className="size-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Custom Overrides */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="overflow-x-auto rounded-lg border border-border bg-surface-1">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-surface-2 text-xs uppercase text-text-secondary">
                <tr>
                  <th className="whitespace-nowrap px-4 py-3">{t.rpz.colDomain}</th>
                  <th className="whitespace-nowrap px-4 py-3">{t.rpz.colAction}</th>
                  <th className="whitespace-nowrap px-4 py-3">{t.rpz.colComment}</th>
                  <th className="whitespace-nowrap px-4 py-3">{t.rpz.colAdded}</th>
                  <th className="whitespace-nowrap px-4 py-3 text-right">{t.rpz.colActions}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-text-primary">
                {customRules.map((r) => (
                  <tr key={r.id} className="hover:bg-surface-2/50 transition-colors">
                    <td className="px-4 py-3 font-mono font-bold text-text-primary">{r.domain}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-bold ${
                          r.action === 'PASSTHRU'
                            ? 'bg-success/20 text-success'
                            : 'bg-accent/20 text-accent'
                        }`}
                      >
                        {r.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-text-secondary">{r.comment || '—'}</td>
                    <td className="px-4 py-3 text-xs text-text-secondary">
                      {new Date(r.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => handleDeleteRule(r.id)}
                        className="rounded p-1.5 text-danger/70 hover:bg-danger/20 hover:text-danger"
                      >
                        <Trash2 className="size-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Top Threat Blocks */}
      {activeTab === 'top' && (
        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-surface-1 p-4">
            <h3 className="mb-3 text-sm font-bold text-text-primary">{t.rpz.topTitle}</h3>
            <div className="space-y-3">
              {stats?.topDomains.map((item, i) => (
                <div
                  key={item.domain}
                  className="flex flex-col justify-between rounded-md border border-border/60 bg-surface-0 p-3 sm:flex-row sm:items-center"
                >
                  <div className="flex items-center gap-3">
                    <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-surface-2 text-xs font-bold text-text-secondary">
                      #{i + 1}
                    </span>
                    <div>
                      <div className="font-mono text-sm font-bold text-text-primary">{item.domain}</div>
                      <span className="text-xs text-text-secondary">{item.category}</span>
                    </div>
                  </div>
                  <div className="mt-2 flex items-center gap-4 sm:mt-0">
                    <span className="font-mono text-sm font-bold text-accent">
                      {item.count.toLocaleString()} {t.rpz.blocksSuffix}
                    </span>
                    <span className="rounded bg-accent/15 px-2 py-0.5 text-xs font-bold text-accent">
                      {item.action}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Upload RPZ List Modal */}
      <Modal
        open={uploadModalOpen}
        onClose={() => setUploadModalOpen(false)}
        title={t.rpz.uploadTitle}
        footer={
          <>
            <Button variant="ghost" onClick={() => setUploadModalOpen(false)}>
              {t.common.cancel}
            </Button>
            <Button variant="primary" onClick={handleCreateUploadList} disabled={!uploadName || !uploadContent}>
              <Upload className="size-4" />
              {t.rpz.uploadSubmit}
            </Button>
          </>
        }
      >
        <form onSubmit={handleCreateUploadList} className="space-y-4">
          <FormField label={t.rpz.fieldListName} required>
            <input
              type="text"
              placeholder={t.rpz.fieldListNamePh}
              value={uploadName}
              onChange={(e) => setUploadName(e.target.value)}
              className={controlClass}
            />
          </FormField>

          <FormField label="Description">
            <input
              type="text"
              placeholder={t.rpz.fieldDescriptionPh}
              value={uploadDesc}
              onChange={(e) => setUploadDesc(e.target.value)}
              className={controlClass}
            />
          </FormField>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label={t.rpz.fieldListFormat}>
              <select
                value={uploadFormat}
                onChange={(e) => setUploadFormat(e.target.value as RpzListFormat)}
                className={controlClass}
              >
                <option value="rpz-zone">{t.rpz.optRpzZoneExt}</option>
                <option value="hosts">{t.rpz.optHostsExt}</option>
                <option value="domain-list">{t.rpz.optDomainListExt}</option>
              </select>
            </FormField>

            <FormField label={t.rpz.fieldDefaultBlockAction}>
              <select
                value={uploadAction}
                onChange={(e) => setUploadAction(e.target.value as RpzAction)}
                className={controlClass}
              >
                <option value="NXDOMAIN">{t.rpz.optNxdomainFull}</option>
                <option value="SINKHOLE">{t.rpz.optSinkholeFull}</option>
                <option value="DROP">{t.rpz.optDropFull}</option>
                <option value="NODATA">{t.rpz.optNodataFull}</option>
              </select>
            </FormField>
          </div>

          <FormField label={t.rpz.fieldFile}>
            <input
              type="file"
              accept=".txt,.rpz,.hosts,.zone,.conf"
              onChange={handleFileUploadChange}
              className="w-full text-xs text-text-secondary file:mr-4 file:rounded-md file:border-0 file:bg-surface-2 file:px-4 file:py-2 file:text-xs file:font-semibold file:text-text-primary hover:file:bg-surface-3"
            />
          </FormField>

          <FormField label={t.rpz.fieldContent}>
            <textarea
              rows={5}
              placeholder={t.rpz.fieldContentPh}
              value={uploadContent}
              onChange={(e) => setUploadContent(e.target.value)}
              className={`${controlClass} font-mono text-xs`}
            />
          </FormField>

          {uploadContent && (
            <div className="rounded border border-success/30 bg-success/10 p-2.5 text-xs text-success flex items-center justify-between">
              <span>{t.rpz.parsedPreview}</span>
              <strong className="font-mono">
                ~
                {uploadContent
                  .split('\n')
                  .filter((l) => l.trim().length > 0 && !l.trim().startsWith('#')).length}{' '}
                {t.rpz.validEntries}
              </strong>
            </div>
          )}
        </form>
      </Modal>

      {/* Add Feed URL Modal */}
      <Modal
        open={urlModalOpen}
        onClose={() => setUrlModalOpen(false)}
        title={t.rpz.feedTitle}
        footer={
          <>
            <Button variant="ghost" onClick={() => setUrlModalOpen(false)}>
              {t.common.cancel}
            </Button>
            <Button variant="primary" onClick={handleCreateUrlFeed} disabled={!feedName || !feedUrl}>
              <Link className="size-4" />
              {t.rpz.feedSubmit}
            </Button>
          </>
        }
      >
        <form onSubmit={handleCreateUrlFeed} className="space-y-4">
          <FormField label={t.rpz.fieldFeedName} required>
            <input
              type="text"
              placeholder={t.rpz.fieldFeedNamePh}
              value={feedName}
              onChange={(e) => setFeedName(e.target.value)}
              className={controlClass}
            />
          </FormField>

          <FormField label={t.rpz.fieldFeedUrl} required>
            <input
              type="url"
              placeholder="https://example.com/downloads/rpz-zone.txt"
              value={feedUrl}
              onChange={(e) => setFeedUrl(e.target.value)}
              className={`${controlClass} font-mono`}
            />
          </FormField>

          <FormField label="Description">
            <input
              type="text"
              placeholder={t.rpz.fieldFeedDescPh}
              value={feedDesc}
              onChange={(e) => setFeedDesc(e.target.value)}
              className={controlClass}
            />
          </FormField>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label={t.rpz.fieldFormat}>
              <select
                value={feedFormat}
                onChange={(e) => setFeedFormat(e.target.value as RpzListFormat)}
                className={controlClass}
              >
                <option value="rpz-zone">{t.rpz.formatRpzZone}</option>
                <option value="hosts">{t.rpz.formatHosts}</option>
                <option value="domain-list">{t.rpz.formatDomainList}</option>
              </select>
            </FormField>

            <FormField label={t.rpz.fieldDefaultAction}>
              <select
                value={feedAction}
                onChange={(e) => setFeedAction(e.target.value as RpzAction)}
                className={controlClass}
              >
                <option value="NXDOMAIN">NXDOMAIN</option>
                <option value="SINKHOLE">SINKHOLE</option>
                <option value="DROP">DROP</option>
              </select>
            </FormField>
          </div>
        </form>
      </Modal>

      {/* Custom Domain Rule Modal */}
      <Modal
        open={ruleModalOpen}
        onClose={() => setRuleModalOpen(false)}
        title={t.rpz.ruleTitle}
        footer={
          <>
            <Button variant="ghost" onClick={() => setRuleModalOpen(false)}>
              {t.common.cancel}
            </Button>
            <Button variant="primary" onClick={handleAddCustomRule} disabled={!ruleDomain}>
              <Plus className="size-4" />
              {t.rpz.ruleSubmit}
            </Button>
          </>
        }
      >
        <form onSubmit={handleAddCustomRule} className="space-y-4">
          <FormField label={t.rpz.colDomain} required>
            <input
              type="text"
              placeholder={t.rpz.fieldDomainPh}
              value={ruleDomain}
              onChange={(e) => setRuleDomain(e.target.value)}
              className={`${controlClass} font-mono`}
            />
          </FormField>

          <FormField label={t.rpz.colAction}>
            <select
              value={ruleAction}
              onChange={(e) => setRuleAction(e.target.value as RpzAction)}
              className={controlClass}
            >
              <option value="NXDOMAIN">{t.rpz.optNxdomainRule}</option>
              <option value="SINKHOLE">{t.rpz.optSinkholeRule}</option>
              <option value="PASSTHRU">{t.rpz.optPassthruRule}</option>
              <option value="DROP">{t.rpz.optDropRule}</option>
            </select>
          </FormField>

          <FormField label={t.rpz.colComment}>
            <input
              type="text"
              placeholder={t.rpz.fieldCommentPh}
              value={ruleComment}
              onChange={(e) => setRuleComment(e.target.value)}
              className={controlClass}
            />
          </FormField>
        </form>
      </Modal>

      {/* Sinkhole Configuration Modal */}
      <Modal
        open={configModalOpen}
        onClose={() => setConfigModalOpen(false)}
        title={t.rpz.configTitle}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfigModalOpen(false)}>
              {t.common.cancel}
            </Button>
            <Button variant="primary" onClick={handleSaveConfig}>
              {t.rpz.configSubmit}
            </Button>
          </>
        }
      >
        <form onSubmit={handleSaveConfig} className="space-y-4">
          <div className="flex items-center justify-between rounded-md border border-border bg-surface-0 p-3">
            <div>
              <div className="text-sm font-semibold text-text-primary">{t.rpz.cfgEnable}</div>
              <div className="text-xs text-text-secondary">{t.rpz.cfgEnableHint}</div>
            </div>
            <input
              type="checkbox"
              checked={cfgEnabled}
              onChange={(e) => setCfgEnabled(e.target.checked)}
              className="size-5 rounded border-border text-accent focus:ring-accent"
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField label={t.rpz.cfgIpv4}>
              <input
                type="text"
                value={cfgIpv4}
                onChange={(e) => setCfgIpv4(e.target.value)}
                className={`${controlClass} font-mono`}
              />
            </FormField>

            <FormField label={t.rpz.cfgIpv6}>
              <input
                type="text"
                value={cfgIpv6}
                onChange={(e) => setCfgIpv6(e.target.value)}
                className={`${controlClass} font-mono`}
              />
            </FormField>
          </div>

          <FormField label={t.rpz.cfgCname}>
            <input
              type="text"
              placeholder={t.rpz.cfgCnamePh}
              value={cfgCname}
              onChange={(e) => setCfgCname(e.target.value)}
              className={`${controlClass} font-mono`}
            />
          </FormField>

          <FormField label={t.rpz.cfgDefaultAction}>
            <select
              value={cfgAction}
              onChange={(e) => setCfgAction(e.target.value as RpzAction)}
              className={controlClass}
            >
              <option value="SINKHOLE">{t.rpz.optSinkholeReturn}</option>
              <option value="NXDOMAIN">NXDOMAIN</option>
              <option value="DROP">DROP</option>
            </select>
          </FormField>

          <div className="space-y-2 pt-2">
            <label className="flex items-center gap-2 text-xs text-text-primary">
              <input
                type="checkbox"
                checked={cfgLogBlocks}
                onChange={(e) => setCfgLogBlocks(e.target.checked)}
                className="size-4 rounded border-border text-accent focus:ring-accent"
              />
              {t.rpz.cfgLogBlocks}
            </label>
            <label className="flex items-center gap-2 text-xs text-text-primary">
              <input
                type="checkbox"
                checked={cfgWildcard}
                onChange={(e) => setCfgWildcard(e.target.checked)}
                className="size-4 rounded border-border text-accent focus:ring-accent"
              />
              {t.rpz.cfgWildcard}
            </label>
          </div>
        </form>
      </Modal>
    </div>
  )
}
