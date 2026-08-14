import { useEffect, useMemo, useState } from 'react'
import { Pencil, Plus, RefreshCw, RotateCcw, Save, Trash2 } from 'lucide-react'
import {
  addAclRule,
  deleteAclRule,
  fetchAclRules,
  persistAclRules,
  reloadAclRules,
  updateAclRule,
  type AclRule,
  type AclRulesResponse,
} from '../api/acl'
import { ApiError } from '../api/client'
import { Button } from '../components/ui/Button'
import { Panel } from '../components/dashboard/MetricWidget'
import { ErrorState } from '../components/ui/DataState'
import { FormField, FormGrid } from '../components/ui/Form'
import { Modal } from '../components/ui/Modal'
import { useToast } from '../components/ui/Toast'
import { useLanguage, translations } from '../lib/i18n'
import {
  ACL_CATEGORIES,
  CATEGORY_GROUP_ORDER,
  categoryOfRule,
  defaultCategoryRule,
  findCategoryDef,
  isCategoryRule,
  liveCategoryRows,
  unusedCatalog,
  withCategory,
} from '../lib/acl/categories'
import { PoliciesHelp } from './policies/PoliciesHelp'

type CategoryDraft = {
  id: string
  name: string
  category: string
  customCategory: string
  priority: string
  action: AclRule['action']
  enabled: boolean
  comment: string
  redirectUrl: string
  existing: boolean
}

const EMPTY_DRAFT: CategoryDraft = {
  id: '',
  name: '',
  category: 'social',
  customCategory: '',
  priority: '140',
  action: 'deny',
  enabled: true,
  comment: '',
  redirectUrl: '',
  existing: false,
}

export function PoliciesPage() {
  const [lang] = useLanguage()
  const tr = translations[lang]

  const { toast } = useToast()
  const [data, setData] = useState<AclRulesResponse | null>(null)
  const [loadError, setLoadError] = useState<{ title: string; detail: string } | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [ruleFilter, setRuleFilter] = useState('')
  const [draft, setDraft] = useState<CategoryDraft | null>(null)

  const load = async (silent = false) => {
    if (!silent) setLoading(true)
    setLoadError(null)
    try {
      setData(await fetchAclRules())
    } catch (error) {
      setData(null)
      const unauthorized = error instanceof ApiError && (error.status === 401 || error.status === 403)
      setLoadError({
        title: unauthorized ? 'ACL API unauthorized' : 'ACL API unreachable',
        detail: error instanceof ApiError ? `HTTP ${error.status}: ${error.message}` : String(error),
      })
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const handleReload = async () => {
    setBusy(true)
    try {
      await reloadAclRules()
      await load(true)
      toast('success', 'ACL rules reloaded from file')
    } catch {
      toast('error', 'Reload failed — check ACL API connection in Settings')
    }
    setBusy(false)
  }

  const handlePersist = async () => {
    setBusy(true)
    try {
      await persistAclRules()
      toast('success', 'Rules persisted to ACL_RULES_PATH')
    } catch {
      toast('error', 'Persist failed — ACL_RULES_PATH may be unset or unwritable')
    }
    setBusy(false)
  }

  const persistAfterChange = async (okMessage: string) => {
    try {
      await persistAclRules()
      toast('success', okMessage)
    } catch {
      toast('error', tr.policies.persistFailedAfterSave)
    }
    await load(true)
  }

  const handleDelete = async (id: string) => {
    if (!confirm(`Delete rule "${id}"?`)) return
    setBusy(true)
    try {
      await deleteAclRule(id)
      await persistAfterChange(`Rule "${id}" deleted`)
    } catch {
      toast('error', 'Delete failed — check ACL API token / connection')
    }
    setBusy(false)
  }

  const openCreate = (category?: string) => {
    const seed = defaultCategoryRule(category ?? 'social', (data?.rules ?? []).map((rule) => rule.id), lang)
    setDraft({
      ...EMPTY_DRAFT,
      id: seed.id,
      name: seed.name,
      category: category && findCategoryDef(category) ? category : category ? '__custom__' : 'social',
      customCategory: category && !findCategoryDef(category) ? category : '',
      priority: String(seed.priority),
      existing: false,
    })
  }

  const openEdit = (rule: AclRule) => {
    const slug = categoryOfRule(rule) ?? ''
    const known = Boolean(findCategoryDef(slug))
    setDraft({
      id: rule.id,
      name: rule.name,
      category: known ? slug : '__custom__',
      customCategory: known ? '' : slug,
      priority: String(rule.priority),
      action: rule.action,
      enabled: rule.enabled,
      comment: rule.comment ?? '',
      redirectUrl: rule.redirect_url ?? '',
      existing: true,
    })
  }

  const resolvedCategory = (form: CategoryDraft) =>
    (form.category === '__custom__' ? form.customCategory : form.category).trim().toLowerCase()

  const saveDraft = async () => {
    if (!draft) return
    const category = resolvedCategory(draft)
    if (!category) {
      toast('error', tr.policies.categoryHint)
      return
    }
    const priority = Number(draft.priority)
    if (!Number.isFinite(priority) || priority < 0) {
      toast('error', tr.policies.priority)
      return
    }
    const payload: AclRule = withCategory(
      {
        id: draft.id,
        name: draft.name.trim() || (lang === 'ru' ? `Блок: ${category}` : `Block ${category}`),
        enabled: draft.enabled,
        priority,
        action: draft.action,
        rule_type: { Category: category },
        comment: draft.comment.trim() || null,
        redirect_url: draft.action === 'redirect' ? draft.redirectUrl.trim() || null : null,
      },
      category,
    )
    setBusy(true)
    try {
      if (draft.existing) {
        await updateAclRule(payload)
      } else {
        await addAclRule(payload)
      }
      setDraft(null)
      await persistAfterChange(draft.existing ? `Rule "${payload.id}" updated` : `Rule "${payload.id}" created`)
    } catch (error) {
      toast('error', error instanceof ApiError ? error.message : 'Save failed — check ACL API token / connection')
    }
    setBusy(false)
  }

  const toggleCategory = async (category: string, current?: AclRule) => {
    setBusy(true)
    try {
      if (!current) {
        const created = defaultCategoryRule(category, (data?.rules ?? []).map((rule) => rule.id), lang)
        await addAclRule(created)
        await persistAfterChange(`${created.name} enabled`)
      } else {
        await updateAclRule({ ...current, enabled: !current.enabled })
        await persistAfterChange(`${current.name} ${current.enabled ? 'disabled' : 'enabled'}`)
      }
    } catch (error) {
      toast('error', error instanceof ApiError ? error.message : 'Update failed — check ACL API token / connection')
    }
    setBusy(false)
  }

  const filteredRules = (data?.rules ?? []).filter((rule) => {
    if (isCategoryRule(rule)) return false
    if (!ruleFilter.trim()) return true
    const query = ruleFilter.toLowerCase()
    return (
      rule.name.toLowerCase().includes(query) ||
      rule.id.toLowerCase().includes(query) ||
      rule.action.toLowerCase().includes(query) ||
      formatRuleType(rule).toLowerCase().includes(query)
    )
  })

  const liveRows = useMemo(() => liveCategoryRows(data?.rules ?? []), [data?.rules])
  const unused = useMemo(() => unusedCatalog(data?.rules ?? []), [data?.rules])

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-border/80 bg-surface-1/70 p-5 backdrop-blur-md">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary">{tr.policies.title}</h1>
          <p className="mt-1 text-sm text-text-secondary">
            {tr.policies.subtitle}{' '}
            <span className="font-mono font-bold text-text-primary px-2 py-0.5 rounded border border-border bg-surface-0">{data?.default_action ?? '—'}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => load()} disabled={loading || busy}>
            <RefreshCw className={`size-4 ${loading ? 'animate-spin' : ''}`} />
            {tr.policies.refresh}
          </Button>
          <Button variant="secondary" onClick={handlePersist} disabled={busy || loading || !data}>
            <Save className="size-4" />
            {tr.policies.persist}
          </Button>
          <Button variant="primary-glow" onClick={handleReload} disabled={busy || loading || !data}>
            <RotateCcw className={`size-4 ${busy ? 'animate-spin' : ''}`} />
            {tr.policies.reload}
          </Button>
        </div>
      </div>

      <PoliciesHelp lang={lang} />

      {loadError ? (
        <ErrorState title={loadError.title} detail={loadError.detail} onRetry={() => load()} />
      ) : (
        <>
          <Panel
            title={`${tr.policies.categories} (${liveRows.length})`}
            action={
              <Button variant="secondary" onClick={() => openCreate()} disabled={busy || loading || !data}>
                <Plus className="size-4" />
                {tr.policies.addCategory}
              </Button>
            }
          >
            <p className="mb-4 text-xs text-text-secondary">{tr.policies.categoriesSubtitle}</p>
            {liveRows.length === 0 ? (
              <p className="rounded-lg border border-dashed border-border px-3 py-6 text-center text-sm text-text-secondary">
                {tr.policies.noCategoryRules}
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead className="border-b border-border text-xs uppercase text-text-secondary font-bold">
                    <tr>
                      <th className="pb-2 pr-4">{tr.policies.category}</th>
                      <th className="pb-2 pr-4">{tr.policies.action}</th>
                      <th className="pb-2 pr-4">{tr.policies.priority}</th>
                      <th className="pb-2 pr-4">{tr.policies.status}</th>
                      <th className="pb-2"> </th>
                    </tr>
                  </thead>
                  <tbody>
                    {liveRows.map(({ def, rules: catRules }) => {
                      const primary = catRules[0]
                      return (
                        <tr key={def.id} className="border-t border-border/50">
                          <td className="py-2.5 pr-4">
                            <div className="font-medium text-text-primary">{def.label[lang]}</div>
                            <div className="font-mono text-[11px] text-text-secondary">
                              {def.id}
                              {def.ut1.length > 0 ? ` · UT1 ${def.ut1.join(', ')}` : ''}
                            </div>
                          </td>
                          <td className="py-2.5 pr-4 capitalize">{primary.action}</td>
                          <td className="py-2.5 pr-4 font-mono text-xs">{primary.priority}</td>
                          <td className="py-2.5 pr-4">
                            <span className={primary.enabled ? 'text-success' : 'text-text-secondary'}>
                              {primary.enabled ? 'enabled' : 'disabled'}
                            </span>
                          </td>
                          <td className="py-2.5">
                            <div className="flex justify-end gap-1">
                              <button
                                type="button"
                                className="touch-target rounded-md px-2 py-1 text-xs font-semibold text-text-primary hover:bg-surface-2 disabled:opacity-40"
                                disabled={busy}
                                onClick={() => toggleCategory(def.id, primary)}
                              >
                                {primary.enabled ? tr.policies.disableRule : tr.policies.enableRule}
                              </button>
                              <button
                                type="button"
                                className="touch-target rounded-md p-2 text-text-secondary hover:bg-surface-2 hover:text-text-primary disabled:opacity-40"
                                disabled={busy}
                                onClick={() => openEdit(primary)}
                                aria-label={`${tr.policies.editCategory} ${def.id}`}
                              >
                                <Pencil className="size-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {unused.length > 0 && (
              <p className="mt-3 text-xs text-text-secondary">
                {tr.policies.catalogHint} {unused.length} — {tr.policies.addCategory}.
              </p>
            )}
          </Panel>

          <Panel
            title={`${tr.policies.otherRules} (${filteredRules.length})`}
            action={
              <div className="w-64">
                <input
                  type="text"
                  placeholder={tr.common.search}
                  value={ruleFilter}
                  onChange={(e) => setRuleFilter(e.target.value)}
                  className="w-full rounded-lg border border-border bg-surface-0 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-secondary focus:border-accent focus:outline-none"
                />
              </div>
            }
          >
            <p className="mb-4 text-xs text-text-secondary">{tr.policies.otherRulesHint}</p>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead className="border-b border-border text-xs uppercase text-text-secondary font-bold">
                  <tr>
                    <th className="pb-3 pr-4">{tr.policies.priority}</th>
                    <th className="pb-3 pr-4">{tr.policies.name}</th>
                    <th className="pb-3 pr-4">{tr.policies.type}</th>
                    <th className="pb-3 pr-4">{tr.policies.action}</th>
                    <th className="pb-3 pr-4">{tr.policies.status}</th>
                    <th className="pb-3"> </th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.map((rule) => (
                    <RuleRow
                      key={rule.id}
                      rule={rule}
                      onDelete={handleDelete}
                      onEdit={isCategoryRule(rule) ? openEdit : undefined}
                      disabled={busy}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            <div className="space-y-3 md:hidden">
              {filteredRules.map((rule) => (
                <div key={rule.id} className="rounded-xl border border-border/80 bg-surface-0/60 p-4">
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-semibold text-text-primary">{rule.name}</span>
                    <div className="flex gap-1">
                      {isCategoryRule(rule) && (
                        <button
                          type="button"
                          className="text-text-secondary hover:text-text-primary cursor-pointer"
                          disabled={busy}
                          onClick={() => openEdit(rule)}
                          aria-label={`Edit ${rule.id}`}
                        >
                          <Pencil className="size-4" />
                        </button>
                      )}
                      <button
                        type="button"
                        className="text-danger hover:text-danger/80 cursor-pointer"
                        disabled={busy}
                        onClick={() => handleDelete(rule.id)}
                        aria-label={`Delete ${rule.id}`}
                      >
                        <Trash2 className="size-4" />
                      </button>
                    </div>
                  </div>
                  <p className="mt-1.5 font-mono text-xs text-text-secondary">
                    P{rule.priority} · {rule.action} · {formatRuleType(rule)}
                  </p>
                </div>
              ))}
            </div>
          </Panel>
        </>
      )}

      <div className="rounded-lg border border-border bg-surface-0 p-4 text-sm text-text-secondary">
        {tr.policies.liveCrud}{' '}
        <code className="rounded bg-surface-2 px-1 font-mono text-xs">PUT/DELETE /api/acl/rules/:id</code>
        {' · '}
        <code className="rounded bg-surface-2 px-1 font-mono text-xs">POST /api/acl/persist</code>
      </div>

      <CategoryRuleModal
        open={draft !== null}
        draft={draft}
        busy={busy}
        lang={lang}
        onChange={setDraft}
        onClose={() => setDraft(null)}
        onSave={saveDraft}
        onDelete={
          draft?.existing
            ? async () => {
                await handleDelete(draft.id)
                setDraft(null)
              }
            : undefined
        }
      />
    </div>
  )
}

function CategoryRuleModal({
  open,
  draft,
  busy,
  lang,
  onChange,
  onClose,
  onSave,
  onDelete,
}: {
  open: boolean
  draft: CategoryDraft | null
  busy: boolean
  lang: 'en' | 'ru'
  onChange: (next: CategoryDraft) => void
  onClose: () => void
  onSave: () => void
  onDelete?: () => void
}) {
  const tr = translations[lang]
  if (!draft) return null

  const catalogOptions = [
    ...CATEGORY_GROUP_ORDER.flatMap((group) =>
      ACL_CATEGORIES.filter((item) => item.group === group).map((item) => ({
        value: item.id,
        label: `${item.label[lang]} (${item.id})`,
      })),
    ),
    { value: '__custom__', label: tr.policies.customCategory },
  ]
  const selected = ACL_CATEGORIES.find((item) => item.id === draft.category)

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={draft.existing ? tr.policies.editCategory : tr.policies.addCategory}
      footer={
        <>
          {onDelete && (
            <Button variant="danger" onClick={onDelete} disabled={busy} className="mr-auto">
              <Trash2 className="size-4" />
              {tr.policies.deleteRule}
            </Button>
          )}
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {tr.common.cancel}
          </Button>
          <Button variant="primary" onClick={onSave} disabled={busy}>
            {tr.policies.saveRule}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormField label={tr.policies.category} required>
          <select
            value={draft.category}
            onChange={(e) => onChange({ ...draft, category: e.target.value })}
            className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
          >
            {catalogOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <p className="mt-1 text-xs text-text-secondary">{tr.policies.catalogHint}</p>
          {selected && (
            <p className="mt-1 font-mono text-[11px] text-text-secondary">
              {selected.ut1.length > 0
                ? `${tr.policies.ut1Folders}: ${selected.ut1.join(', ')}`
                : tr.policies.engineOnly}
            </p>
          )}
        </FormField>
        {draft.category === '__custom__' && (
          <FormField label={tr.policies.customCategory} required>
            <input
              type="text"
              value={draft.customCategory}
              onChange={(e) => onChange({ ...draft, customCategory: e.target.value })}
              placeholder="filehosting"
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
            <p className="mt-1 text-xs text-text-secondary">{tr.policies.categoryHint}</p>
          </FormField>
        )}
        <FormGrid>
          <FormField label={tr.policies.name} required>
            <input
              type="text"
              value={draft.name}
              onChange={(e) => onChange({ ...draft, name: e.target.value })}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>
          <FormField label={tr.policies.priority} required>
            <input
              type="number"
              min={0}
              value={draft.priority}
              onChange={(e) => onChange({ ...draft, priority: e.target.value })}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>
        </FormGrid>
        <FormGrid>
          <FormField label={tr.policies.action} required>
            <select
              value={draft.action}
              onChange={(e) => onChange({ ...draft, action: e.target.value as AclRule['action'] })}
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="deny">deny</option>
              <option value="allow">allow</option>
              <option value="redirect">redirect</option>
            </select>
          </FormField>
          <FormField label={tr.policies.status}>
            <label className="flex min-h-[40px] items-center gap-2 text-sm text-text-primary">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(e) => onChange({ ...draft, enabled: e.target.checked })}
                className="size-5 accent-accent"
              />
              {tr.policies.enabled}
            </label>
          </FormField>
        </FormGrid>
        {draft.action === 'redirect' && (
          <FormField label={tr.policies.redirectUrl} required>
            <input
              type="url"
              value={draft.redirectUrl}
              onChange={(e) => onChange({ ...draft, redirectUrl: e.target.value })}
              placeholder="https://blocked.example/policy"
              className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 font-mono text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </FormField>
        )}
        <FormField label={tr.policies.comment}>
          <input
            type="text"
            value={draft.comment}
            onChange={(e) => onChange({ ...draft, comment: e.target.value })}
            className="w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
          />
        </FormField>
      </div>
    </Modal>
  )
}

function RuleRow({
  rule,
  onDelete,
  onEdit,
  disabled,
}: {
  rule: AclRule
  onDelete: (id: string) => void
  onEdit?: (rule: AclRule) => void
  disabled: boolean
}) {
  return (
    <tr className="border-t border-border/50">
      <td className="py-3 pr-4 font-mono text-xs">{rule.priority}</td>
      <td className="py-3 pr-4">{rule.name}</td>
      <td className="py-3 pr-4 font-mono text-xs">{formatRuleType(rule)}</td>
      <td className="py-3 pr-4 capitalize">{rule.action}</td>
      <td className="py-3 pr-4">
        <span className={rule.enabled ? 'text-success' : 'text-text-secondary'}>
          {rule.enabled ? 'enabled' : 'disabled'}
        </span>
      </td>
      <td className="py-3">
        <div className="flex justify-end gap-1">
          {onEdit && (
            <button
              type="button"
              className="touch-target rounded-md p-2 text-text-secondary hover:bg-surface-2 hover:text-text-primary disabled:opacity-40"
              disabled={disabled}
              onClick={() => onEdit(rule)}
              aria-label={`Edit ${rule.id}`}
            >
              <Pencil className="size-4" />
            </button>
          )}
          <button
            type="button"
            className="touch-target rounded-md p-2 text-danger hover:bg-danger/10 disabled:opacity-40"
            disabled={disabled}
            onClick={() => onDelete(rule.id)}
            aria-label={`Delete ${rule.id}`}
          >
            <Trash2 className="size-4" />
          </button>
        </div>
      </td>
    </tr>
  )
}

function formatRuleType(rule: AclRule): string {
  const entries = Object.entries(rule.rule_type ?? {})
  if (entries.length === 0) return '—'
  const [key, value] = entries[0]
  if (value !== null && typeof value === 'object') return `${key}: ${JSON.stringify(value)}`
  return `${key}: ${String(value)}`
}
