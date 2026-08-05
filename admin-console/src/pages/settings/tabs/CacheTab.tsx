import { Checkbox, FormGrid, FormSection, Input } from '../../../components/ui/Form'
import { cacheMetadataEstimate } from '../../../lib/config/collect'
import type { FormTabProps } from '../types'

export function CacheTab({ form, update, tr }: FormTabProps) {
  return (
    <div className="space-y-6">
      <FormSection title={tr.settings.tabCache}>
        <Input
          label="CACHE_CAPACITY"
          type="number"
          value={form.cacheCapacity}
          onChange={(e) => update('cacheCapacity', e.target.value)}
          hint={cacheMetadataEstimate(form.cacheCapacity)}
        />
        <FormGrid>
          <Input
            label="CACHE_TTL_SECONDS"
            type="number"
            value={form.cacheTtl}
            onChange={(e) => update('cacheTtl', e.target.value)}
          />
          <Input
            label="CACHE_SHARDS"
            type="number"
            value={form.cacheShards}
            onChange={(e) => update('cacheShards', e.target.value)}
          />
        </FormGrid>
        <FormGrid>
          <Input
            label="Max cache body (MB)"
            type="number"
            value={form.maxBodySizeMb}
            onChange={(e) => update('maxBodySizeMb', e.target.value)}
          />
          <Input
            label="Spill threshold (KB)"
            type="number"
            value={form.spillThresholdKb}
            onChange={(e) => update('spillThresholdKb', e.target.value)}
          />
        </FormGrid>
        <Checkbox
          label="CACHE_HONOR_CACHE_CONTROL"
          checked={form.cacheHonorCacheControl}
          onChange={(v) => update('cacheHonorCacheControl', v)}
        />
        <Checkbox
          label="NEGATIVE_CACHE_ENABLED"
          checked={form.negativeCacheEnabled}
          onChange={(v) => update('negativeCacheEnabled', v)}
        />
        {form.negativeCacheEnabled && (
          <Input
            label="NEGATIVE_CACHE_TTL_SECONDS"
            type="number"
            value={form.negativeCacheTtl}
            onChange={(e) => update('negativeCacheTtl', e.target.value)}
          />
        )}
      </FormSection>
      <FormSection title="Redis L2">
        <Checkbox
          label="REDIS_L2_ENABLED"
          checked={form.redisL2Enabled}
          onChange={(v) => update('redisL2Enabled', v)}
        />
        {form.redisL2Enabled && (
          <FormGrid>
            <Input label="REDIS_URL" value={form.redisUrl} onChange={(e) => update('redisUrl', e.target.value)} />
            <Input
              label="REDIS_KEY_PREFIX"
              value={form.redisKeyPrefix}
              onChange={(e) => update('redisKeyPrefix', e.target.value)}
            />
          </FormGrid>
        )}
      </FormSection>
      <FormSection title="AI Semantic Cache (L0)">
        <Checkbox
          label="AI_CACHE_ENABLED"
          checked={form.aiCacheEnabled}
          onChange={(v) => update('aiCacheEnabled', v)}
          hint="Cache LLM POST requests using vector similarity"
        />
        {form.aiCacheEnabled && (
          <FormGrid>
            <Input
              label="OLLAMA_URL (Embeddings)"
              value={form.ollamaUrl}
              onChange={(e) => update('ollamaUrl', e.target.value)}
            />
            <Input
              label="QDRANT_URL (Vector DB)"
              value={form.qdrantUrl}
              onChange={(e) => update('qdrantUrl', e.target.value)}
            />
          </FormGrid>
        )}
      </FormSection>
    </div>
  )
}
