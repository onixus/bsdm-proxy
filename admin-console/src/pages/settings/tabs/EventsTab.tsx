import { Checkbox, FormGrid, FormSection, Input } from '../../../components/ui/Form'
import type { FormTabProps } from '../types'

export function EventsTab({ form, update, tr }: FormTabProps) {
  return (
    <div className="space-y-6">
      <FormSection title={tr.settings.tabEvents}>
        <FormGrid>
          <Input
            label="KAFKA_BROKERS"
            value={form.kafkaBrokers}
            onChange={(e) => update('kafkaBrokers', e.target.value)}
          />
          <Input
            label="KAFKA_TOPIC"
            value={form.kafkaTopic}
            onChange={(e) => update('kafkaTopic', e.target.value)}
          />
        </FormGrid>
        <FormGrid>
          <Input
            label="KAFKA_SAMPLE_RATE"
            value={form.kafkaSampleRate}
            onChange={(e) => update('kafkaSampleRate', e.target.value)}
            hint="0 = log every request, N = 1-in-N sampling"
          />
          <Input
            label="KAFKA_QUEUE_CAPACITY"
            type="number"
            value={form.kafkaQueueCapacity}
            onChange={(e) => update('kafkaQueueCapacity', e.target.value)}
          />
        </FormGrid>
        <FormGrid>
          <Input
            label="KAFKA_ACKS"
            value={form.kafkaAcks}
            onChange={(e) => update('kafkaAcks', e.target.value)}
          />
          <Input
            label="METRICS_SAMPLE_RATE"
            value={form.metricsSampleRate}
            onChange={(e) => update('metricsSampleRate', e.target.value)}
          />
        </FormGrid>
      </FormSection>
      <FormSection title="ClickHouse (search index)">
        <Input
          label="CLICKHOUSE_URL"
          value={form.clickhouseUrl}
          onChange={(e) => update('clickhouseUrl', e.target.value)}
        />
        <FormGrid>
          <Input
            label="CLICKHOUSE_DATABASE"
            value={form.clickhouseDatabase}
            onChange={(e) => update('clickhouseDatabase', e.target.value)}
          />
          <Input
            label="CLICKHOUSE_TABLE"
            value={form.clickhouseTable}
            onChange={(e) => update('clickhouseTable', e.target.value)}
          />
        </FormGrid>
        <Input
          label="SEARCH_API_TOKEN"
          type="password"
          value={form.searchApiToken}
          onChange={(e) => update('searchApiToken', e.target.value)}
          hint="Session-only, never persisted"
        />
      </FormSection>
      <FormSection title="Observability stack (compose export)">
        <Checkbox
          label="Include Prometheus"
          checked={form.prometheusEnabled}
          onChange={(v) => update('prometheusEnabled', v)}
        />
        <Checkbox
          label="Include Grafana"
          checked={form.grafanaEnabled}
          onChange={(v) => update('grafanaEnabled', v)}
        />
      </FormSection>
      <FormSection title="Alert Worker (SIEM Webhooks)">
        <Checkbox
          label="ALERT_WORKER_ENABLED"
          checked={form.alertWorkerEnabled}
          onChange={(v) => update('alertWorkerEnabled', v)}
          hint="Enable sending analytical alerts to SIEM or external webhooks"
        />
        {form.alertWorkerEnabled && (
          <Input
            label="ALERT_WEBHOOK_URL"
            value={form.alertWebhookUrl}
            onChange={(e) => update('alertWebhookUrl', e.target.value)}
            hint="e.g. https://hooks.slack.com/services/... or http://siem:8080/events"
          />
        )}
      </FormSection>
    </div>
  )
}
