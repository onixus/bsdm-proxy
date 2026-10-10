import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { defaultFormState } from '../src/lib/config/types.ts'
import {
  collectConfig,
  collectConfigDelta,
  describeEnvDelta,
  isMaskedSecret,
} from '../src/lib/config/collect.ts'

describe('collectConfigDelta', () => {
  it('detects masked secrets', () => {
    assert.equal(isMaskedSecret('***'), true)
    assert.equal(isMaskedSecret('  ***  '), true)
    assert.equal(isMaskedSecret('real-token'), false)
  })

  it('does not re-send baseline keys that match the form', () => {
    const form = { ...defaultFormState, httpPort: '3128', aclRulesPath: '/etc/bsdm-proxy/acl-rules.json' }
    const baseline = {
      HTTP_PORT: '3128',
      METRICS_PORT: '9090',
      ACL_RULES_PATH: '/etc/bsdm-proxy/acl-rules.json',
      ACL_ENABLED: 'true',
    }
    // Align form ACL with baseline so only true diffs remain
    form.aclEnabled = true
    form.metricsPort = '9090'
    const delta = collectConfigDelta(form, baseline)
    assert.equal(delta.HTTP_PORT, undefined)
    assert.equal(delta.ACL_RULES_PATH, undefined)
  })

  it('sends only changed pilot-sensitive keys', () => {
    const form = {
      ...defaultFormState,
      httpPort: '3130',
      metricsPort: '9090',
    }
    const baseline = {
      HTTP_PORT: '3128',
      METRICS_PORT: '9090',
    }
    const delta = collectConfigDelta(form, baseline)
    assert.equal(delta.HTTP_PORT, '3130')
    assert.equal(delta.METRICS_PORT, undefined)
    const { sensitive } = describeEnvDelta(delta, baseline)
    assert.ok(sensitive.includes('HTTP_PORT'))
  })

  it('never sends host-managed keys the control plane rejects', () => {
    const form = {
      ...defaultFormState,
      aclRulesPath: '/var/lib/bsdm-proxy/acl-rules.json',
      controlApiToken: 'new-token',
      upstreamCaCert: '/tmp/ca.pem',
    }
    const baseline = {
      HTTP_PORT: '3128',
      ACL_RULES_PATH: '/etc/bsdm-proxy/acl-rules.json',
    }
    const delta = collectConfigDelta(form, baseline)
    assert.equal(delta.ACL_RULES_PATH, undefined)
    assert.equal(delta.CONTROL_API_TOKEN, undefined)
    assert.equal(delta.UPSTREAM_CA_CERT, undefined)
  })

  it('never sends traffic/credential destinations or listener binds', () => {
    const form = {
      ...defaultFormState,
      icapUrl: 'icap://attacker:1344/reqmod',
      kafkaBrokers: 'attacker:9092',
      clickhouseUrl: 'http://attacker:8123',
    }
    const baseline = { HTTP_PORT: '3128', ICAP_URL: 'icap://icap:1344/reqmod' }
    const delta = collectConfigDelta(form, baseline)
    assert.equal(delta.ICAP_URL, undefined)
    assert.equal(delta.KAFKA_BROKERS, undefined)
    assert.equal(delta.CLICKHOUSE_URL, undefined)
  })

  it('does not dump full UI defaults when baseline is live pilot env', () => {
    const form = { ...defaultFormState }
    // defaults still enable UT1 in form; live pilot has UT1 off / unset
    const baseline = {
      HTTP_PORT: '3128',
      METRICS_PORT: '9090',
      ACL_RULES_PATH: '/etc/bsdm-proxy/acl-rules.json',
      UT1_ENABLED: 'false',
      RKN_SYNC_ENABLED: 'false',
    }
    form.httpPort = '3128'
    form.metricsPort = '9090'
    form.aclRulesPath = '/etc/bsdm-proxy/acl-rules.json'
    form.ut1Enabled = false
    form.rknSyncEnabled = false
    const delta = collectConfigDelta(form, baseline)
    // Should not invent RKN_SYNC_URL / DOH etc. from form-only defaults
    assert.equal(delta.RKN_SYNC_URL, undefined)
    assert.equal(delta.DOH_BIND, undefined)
    assert.equal(delta.UT1_PATH, undefined)
  })

  it('never writes masked secrets back', () => {
    const form = { ...defaultFormState, aclApiToken: '***' }
    const baseline = { ACL_API_TOKEN: '***', HTTP_PORT: '3128' }
    form.httpPort = '3128'
    const delta = collectConfigDelta(form, baseline)
    assert.equal(delta.ACL_API_TOKEN, undefined)
  })

  it('full collect still used for export (includes defaults)', () => {
    const full = collectConfig(defaultFormState)
    assert.ok(full.HTTP_PORT)
    assert.ok(full.ACL_RULES_PATH)
  })
})
