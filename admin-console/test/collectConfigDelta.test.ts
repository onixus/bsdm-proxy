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

  it('sends only changed pilot paths', () => {
    const form = {
      ...defaultFormState,
      httpPort: '3128',
      aclRulesPath: '/var/lib/bsdm-proxy/acl-rules.json',
    }
    const baseline = {
      HTTP_PORT: '3128',
      ACL_RULES_PATH: '/etc/bsdm-proxy/acl-rules.json',
    }
    const delta = collectConfigDelta(form, baseline)
    assert.equal(delta.ACL_RULES_PATH, '/var/lib/bsdm-proxy/acl-rules.json')
    assert.equal(delta.HTTP_PORT, undefined)
    const { sensitive } = describeEnvDelta(delta, baseline)
    assert.ok(sensitive.includes('ACL_RULES_PATH'))
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
