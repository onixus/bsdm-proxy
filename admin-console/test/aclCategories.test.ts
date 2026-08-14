import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import type { AclRule } from '../src/api/acl.ts'
import {
  allocateCategoryRuleId,
  categoryOfRule,
  categoryRows,
  categoryRuleId,
  liveCategoryRows,
  unusedCatalog,
  defaultCategoryRule,
  isCategoryRule,
  withCategory,
} from '../src/lib/acl/categories.ts'

function rule(partial: Partial<AclRule> & Pick<AclRule, 'id' | 'rule_type'>): AclRule {
  return {
    name: partial.id,
    enabled: true,
    priority: 100,
    action: 'deny',
    ...partial,
  }
}

describe('categoryOfRule', () => {
  it('reads serde Category key', () => {
    assert.equal(categoryOfRule(rule({ id: 'a', rule_type: { Category: 'Social' } })), 'social')
    assert.equal(isCategoryRule(rule({ id: 'a', rule_type: { Category: 'social' } })), true)
  })

  it('reads lowercase fixture key', () => {
    assert.equal(categoryOfRule(rule({ id: 'b', rule_type: { category: 'phishing' } })), 'phishing')
  })

  it('ignores domain rules', () => {
    assert.equal(categoryOfRule(rule({ id: 'c', rule_type: { Domain: '*.example.com' } })), null)
    assert.equal(isCategoryRule(rule({ id: 'c', rule_type: { Domain: '*.example.com' } })), false)
  })
})

describe('categoryRuleId', () => {
  it('slugifies and avoids collisions', () => {
    assert.equal(categoryRuleId('Social'), 'block-social')
    assert.equal(categoryRuleId('filehosting'), 'block-filehosting')
    assert.equal(allocateCategoryRuleId('social', ['block-social']), 'block-social-2')
    assert.equal(allocateCategoryRuleId('social', ['block-social', 'block-social-2']), 'block-social-3')
  })
})

describe('defaultCategoryRule', () => {
  it('uses catalog priority and Category key', () => {
    const created = defaultCategoryRule('adult', [])
    assert.equal(created.id, 'block-adult')
    assert.equal(created.priority, 150)
    assert.equal(created.action, 'deny')
    assert.deepEqual(created.rule_type, { Category: 'adult' })
  })

  it('keeps custom slugs as custom ACL names', () => {
    const created = defaultCategoryRule('mixed_adult', ['block-mixed-adult'])
    assert.equal(created.id, 'block-mixed-adult-2')
    assert.deepEqual(created.rule_type, { Category: 'mixed_adult' })
  })
})

describe('categoryRows', () => {
  it('pairs catalog entries with matching rules and appends unknown slugs', () => {
    const rows = categoryRows([
      rule({ id: 'block-social', rule_type: { Category: 'social' } }),
      rule({ id: 'block-weird', rule_type: { Category: 'mixed_adult' } }),
      rule({ id: 'block-host', rule_type: { Domain: 't.me' } }),
    ])
    const social = rows.find((row) => row.def.id === 'social')
    const extra = rows.find((row) => row.def.id === 'mixed_adult')
    assert.equal(social?.rules[0]?.id, 'block-social')
    assert.equal(extra?.rules[0]?.id, 'block-weird')
    assert.equal(rows.some((row) => row.def.id === 'filehosting' && row.rules.length === 0), true)
    const live = liveCategoryRows([
      rule({ id: 'block-social', rule_type: { Category: 'social' } }),
      rule({ id: 'block-host', rule_type: { Domain: 't.me' } }),
    ])
    assert.deepEqual(live.map((row) => row.def.id), ['social'])
    assert.equal(unusedCatalog(live.flatMap((row) => row.rules)).some((def) => def.id === 'adult'), true)
  })
})

describe('withCategory', () => {
  it('replaces rule_type with a Category payload', () => {
    const updated = withCategory(rule({ id: 'x', rule_type: { Domain: 'x' } }), 'FileHosting')
    assert.deepEqual(updated.rule_type, { Category: 'filehosting' })
  })
})
