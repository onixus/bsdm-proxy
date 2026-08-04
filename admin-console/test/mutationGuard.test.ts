import assert from 'node:assert/strict'
import test from 'node:test'
import { isReadOnlyMethod, mutationRequiresCredentials } from '../src/api/mutationGuard.ts'

test('read-only methods remain available without credentials', () => {
  for (const method of ['GET', 'get', 'HEAD', 'OPTIONS']) {
    assert.equal(isReadOnlyMethod(method), true)
    assert.equal(mutationRequiresCredentials(method, ''), false)
  }
})

test('mutating methods require a non-empty token', () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    assert.equal(mutationRequiresCredentials(method, ''), true)
    assert.equal(mutationRequiresCredentials(method, '   '), true)
    assert.equal(mutationRequiresCredentials(method, 'session-token'), false)
  }
})

test('mutation gate matrix matches pilot honesty (no token → block writes)', () => {
  assert.equal(mutationRequiresCredentials('GET', ''), false)
  assert.equal(mutationRequiresCredentials('POST', ''), true)
  assert.equal(mutationRequiresCredentials('DELETE', '  x  '), false)
})
