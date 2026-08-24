import assert from 'node:assert/strict'
import test from 'node:test'
import {
  FROZEN_PATHS,
  isFrozenPath,
  resolveRouteScope,
  ROUTE_SCOPES,
} from '../src/lib/routeScope.ts'

test('primary hybrid surfaces are supported', () => {
  for (const path of ['/', '/logs', '/policies', '/settings', '/rpz', '/devices', '/amneziawg', '/users', '/analytics']) {
    assert.equal(resolveRouteScope(path).maturity, 'supported', path)
    assert.equal(isFrozenPath(path), false, path)
  }
})

test('experimental deep-links are frozen', () => {
  for (const path of ['/wasm', '/cluster', '/ai-cache']) {
    assert.equal(isFrozenPath(path), true, path)
    assert.ok(FROZEN_PATHS.includes(path), path)
    const scope = resolveRouteScope(path)
    assert.equal(scope.maturity, 'frozen')
    assert.ok(scope.frozenNote && scope.frozenNote.length > 0)
  }
})

test('supported routes never include frozen paths', () => {
  const supported = ROUTE_SCOPES.filter((r) => r.maturity === 'supported').map((r) => r.path)
  for (const frozen of FROZEN_PATHS) {
    assert.equal(supported.includes(frozen), false)
  }
})
