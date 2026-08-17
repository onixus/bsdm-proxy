import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const srcDir = path.join(here, '..', 'src')

/**
 * `src/lib/i18n.ts` imports React, so it cannot be loaded by the plain-node
 * test runner. The copy table is a plain object literal though, so we read the
 * key structure straight out of the source text.
 */
function readTranslationKeys(): { ru: string[]; en: string[] } {
  const source = fs.readFileSync(path.join(srcDir, 'lib', 'i18n.ts'), 'utf8')
  const start = source.indexOf('export const translations = {')
  assert.ok(start >= 0, 'translations literal not found')

  const keys: { ru: string[]; en: string[] } = { ru: [], en: [] }
  let lang: 'ru' | 'en' | null = null
  const stack: string[] = []

  for (const raw of source.slice(start).split('\n').slice(1)) {
    const line = raw.trim()
    if (line.startsWith('//') || line === '') continue

    if (stack.length === 0 && (line === 'ru: {' || line === 'en: {')) {
      lang = line.slice(0, 2) as 'ru' | 'en'
      stack.push(lang)
      continue
    }
    if (!lang) continue

    const open = /^([A-Za-z0-9_]+):\s*\{$/.exec(line)
    if (open) {
      stack.push(open[1])
      keys[lang].push(stack.slice(1).join('.'))
      continue
    }
    if (line.startsWith('}')) {
      stack.pop()
      if (stack.length === 0) lang = null
      continue
    }

    const leaf = /^([A-Za-z0-9_]+):/.exec(line)
    if (leaf) keys[lang].push([...stack.slice(1), leaf[1]].join('.'))
  }

  return keys
}

test('ru and en translations expose the same keys', () => {
  const { ru, en } = readTranslationKeys()
  assert.ok(ru.length > 100, `expected a populated ru table, got ${ru.length} keys`)

  const missingInEn = ru.filter((k) => !en.includes(k))
  const missingInRu = en.filter((k) => !ru.includes(k))

  assert.deepEqual(missingInEn, [], 'keys present in ru but missing in en')
  assert.deepEqual(missingInRu, [], 'keys present in en but missing in ru')
})

/**
 * Guards the bug this refactor fixed: hardcoded Russian copy in components
 * leaked into the English UI (and vice versa). Cyrillic belongs in the copy
 * modules (i18n.ts, the ACL category catalog, the nav descriptions) only.
 */
test('no stray Cyrillic literals outside the copy modules', () => {
  const allowed = new Set([
    path.join('lib', 'i18n.ts'),
    path.join('lib', 'acl', 'categories.ts'),
    path.join('navigation', 'menu.ts'),
  ])

  const offenders: string[] = []
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
        continue
      }
      if (!/\.(ts|tsx)$/.test(entry.name)) continue
      const rel = path.relative(srcDir, full)
      if (allowed.has(rel)) continue

      fs.readFileSync(full, 'utf8')
        .split('\n')
        .forEach((line, index) => {
          if (/[А-Яа-яЁё]/.test(line)) offenders.push(`${rel}:${index + 1}`)
        })
    }
  }
  walk(srcDir)

  assert.deepEqual(offenders, [], 'move this copy into src/lib/i18n.ts')
})
