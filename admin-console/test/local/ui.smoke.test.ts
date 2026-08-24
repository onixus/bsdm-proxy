/**
 * Local UI smoke test.
 *
 * Boots the production build against the fixture backend (`mock-api.ts`) and
 * drives a real Chromium over every console route. It is the cheapest honest
 * answer to "does the UI actually work?" — no proxy, Kafka or ClickHouse
 * required, and no network access beyond loopback.
 *
 *   npm run test:ui
 *
 * Each route must:
 *   - render its page heading and data that can only come from the backend;
 *   - report `Live` provenance — never the demo badge or an error state;
 *   - produce no console errors, page errors, or failed HTTP requests.
 */

import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { after, before, describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'
import { chromium, type Browser, type Page } from 'playwright-core'
import { MARKERS, NOW_MS } from './fixtures.ts'
import { isPathWithinRoot, startMockApi, type MockApiInstance } from './mock-api.ts'

const here = dirname(fileURLToPath(import.meta.url))
const distDir = join(here, '..', '..', 'dist')

/** `UI_TEST_SCREENSHOTS=1 npm run test:ui` writes one PNG per route for review. */
const screenshotDir = process.env.UI_TEST_SCREENSHOTS ? join(here, 'screenshots') : null

/**
 * Chromium lookup: explicit override first, then browsers this image is known
 * to ship. Returning `undefined` lets playwright-core fall back to a browser
 * it installed itself (`npx playwright-core install chromium`).
 */
function chromiumExecutable(): string | undefined {
  const candidates = [
    process.env.CHROMIUM_PATH,
    process.env.PLAYWRIGHT_BROWSERS_PATH
      ? join(process.env.PLAYWRIGHT_BROWSERS_PATH, 'chromium')
      : undefined,
    '/opt/pw-browsers/chromium',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
  ].filter((candidate): candidate is string => Boolean(candidate))
  return candidates.find((candidate) => existsSync(candidate))
}

interface RouteCase {
  path: string
  name: string
  /** Text that can only be on screen if the fixture backend was reached. */
  marker: string
  frozen?: boolean
}

const ROUTES: RouteCase[] = [
  { path: '/', name: 'Dashboard', marker: MARKERS.dashboard },
  { path: '/logs', name: 'Logs', marker: MARKERS.logs },
  { path: '/analytics', name: 'Analytics', marker: MARKERS.analytics },
  { path: '/threat-scores', name: 'Threat Scores', marker: MARKERS.threatScores },
  { path: '/security', name: 'Data Security', marker: MARKERS.security },
  { path: '/policies', name: 'Policies', marker: MARKERS.policies },
  { path: '/rpz', name: 'DNS RPZ', marker: MARKERS.rpz },
  { path: '/devices', name: 'Devices', marker: MARKERS.devices },
  { path: '/users', name: 'Users', marker: MARKERS.users },
  { path: '/settings', name: 'Settings', marker: MARKERS.settings },
  { path: '/wasm', name: 'Wasm plugins (frozen)', marker: 'header-scrubber', frozen: true },
  { path: '/cluster', name: 'Cluster mesh (frozen)', marker: 'bsdm-proxy-node-beta', frozen: true },
  { path: '/ai-cache', name: 'AI semantic cache (frozen)', marker: 'gpt-4o-mini', frozen: true },
  { path: '/amneziawg', name: 'AmneziaWG', marker: '10.8.0.1/24' },
]

let mock: MockApiInstance
let browser: Browser

/**
 * Console noise that is not a UI defect: Chromium's own devtools chatter and
 * requests aborted by React Query when a route unmounts mid-flight.
 */
function isBenign(text: string): boolean {
  return /Download the React DevTools|net::ERR_ABORTED|The operation was aborted/i.test(text)
}

interface PageProbe {
  page: Page
  problems: string[]
}

async function openPage(): Promise<PageProbe> {
  const context = await browser.newContext({
    baseURL: mock.url,
    viewport: { width: 1440, height: 1000 },
    locale: 'en-US',
    timezoneId: 'UTC',
  })
  // Deterministic language and provenance: demo mode explicitly off, so any
  // "Demo" badge on screen means the console silently faked data.
  await context.addInitScript(() => {
    localStorage.setItem('bsdm_console_lang', 'en')
    localStorage.setItem('bsdm-admin-demo-mode', 'false')
  })

  const problems: string[] = []
  const page = await context.newPage()
  page.on('console', (message) => {
    if (message.type() === 'error' && !isBenign(message.text())) {
      problems.push(`console.error: ${message.text()}`)
    }
  })
  page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`))
  page.on('requestfailed', (request) => {
    const failure = request.failure()?.errorText ?? 'unknown'
    if (!isBenign(failure)) problems.push(`requestfailed: ${request.url()} (${failure})`)
  })
  page.on('response', (response) => {
    if (response.status() >= 400) problems.push(`HTTP ${response.status()}: ${response.url()}`)
  })
  return { page, problems }
}

describe('admin console local UI smoke', { concurrency: 1 }, () => {
  before(async () => {
    assert.ok(
      existsSync(join(distDir, 'index.html')),
      `no production build at ${distDir} — run "npm run build" first (or use "npm run test:ui")`,
    )
    mock = await startMockApi({ distDir })
    browser = await chromium.launch({
      executablePath: chromiumExecutable(),
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    })
  })

  after(async () => {
    await browser?.close()
    await mock?.close()
  })

  it('serves the built console under /admin/', async () => {
    const res = await fetch(`${mock.url}/admin/`)
    assert.equal(res.status, 200)
    const html = await res.text()
    assert.match(html, /<div id="root">/)
    assert.match(html, /\/admin\/assets\//)
  })

  it('redirects / to the console base path', async () => {
    const res = await fetch(`${mock.url}/`, { redirect: 'manual' })
    assert.equal(res.status, 302)
    assert.equal(res.headers.get('location'), '/admin/')
  })

  for (const route of ROUTES) {
    it(`renders ${route.name} (${route.path}) from live fixtures`, async () => {
      const { page, problems } = await openPage()
      try {
        await page.goto(`/admin${route.path}`, { waitUntil: 'domcontentloaded' })

        const heading = page.locator('h1').first()
        await heading.waitFor({ state: 'visible', timeout: 15_000 })
        assert.ok(
          (await heading.innerText()).trim().length > 0,
          `${route.path}: page heading is empty`,
        )

        await page
          .getByText(route.marker, { exact: false })
          .first()
          .waitFor({ state: 'visible', timeout: 15_000 })

        const errorState = page.getByText('Failed to load data', { exact: false })
        assert.equal(
          await errorState.count(),
          0,
          `${route.path}: an error state is visible — the console could not read the backend`,
        )

        const demoBadge = page.getByTitle('Demo mode is on', { exact: false })
        assert.equal(
          await demoBadge.count(),
          0,
          `${route.path}: demo data rendered while the backend was reachable`,
        )

        const frozenBanner = page.getByTestId('frozen-module-banner')
        assert.equal(
          await frozenBanner.count(),
          route.frozen ? 1 : 0,
          `${route.path}: unexpected frozen-module banner state`,
        )

        if (screenshotDir) {
          const name = route.path === '/' ? 'dashboard' : route.path.replace(/^\//, '').replace(/\//g, '-')
          await page.screenshot({ path: join(screenshotDir, `${name}.png`), fullPage: true })
        }

        assert.deepEqual(problems, [], `${route.path}: browser reported problems`)
      } finally {
        await page.context().close()
      }
    })
  }

  it('navigates between routes without a full page reload', async () => {
    const { page, problems } = await openPage()
    try {
      await page.goto('/admin/', { waitUntil: 'domcontentloaded' })
      await page.evaluate(() => {
        ;(window as unknown as { __spa: boolean }).__spa = true
      })

      await page.getByRole('link', { name: /logs/i }).first().click()
      await page.waitForURL('**/admin/logs')
      await page.getByText(MARKERS.logs).first().waitFor({ state: 'visible', timeout: 15_000 })

      const survived = await page.evaluate(
        () => (window as unknown as { __spa?: boolean }).__spa === true,
      )
      assert.ok(survived, 'client-side navigation triggered a full document reload')
      assert.deepEqual(problems, [], 'browser reported problems during navigation')
    } finally {
      await page.context().close()
    }
  })

  it('rejects paths outside the static root, including sibling prefix collisions', () => {
    const root = resolve('/tmp/bsdm-admin-dist')
    assert.equal(isPathWithinRoot(root, join(root, 'assets', 'app.js')), true)
    assert.equal(isPathWithinRoot(root, `${root}-escape/secret.txt`), false)
    assert.equal(isPathWithinRoot(root, resolve(root, '..', 'secret.txt')), false)
  })

  it('keeps fixture timestamps stable across runs', () => {
    assert.equal(NOW_MS, Date.UTC(2026, 4, 12, 9, 30, 0))
  })
})
