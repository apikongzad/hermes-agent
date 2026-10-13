/**
 * KaTeX prototype-pollution trust bypass (GHSA-238p-pmpm-9mq7, range
 * >=0.11.0 <0.18.2) + braces stack-exhaustion DoS (GHSA-vfj7-8cjw-p6xm,
 * <=3.0.3, no patched release — latest 3.0.3 is still vulnerable).
 *
 * Causal counts persisted from fresh audit at 7cb1ad2c (2026-10-12):
 * - Root graph (`npm audit --json`, hoisted workspaces): 7 low total, all
 *   caused by ONE advisory — katex 0.16.47 via mermaid 11.16.1 /
 *   rehype-katex 7.0.1 / remark-math 6.0.0 / @streamdown/math 1.0.2 /
 *   @assistant-ui/react-streamdown 0.3.5. Effects: katex, rehype-katex,
 *   remark-math, micromark-extension-math, @streamdown/math,
 *   @assistant-ui/react-streamdown, mermaid. `npm audit --workspaces=false`
 *   reports 0 because the vulnerable nodes are hoisted through workspaces.
 * - Website (`npm audit --prefix website`): 33 total = 30 high + 3 low.
 *   The 3 low are katex 0.16.47 + mermaid + @mermaid-js/layout-elk
 *   (same katex cause). The 30 high all propagate from ONE advisory —
 *   braces <=3.0.3 via micromatch/fast-glob/globby/chokidar/
 *   http-proxy-middleware/copy-webpack-plugin/webpack-dev-server up through
 *   @docusaurus/utils into every @docusaurus/* package. fixAvailable is
 *   False for the braces chain; latest registry braces is 3.0.3 (nofix).
 *
 * Fix (this commit): coordinate katex to patched 0.18.2 — the FIRST patched
 * release per the advisory range — in BOTH graphs plus the direct desktop
 * pin, because a patched release EXISTS so "nofix" must NOT be claimed:
 * - root package.json overrides: "katex": "0.18.2" (covers mermaid,
 *   rehype-katex, streamdown hoisted graph; 7->0 low)
 * - website/package.json overrides: "katex": "0.18.2" (covers
 *   @docusaurus/theme-mermaid -> mermaid -> katex; 33->30, 3 low gone)
 * - apps/desktop/package.json dependencies: "katex": "0.16.47" -> "0.18.2"
 *   (direct pin used by katex-memo.ts / markdown-text.tsx / preview-file)
 * Registry verified 2026-10-12: katex versions include 0.18.2
 * (2026-08-08, >14d so no min-release-age exclude needed) and 0.19.0
 * (2026-10-01, latest). 0.18.2 chosen as minimal compatible patch:
 * same commander ^8.3.0 dep as 0.16.47 (0.19.0 jumps to commander ^15.0.0),
 * and every mermaid release including latest 12.1.0 still declares
 * katex ^0.16.47 so the override is required regardless of mermaid line.
 *
 * Braces residual — EXPLICIT BLOCKER, not vendored, not removed:
 * Do NOT vendor an ad-hoc security patch for braces and do NOT remove
 * essential Docusaurus to silence the audit. micropatch-vendoring a
 * stack-exhaustion guard into braces/micromatch diverges from upstream and
 * blindly dropping @docusaurus/* breaks the docs site. Exposure mitigation
 * only: docs builds run on trusted source (our own markdown in website/docs,
 * no untrusted contributor glob input), no public devserver
 * (webpack-dev-server + chokidar + http-proxy-middleware are dev-only,
 * never exposed; `docusaurus serve` is local preview only), no untrusted
 * glob patterns reach micromatch/fast-glob/globby from the network.
 * Remaining 30 high are build-tooling scope, separate from the Python
 * agent/Gateway/TUI/web runtime — runtime-scope activation is a separate
 * concern from website tooling. No live edit/restart performed.
 */

import { createRequire } from 'node:module'
import { describe, expect, test } from 'vitest'

const require = createRequire(import.meta.url)

describe('katex override (GHSA-238p-pmpm-9mq7)', () => {
  test('installed katex is the patched 0.18.2, not vulnerable <0.18.2', () => {
    const { version } = require('katex/package.json')

    expect(version).toBe('0.18.2')
  })

  test('desktop direct pin is coordinated to 0.18.2', async () => {
    const { readFileSync } = await import('node:fs')
    const { dirname, resolve } = await import('node:path')
    const { fileURLToPath } = await import('node:url')

    const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')
    const desktop = JSON.parse(readFileSync(resolve(repo, 'apps/desktop/package.json'), 'utf8'))
    const root = JSON.parse(readFileSync(resolve(repo, 'package.json'), 'utf8'))
    const website = JSON.parse(readFileSync(resolve(repo, 'website/package.json'), 'utf8'))

    expect(desktop.dependencies.katex).toBe('0.18.2')
    expect(root.overrides.katex).toBe('0.18.2')
    expect(website.overrides.katex).toBe('0.18.2')
  })

  test('katex renderToString still typesets math (no rendering regress)', () => {
    const katex = require('katex')

    const inline = katex.renderToString('x^2 + y^2')
    expect(inline).toContain('class="katex"')
    expect(inline).toContain('katex-mathml')

    const display = katex.renderToString('E = mc^2', { displayMode: true })
    expect(display).toContain('class="katex"')

    const frac = katex.renderToString('\\frac{a}{b}')
    expect(frac).toContain('class="katex"')

    // Invalid input with throwOnError:false renders an error span, not raw
    // source — proves the error path still works on the patched release.
    const err = katex.renderToString('\\invalid@@@', { throwOnError: false })
    expect(err).toContain('katex')
  })

  test('mermaid stays at audited 11.16.1 and loads alongside patched katex', async () => {
    const { version } = require('mermaid/package.json')

    expect(version).toBe('11.16.1')

    const mermaid = await import('mermaid')
    expect(typeof mermaid.default.initialize).toBe('function')
  })
})

describe('braces residual (GHSA-vfj7-8cjw-p6xm, nofix blocker)', () => {
  test('installed braces is latest 3.0.3 — still advisory range, documented not patched', async () => {
    const { dirname, resolve } = await import('node:path')
    const { fileURLToPath } = await import('node:url')

    const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')
    // braces is website-scope (Docusaurus build tooling), not a root
    // workspace dep — resolve via the website graph, not tests-js.
    const websiteRequire = createRequire(resolve(repo, 'website/package.json'))
    const { version } = websiteRequire('braces/package.json')

    // Latest registry braces is 3.0.3 which is <=3.0.3: no patched release
    // exists. This test pins the nofix fact so a future patched release
    // (version bump) fails loudly instead of silently claiming nofix.
    expect(version).toBe('3.0.3')
  })

  test('micromatch still expands trusted doc globs (no blind Docusaurus removal)', async () => {
    const { dirname, resolve } = await import('node:path')
    const { fileURLToPath } = await import('node:url')

    const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')
    const websiteRequire = createRequire(resolve(repo, 'website/package.json'))
    const micromatch = websiteRequire('micromatch')

    expect(micromatch(['docs/a.md', 'docs/b.ts'], 'docs/*.md')).toEqual(['docs/a.md'])
  })
})
