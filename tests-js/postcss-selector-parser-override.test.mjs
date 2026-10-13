/**
 * GHSA-rj75-hqrm-r3gf (postcss-selector-parser <7.1.6, quadratic flat-selector
 * parse): npm audit suggests downgrading @tailwindcss/typography to 0.5.4 to
 * drop the parser dependency. That downgrade is blind — 0.5.4 predates Tailwind
 * v4 support used by apps/desktop (`@plugin '@tailwindcss/typography'`) and
 * would regress styling. Instead the root lock overrides the parser to patched
 * 7.1.6 while keeping typography at 0.5.20 (advisory notes the fix is
 * byte-identical on a differential corpus, no behaviour change).
 *
 * Reachability: build-time only on trusted sources (Tailwind processes our own
 * CSS at build); untrusted-selector request paths are not present. Ordinary
 * build-time use is not affected per the advisory.
 */

import { createRequire } from 'node:module'
import { describe, expect, test } from 'vitest'

const require = createRequire(import.meta.url)

describe('postcss-selector-parser override (GHSA-rj75-hqrm-r3gf)', () => {
  test('installed parser is the patched 7.1.6, not the vulnerable 6.x', () => {
    const { version } = require('postcss-selector-parser/package.json')

    expect(version).toBe('7.1.6')
  })

  test('typography stays at 0.5.20 (no blind downgrade to 0.5.4)', () => {
    const { version } = require('@tailwindcss/typography/package.json')

    expect(version).toBe('0.5.20')
  })

  test('flat selector parses linearly and byte-identically', () => {
    const parser = require('postcss-selector-parser')
    const flat = '.a'.repeat(500)
    const start = Date.now()
    const out = parser().processSync(flat)
    const ms = Date.now() - start

    expect(out).toBe(flat)
    // Vulnerable 6.x took ~34s for 400KB; patched 7.1.6 is linear. 500-class
    // probe must finish in well under a second even on slow CI.
    expect(ms).toBeLessThan(2000)
  })

  test('typography plugin loads and its selector AST walks', () => {
    const parser = require('postcss-selector-parser')
    const typography = require('@tailwindcss/typography')

    expect(typeof typography).toBe('function')

    let classes = 0
    parser().astSync('.prose h1, .prose > p').walkClasses(() => {
      classes += 1
    })

    expect(classes).toBeGreaterThan(0)
  })
})
