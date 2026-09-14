/**
 * The scope copy and its presentation grouping.
 *
 * The control here is fail-closed: every scope must appear in exactly one group.
 * A scope added next month is ungrouped, this goes red, and nobody can ship a
 * checkbox that renders nowhere.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import { MCP_SCOPE_COPY, SCOPE_GROUPS } from './scopeCopy'

describe('the copy', () => {
  test('every scope has a label and a blurb', () => {
    for (const s of MCP_SCOPES) {
      expect(MCP_SCOPE_COPY[s], `no copy for ${s}`).toBeDefined()
      expect(MCP_SCOPE_COPY[s].label.length, `${s} has no label`).toBeGreaterThan(0)
      expect(MCP_SCOPE_COPY[s].blurb.length, `${s} has no blurb`).toBeGreaterThan(20)
    }
  })

  test('a blurb stays table-safe, because it becomes one markdown cell', () => {
    // The generated API reference prints each blurb into a single table cell.
    // A newline or a raw pipe would break the table.
    for (const s of MCP_SCOPES) {
      expect(MCP_SCOPE_COPY[s].blurb, `${s} blurb has a newline`).not.toMatch(/\r?\n/)
      expect(MCP_SCOPE_COPY[s].blurb, `${s} blurb has a raw pipe`).not.toContain('|')
    }
  })

  test('detail is UI-only, so it may be as long as it needs to be', () => {
    // Nothing asserts its length; this asserts it EXISTS where the UI needs it.
    expect(MCP_SCOPE_COPY['kali:exec'].detail).toBeDefined()
    expect(MCP_SCOPE_COPY['kali:exec'].detail!.length).toBeGreaterThan(300)
  })

  test('the exec copy does not enumerate the allowlist, which grows', () => {
    // A list copied into this string goes stale silently, and a copy that
    // overstates the allowlist is wrong in the dangerous direction. The wiki
    // links carry the current list instead.
    const detail = MCP_SCOPE_COPY['kali:exec'].detail!
    expect(detail).toContain('fixed allowlist of read-only tools')
    expect(detail).toContain('not a shell')
    expect(detail).toContain('not sufficient on its own')
    expect(MCP_SCOPE_COPY['kali:exec'].learnMore).toHaveLength(2)
  })

  test('every learnMore link points at the wiki over https', () => {
    for (const s of MCP_SCOPES) {
      for (const link of MCP_SCOPE_COPY[s].learnMore ?? []) {
        expect(link.text.length, `${s} has an unlabelled link`).toBeGreaterThan(0)
        expect(link.href, `${s} link is not an https wiki URL`).toMatch(/^https:\/\/github\.com\/.+\/wiki\//)
      }
    }
  })
})

describe('the grouping', () => {
  test('every scope appears in EXACTLY one group', () => {
    const seen = new Map<string, number>()
    for (const g of SCOPE_GROUPS) {
      for (const s of g.scopes) seen.set(s, (seen.get(s) ?? 0) + 1)
    }
    for (const s of MCP_SCOPES) {
      expect(
        seen.get(s) ?? 0,
        `${s} appears in ${seen.get(s) ?? 0} groups. Add it to exactly one SCOPE_GROUPS entry.`
      ).toBe(1)
    }
  })

  test('no group names a scope that does not exist', () => {
    const known = new Set<string>(MCP_SCOPES)
    for (const g of SCOPE_GROUPS) {
      for (const s of g.scopes) {
        expect(known.has(s), `group ${g.id} names unknown scope ${s}`).toBe(true)
      }
    }
  })

  test('every group has a label and a hint', () => {
    for (const g of SCOPE_GROUPS) {
      expect(g.label.length, `${g.id} has no label`).toBeGreaterThan(0)
      expect(g.hint.length, `${g.id} has no hint`).toBeGreaterThan(0)
      expect(g.scopes.length, `${g.id} is empty`).toBeGreaterThan(0)
    }
  })

  test('the read group changes nothing, so it carries no danger scope', () => {
    const read = SCOPE_GROUPS.find(g => g.id === 'read')!
    expect(read.tone).toBe('neutral')
    for (const s of read.scopes) {
      expect(MCP_SCOPE_COPY[s].danger, `${s} is a danger scope in the neutral group`).not.toBe(true)
    }
  })

  test('kali:exec is set apart in its own tier, not treated as a ninth checkbox', () => {
    const exec = SCOPE_GROUPS.find(g => g.tone === 'exec')!
    expect(exec.scopes).toEqual(['kali:exec'])
    // And it is last, so it reads as a different kind of thing.
    expect(SCOPE_GROUPS[SCOPE_GROUPS.length - 1].id).toBe(exec.id)
  })

  test('MCP_SCOPES itself is NOT reordered to match the groups', () => {
    // That array is the enforcement list and drives the generated reference's
    // permission table; the grouping is presentation beside it.
    const flattened = SCOPE_GROUPS.flatMap(g => g.scopes)
    expect(flattened).not.toEqual([...MCP_SCOPES])
    expect([...flattened].sort()).toEqual([...MCP_SCOPES].sort() as McpScope[])
  })
})
