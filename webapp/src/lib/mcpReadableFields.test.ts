/**
 * The read-side classification for `Project`.
 *
 * The control this file IS: a new Project column is unreadable over MCP until
 * someone classifies it, in exactly the way a new column is already unwritable
 * until someone classifies it. The failure it prevents is not a bug in any tool
 * written today - it is the one that arrives when somebody adds a column
 * holding client information and a read tool with a generous `select` starts
 * returning it.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { Prisma } from '@prisma/client'

import {
  MCP_READABLE_PROJECT_FIELDS,
  READ_ONLY_PROJECT_FIELDS,
  assertReadableSelect,
  isReadableProjectField,
} from './mcpReadableFields'
import { RECON_SETTINGS_ALLOWLIST } from './reconSettingsAllowlist.generated'
import { reconSettingsSelect } from './reconSettingsAllowlist'

const columns = Object.keys(Prisma.ProjectScalarFieldEnum)

describe('the readable set is a real, current subset of the model', () => {
  test('it invents no column Prisma does not have', () => {
    const known = new Set(columns)
    const ghosts = [...MCP_READABLE_PROJECT_FIELDS].filter(k => !known.has(k))
    expect(ghosts, 'stale entries for columns that no longer exist').toEqual([])
  })

  test('every read-only entry documents WHY it is readable', () => {
    for (const [field, why] of Object.entries(READ_ONLY_PROJECT_FIELDS)) {
      expect(why.length, `${field} has no reason`).toBeGreaterThan(10)
    }
  })

  test('a read-only entry is genuinely not writable, or it belongs in one table', () => {
    // If a field is in both, the split has drifted and one of the two lists is
    // lying about what this surface does.
    const both = Object.keys(READ_ONLY_PROJECT_FIELDS)
      .filter(k => k in RECON_SETTINGS_ALLOWLIST)
    expect(both).toEqual([])
  })

  test('the vast majority of the model stays unreadable', () => {
    // A sanity bound on the whole idea: if someone widens this to most of the
    // table, the set has stopped being a boundary.
    const readable = columns.filter(isReadableProjectField).length
    expect(readable).toBeLessThan(columns.length / 2)
  })
})

describe('the fields that must never be returned', () => {
  // Each of these is denied for WRITE with a documented reason. Reading them is
  // a separate decision, and the answer is also no.
  test.each([
    ['roeClientContactName', 'third-party personal data'],
    ['roeClientContactEmail', 'third-party personal data'],
    ['roeClientContactPhone', 'third-party personal data'],
    ['roeEmergencyContact', 'third-party personal data'],
    ['roeRawText', 'the engagement agreement verbatim'],
    ['roeDocumentData', 'a binary blob'],
  ])('%s is not readable (%s)', field => {
    // Skip silently if the column was renamed: the ghost test above owns that.
    if (!columns.includes(field)) return
    expect(isReadableProjectField(field)).toBe(false)
  })

  test('no column that looks like a credential is readable', () => {
    const leaky = columns.filter(
      c => /Token|ApiKey|Secret|Password|Credential/i.test(c) && isReadableProjectField(c)
    )
    expect(leaky, 'a credential-shaped column is MCP-readable').toEqual([])
  })

  test('no RoE column is readable at all', () => {
    // The RoE is the encoded engagement agreement. An agent is judged against
    // it; exposing it is a separate, unshipped decision.
    const roe = columns.filter(c => c.startsWith('roe') && isReadableProjectField(c))
    expect(roe).toEqual([])
  })

  test('no column that steers another scan is readable', () => {
    const leaky = columns.filter(
      c => /DockerImage|Wordlist|customHeaders/i.test(c) && isReadableProjectField(c)
    )
    expect(leaky).toEqual([])
  })
})

describe('the selects the read tools actually use stay inside the boundary', () => {
  test('the recon settings select is entirely readable', () => {
    expect(() => assertReadableSelect(reconSettingsSelect(), 'get_recon_settings')).not.toThrow()
  })

  test('the list_projects select is entirely readable', () => {
    // Mirrors the select in tools.ts. If that select grows a field, this fails
    // until the field is classified.
    const select = {
      id: true, name: true, targetDomain: true, targetIps: true,
      ipMode: true, domainBatchMode: true, updatedAt: true,
    }
    expect(() => assertReadableSelect(select, 'list_projects')).not.toThrow()
  })

  test('a select reaching past the boundary is refused, naming the field', () => {
    expect(() => assertReadableSelect({ id: true, roeRawText: true }, 'some_tool'))
      .toThrow(/roeRawText/)
    expect(() => assertReadableSelect({ roeClientContactPhone: true }, 'some_tool'))
      .toThrow(/Classify them in mcpReadableFields.ts/)
  })
})
