/**
 * The registry against Prisma.
 *
 * Prisma owns which columns exist, their type and their `@default()`. The
 * registry never restates any of that: `recon_settings/build.py` joins it at
 * build time. These tests read the DMMF DIRECTLY rather than the registry's
 * joined copy, so the comparison is between two independent sources and not a
 * tautology, and they are what makes adding a Prisma column fail the build
 * until it has a registry entry.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import {
  loadRegistry,
  fieldKeys,
  prismaColumns,
  prismaDefaults,
  prismaTypes,
} from './registry'

const registry = loadRegistry()
const fields = registry.fields
const columns = prismaColumns()
const defaults = prismaDefaults()
const types = prismaTypes()

// --- T1 / T2: coverage in both directions -------------------------------------------

describe('T1/T2 the registry covers Prisma exactly', () => {
  test('every Project column has a registry entry', () => {
    const missing = columns.filter(c => !(c in fields)).sort()
    expect(
      missing,
      'New Project column(s) have no registry entry. Add each to ' +
        'recon_settings/registry.yaml with a unit, a phase, a traffic class, an mcp ' +
        'disposition, a meaning, and either bounds or a validator. Then run ' +
        'python3 recon_settings/build.py.'
    ).toEqual([])
  })

  test('no registry entry invents a column Prisma does not have', () => {
    const known = new Set(columns)
    const ghosts = fieldKeys().filter(k => !known.has(k))
    expect(ghosts, 'stale registry entries for columns that no longer exist').toEqual([])
  })

  test('the counts agree', () => {
    expect(fieldKeys().length).toBe(columns.length)
  })
})

// --- T35: the registry's expectations match the column's type ---------------------------

describe('T35 registry expectations match the Prisma type', () => {
  test('the joined type matches what the DMMF reports', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      if (!live) continue
      const expected = live.type + (live.isList ? '[]' : '')
      if (fields[key].prisma_type !== expected) {
        problems.push(`${key}: registry says '${fields[key].prisma_type}', Prisma says '${expected}'`)
      }
    }
    expect(problems, 'the built artifact is stale; run python3 recon_settings/build.py').toEqual([])
  })

  test('a numeric column carries bounds and a non-numeric one does not', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      const f = fields[key]
      if (!live) continue
      const numeric = !live.isList && ['Int', 'Float', 'BigInt', 'Decimal'].includes(live.type)
      if (numeric && !f.bounds) problems.push(`${key}: ${live.type} with no bounds`)
      if (!numeric && f.bounds) problems.push(`${key}: ${live.type} with numeric bounds`)
    }
    expect(problems).toEqual([])
  })

  test('a list or Json column carries a validator or a closed value set', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      const f = fields[key]
      if (!live || f.mcp === 'never') continue
      if (!live.isList && live.type !== 'Json') continue
      if (!f.validator && !f.values) problems.push(`${key}: ${live.type} with nothing to validate it`)
    }
    expect(problems).toEqual([])
  })

  test('a closed value set only appears on a string or string list', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      if (!live || !fields[key].values) continue
      if (live.type !== 'String') problems.push(`${key}: values on a ${live.type}`)
    }
    expect(problems).toEqual([])
  })
})

// --- T34: a default that its own bound would refuse -------------------------------------

describe('T34 every Prisma default falls inside its registry bounds', () => {
  test('no default is outside its own bounds unless zero_means says why', () => {
    // This catches the ffufRate class automatically. Its default is 0 and a
    // naive `min: 1` would make the SHIPPED value unrepresentable, so a caller
    // could not restore it. Declaring zero_means is the deliberate answer.
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const f = fields[key]
      const d = defaults[key]
      if (!f.bounds || typeof d !== 'number') continue
      if (d >= f.bounds.min && d <= f.bounds.max) continue
      if (d === 0 && f.zero_means) continue
      problems.push(
        `${key}: default ${d} is outside bounds ${f.bounds.min}..${f.bounds.max}` +
          (d === 0 ? ' (declare zero_means if 0 is a sentinel)' : '')
      )
    }
    expect(problems).toEqual([])
  })

  test('every numeric whose default is 0 declares what 0 means', () => {
    // An agent reading `unit: rps` with no further hint concludes 0 is the
    // gentlest setting, then writes it onto a 3 rps engagement and runs
    // unlimited. That is a scope violation produced by documentation.
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const f = fields[key]
      if (defaults[key] !== 0) continue
      if (typeof defaults[key] !== 'number') continue
      if (!f.zero_means) problems.push(`${key}: default 0 with no zero_means`)
    }
    expect(problems).toEqual([])
  })

  test('the five rates whose zero is unlimited are marked as such', () => {
    // Named rather than derived: these are the ones where 0 is the FASTEST
    // value available, and getting one wrong is a scope violation rather than a
    // documentation nit.
    for (const key of [
      'ffufRate',
      'arjunRateLimit',
      'purednsRateLimit',
      'webCachePoisonMaxRpsPerHost',
    ]) {
      expect(fields[key]?.zero_means, `${key}`).toBe('unlimited')
      expect(fields[key]?.meaning.toLowerCase(), `${key} must say so in words`).toContain('unlimited')
    }
    expect(registry.runtime_only.ORIGIN_DISCOVERY_RATE?.zero_means).toBe('unlimited')
  })

  test('the joined default matches the DMMF', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const f = fields[key]
      if (!f.has_default) continue
      const live = defaults[key]
      if (live === undefined) continue // a function default: cuid(), now()
      const joined = f.default
      // A Float default is a double on both sides, so compare numerically: the
      // DMMF reports 1.4 as 1.4000000000000001 and a textual compare would
      // report a drift that does not exist.
      const same =
        typeof joined === 'number' && typeof live === 'number'
          ? Math.abs(joined - live) < 1e-9
          : JSON.stringify(joined) === JSON.stringify(live)
      if (!same) {
        problems.push(`${key}: registry has ${JSON.stringify(joined)}, Prisma has ${JSON.stringify(live)}`)
      }
    }
    expect(problems, 'the built artifact is stale; run python3 recon_settings/build.py').toEqual([])
  })
})

// --- the disposition sets, sized against the model ---------------------------------------

describe('the dispositions cover the model', () => {
  test('every column has exactly one disposition', () => {
    const counts = { settable: 0, create_only: 0, tighten_only: 0, never: 0 }
    for (const key of fieldKeys()) counts[fields[key].mcp] += 1
    expect(counts.settable + counts.create_only + counts.tighten_only + counts.never).toBe(
      columns.length
    )
    // The headline: most of the model is reachable, and what is not is a short,
    // named list rather than a class that grew.
    expect(counts.settable).toBeGreaterThan(600)
    expect(counts.never).toBeLessThan(25)
  })

  test('the RoE block is tighten_only, except what no settings write can carry', () => {
    // One exception, and it is a type fact rather than a policy one.
    // `roeDocumentData` is `Bytes?`: the agreement's own file, written by the
    // endpoints that receive it. A JSON-RPC settings write cannot carry bytes,
    // so describing it as writable meant a string passing every validator and
    // then throwing a raw Prisma type error out of the tool. The MCP surface
    // records the document's SHA-256 through attach_engagement_authorization.
    const UPLOAD_MANAGED = ['roeDocumentData']
    const roe = columns.filter(c => c.startsWith('roe')).sort()
    const notTighten = roe.filter(
      c => fields[c].mcp !== 'tighten_only' && !UPLOAD_MANAGED.includes(c)
    )
    expect(notTighten).toEqual([])
    expect(roe.length).toBeGreaterThan(30)
    for (const key of UPLOAD_MANAGED) {
      expect(fields[key].mcp, key).toBe('never')
      expect(fields[key].deny_reason, key).toBe('upload-managed')
    }
  })

  test('the scope columns are create_only, never settable', () => {
    for (const key of [
      'targetDomain', 'subdomainList', 'targetIps', 'ipMode',
      'domainBatchMode', 'domainBatchHosts', 'domainBatchGroups',
      'targetGuardrailEnabled', 'verifyDomainOwnership',
      'githubTargetOrg', 'gvmScanTargets', 'supplyChainRepoUrl',
    ]) {
      expect(fields[key]?.mcp, key).toBe('create_only')
    }
  })
})
