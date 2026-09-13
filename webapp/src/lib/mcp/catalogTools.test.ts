/**
 * describe_recon_settings and list_recon_presets.
 *
 * Both are projections of constants this build already ships, so the things
 * that can go wrong are not "the data is missing" but:
 *
 *  - the projection LEAKS, advertising fields the surface denies (which also
 *    hands an external agent a map of the denied surface);
 *  - the projection drifts from what `update_recon_settings` actually accepts,
 *    so a caller is told a bound that is not the enforced one;
 *  - a preset is described as applicable when the denied part of it is the part
 *    that made it safe.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { McpScopeError, __resetRateLimiter } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import {
  ALLOWED_SETTING_KEYS,
  RECON_SETTINGS_ALLOWLIST,
  SCAN_MODULE_VALUES,
  SEVERITY_VALUES,
  filterReconSettings,
} from '@/lib/reconSettingsAllowlist'
import {
  __resetCatalogCache,
  describeReconSettings,
  listReconPresets,
  presetApplicability,
  settingGroups,
} from './catalogTools'
import type { McpContext } from './tools'
import { RECON_PRESETS, getPresetById } from '@/lib/recon-presets'

const ctx = (scopes: string[] = ['recon:read']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const allSettings = () => settingGroups().flatMap(g => g.settings)

beforeEach(() => {
  __resetRateLimiter()
  __resetCatalogCache()
})

describe('describe_recon_settings covers exactly the settable surface', () => {
  test('every allowlisted field is described, once', () => {
    const keys = allSettings().map(s => s.key).sort()
    expect(keys).toEqual([...ALLOWED_SETTING_KEYS].sort())
  })

  test('no denied field is advertised', () => {
    // Not merely useless: it would tell an external agent exactly which
    // sensitive fields exist and are withheld.
    const described = new Set(allSettings().map(s => s.key))
    for (const denied of [
      'targetDomain', 'targetIps', 'stealthMode', 'amassActive', 'roeEnabled',
      'agentOpenaiModel', 'reconDockerImage', 'naabuRateLimit', 'customHeaders',
    ]) {
      expect(described.has(denied), `${denied} must not be advertised`).toBe(false)
    }
  })

  test('the described bound IS the enforced bound', () => {
    // The failure this prevents: a caller told a max it is then refused for.
    for (const s of allSettings()) {
      if (s.kind !== 'number') continue
      expect(filterReconSettings({ [s.key]: s.max }).ok, `${s.key} max`).toBe(true)
      expect(filterReconSettings({ [s.key]: s.min }).ok, `${s.key} min`).toBe(true)
      expect(filterReconSettings({ [s.key]: (s.max as number) + 1 }).ok, `${s.key} over max`).toBe(false)
    }
  })

  test('the described enum values ARE the accepted values', () => {
    for (const s of allSettings()) {
      if (!s.values) continue
      expect(filterReconSettings({ [s.key]: [...s.values] }).ok, s.key).toBe(true)
      expect(filterReconSettings({ [s.key]: ['definitely-not-a-value'] }).ok, s.key).toBe(false)
    }
  })

  test('a list field with a free-form vocabulary advertises none', () => {
    // Status-code lists take "200" or "200-299", which is not a closed set; a
    // bogus `values` array there would be a lie the validator contradicts.
    const codes = allSettings().find(s => /MatchCodes|FilterCodes|StatusCodes$/.test(s.key))
    expect(codes).toBeDefined()
    expect(codes!.values).toBeUndefined()
  })

  test('numbers carry bounds and booleans do not', () => {
    for (const s of allSettings()) {
      if (s.kind === 'number') {
        expect(typeof s.min, s.key).toBe('number')
        expect(typeof s.max, s.key).toBe('number')
      } else {
        expect(s.min, s.key).toBeUndefined()
      }
    }
  })

  test('the meaning is the catalog prose, not re-authored here', () => {
    const byKey = new Map(allSettings().map(s => [s.key, s]))
    expect(byKey.get('amassTimeout')?.meaning).toBe('Amass timeout in MINUTES (default 10)')
    expect(byKey.get('gauWorkers')?.meaning).toBe('Parallel domain query workers')
  })

  test('every settable field lands in a real catalog section', () => {
    // The drift control. A key with no catalog line falls into the "Other"
    // bucket, which is how a newly allowlisted field that nobody documented
    // shows up here instead of reaching a caller undescribed.
    const orphans = settingGroups()
      .filter(g => g.group === 'Other')
      .flatMap(g => g.settings.map(s => s.key))
    expect(orphans).toEqual([])
  })

  test('most fields carry prose, and the rest are self-describing', () => {
    // The catalog has deliberate type-only lines for fields whose name, group
    // and bounds say everything (`naabuThreads: number, 1..200`, under "Port
    // Scanning - Naabu"). That is fine; a majority without prose would not be.
    const all = allSettings()
    const withMeaning = all.filter(s => s.meaning).length
    expect(withMeaning / all.length).toBeGreaterThan(0.6)
  })
})

describe('describe_recon_settings teaches the two-level model', () => {
  test('it names the silent no-op, because that is the failure it exists to prevent', async () => {
    const notes = (await describeReconSettings(ctx())).notes.join(' ')
    expect(notes).toMatch(/scanModules/)
    expect(notes).toMatch(/naabuEnabled and masscanEnabled both false/)
    expect(notes).toMatch(/silent no-op/i)
  })

  test('it lists the phases and the two enum vocabularies', async () => {
    const r = await describeReconSettings(ctx())
    expect(r.phases.map(p => p.module)).toEqual([...SCAN_MODULE_VALUES])
    for (const p of r.phases) expect(p.what.length, p.module).toBeGreaterThan(10)
    expect(r.enums.scanModules).toEqual(SCAN_MODULE_VALUES)
    expect(r.enums.severity).toEqual(SEVERITY_VALUES)
  })

  test('it reports no current values, so it cannot disagree with get_recon_settings', async () => {
    const serialised = JSON.stringify(await describeReconSettings(ctx()))
    expect(serialised).not.toMatch(/"value"|"current"/)
  })

  test('a group filter narrows without inventing', async () => {
    const r = await describeReconSettings(ctx(), { group: 'nuclei' })
    expect(r.groups.length).toBeGreaterThan(0)
    for (const g of r.groups) expect(g.group.toLowerCase()).toContain('nuclei')
  })

  test('an unmatched group is an error naming the fix, not an empty list', async () => {
    await expect(describeReconSettings(ctx(), { group: 'no-such-group' }))
      .rejects.toThrow(/no settings group matches/i)
  })

  test('it needs recon:read', async () => {
    await expect(describeReconSettings(ctx([]))).rejects.toBeInstanceOf(McpScopeError)
  })

  test('it reads no tenant data at all', async () => {
    // Same shape as graph_schema: derived from code, so it still answers when
    // the databases are down. prisma is mocked to {} here, so touching it throws.
    await expect(describeReconSettings(ctx())).resolves.toBeTruthy()
  })
})

describe('list_recon_presets', () => {
  test('lists every curated preset with its choosing metadata', async () => {
    const r = await listReconPresets(ctx()) as { presets: { id: string; shortDescription: string; targetProfile: string; environment: string }[] }
    expect(r.presets).toHaveLength(RECON_PRESETS.length)
    for (const p of r.presets) {
      expect(p.id).toBeTruthy()
      expect(p.shortDescription.length).toBeGreaterThan(10)
      expect(['domain', 'ip', 'both']).toContain(p.targetProfile)
      expect(['external', 'internal', 'either']).toContain(p.environment)
    }
  })

  test('the list withholds fullDescription, which a named preset returns', async () => {
    const list = await listReconPresets(ctx())
    expect(JSON.stringify(list)).not.toContain('Pipeline Goal')

    const one = await listReconPresets(ctx(), { presetId: 'stealth-recon' }) as { preset: { fullDescription: string } }
    expect(one.preset.fullDescription.length).toBeGreaterThan(200)
  })

  test('an unknown preset id is an error that says how to recover', async () => {
    await expect(listReconPresets(ctx(), { presetId: 'nope' })).rejects.toBeInstanceOf(McpToolError)
    await expect(listReconPresets(ctx(), { presetId: 'nope' })).rejects.toThrow(/list them/i)
  })

  test('it needs recon:read', async () => {
    await expect(listReconPresets(ctx([]))).rejects.toBeInstanceOf(McpScopeError)
  })
})

describe('applicability is the field that stops a half-applied preset', () => {
  test('stealth-recon is reported as stealth-critical', () => {
    // The exact trap: applying "Stealth Recon" over MCP would apply everything
    // EXCEPT the stealth - the rate limits, passive mode and brute-force
    // toggles are all denied by class - leaving the caller louder than the
    // preset it asked for while believing it was quieter.
    const a = presetApplicability(getPresetById('stealth-recon')!)
    expect(a.stealthCritical).toBe(true)
    expect(a.deniedCount).toBeGreaterThan(0)
    expect(a.stealthCriticalFields.length).toBeGreaterThan(0)
  })

  test('applied + denied accounts for every key the preset sets', () => {
    for (const p of RECON_PRESETS) {
      const a = presetApplicability(p)
      expect(a.appliedCount + a.deniedCount, p.id).toBe(Object.keys(p.parameters ?? {}).length)
    }
  })

  test('a counted-as-applied key really is writable', () => {
    for (const p of RECON_PRESETS) {
      const writable = Object.keys(p.parameters ?? {})
        .filter(k => Object.prototype.hasOwnProperty.call(RECON_SETTINGS_ALLOWLIST, k))
      expect(presetApplicability(p).appliedCount, p.id).toBe(writable.length)
    }
  })

  test('the tool says plainly that a preset cannot be applied from here', async () => {
    const notes = (await listReconPresets(ctx()) as { notes: string[] }).notes.join(' ')
    expect(notes).toMatch(/cannot be applied from here/i)
    expect(notes).toMatch(/LOUDER/)
  })

  test('no preset parameter VALUES are echoed, only counts', async () => {
    // The payload describes coverage, not configuration: a preset's parameter
    // values are not this tool's business and would bloat every call.
    const r = await listReconPresets(ctx())
    expect(JSON.stringify(r)).not.toContain('"parameters"')
  })
})
