/**
 * T44 and T45: the composed answer, not the layers.
 *
 * Every layer here can be individually truthful while the COMPOSED answer
 * misleads the caller, and that is the class of bug a green unit gate has
 * hidden on this surface before. `describe_recon_settings` can correctly report
 * a registry that `filterReconSettings` correctly enforces, and the pair can
 * still disagree about one field, which an agent discovers by being refused for
 * something it was just told it could do.
 *
 * So both tests exercise the REAL functions and iterate the registry rather
 * than naming examples: the registry is the list of things that could regress,
 * and a field added tomorrow is covered the day it is added.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { settingGroups } from '@/lib/mcp/catalogTools'
import { checkTighten, filterReconSettings, permittedKeys } from './filter'
import { fieldsWhere, loadRegistry, type RegistryField } from './registry'

const registry = loadRegistry()
const advertised = settingGroups().flatMap(g => g.settings)

/** A value inside this field's own bounds or vocabulary. */
function legalValue(key: string, spec: RegistryField): unknown {
  switch (spec.type) {
    case 'boolean':
      return spec.default === true ? false : true
    case 'int':
      return Math.min(spec.bounds!.max, Math.max(spec.bounds!.min, 1))
    case 'float':
      return spec.bounds!.min
    case 'string-list':
      if (spec.values) return [spec.values[0]]
      if (spec.validator === 'status_codes') return ['200']
      if (spec.validator === 'http_header') return ['X-Scan-Id: abc']
      if (spec.validator === 'project_file') return ['/usr/share/seclists/a.txt']
      if (spec.validator === 'project_file_name') return ['mine.yaml']
      return ['a']
    case 'number-list':
      return [200]
    case 'json':
      return {}
    case 'datetime':
      return new Date(0).toISOString()
    default:
      if (spec.values) return spec.values[0]
      if (spec.validator === 'project_file') return '/usr/share/seclists/a.txt'
      if (spec.validator === 'project_file_name') return 'mine.yaml'
      if (spec.validator === 'docker_image') return 'vendor/tool:latest'
      if (spec.validator === 'url') return 'https://example.com'
      if (spec.validator === 'http_header') return 'X-Scan-Id: abc'
      if (spec.validator === 'status_codes') return '200'
      if (spec.validator === 'port_spec') return '80,443'
      if (spec.validator === 'hostname') return 'example.com'
      if (spec.validator === 'identifier') return 'abc'
      return 'x'
  }
}

// --- T44: describe and update agree -------------------------------------------------

describe('T44 what describe advertises, update accepts', () => {
  test('every advertised field accepts a value drawn from its own bounds', () => {
    // An agent that trusts describe_recon_settings must never be surprised by
    // update_recon_settings. One bad key refuses the WHOLE call, so a batch of
    // writes built from a stale reference applies nothing at all.
    const problems: string[] = []
    for (const doc of advertised) {
      const spec = registry.fields[doc.key]
      const value = legalValue(doc.key, spec)
      const r = filterReconSettings({ [doc.key]: value })
      if (!r.ok) problems.push(`${doc.key} = ${JSON.stringify(value)}: ${r.error}`)
    }
    expect(problems).toEqual([])
  })

  test('the advertised bound IS the enforced bound, at both ends', () => {
    const problems: string[] = []
    for (const doc of advertised) {
      if (doc.min === undefined || doc.max === undefined) continue
      if (!filterReconSettings({ [doc.key]: doc.min }).ok) problems.push(`${doc.key}: min refused`)
      if (!filterReconSettings({ [doc.key]: doc.max }).ok) problems.push(`${doc.key}: max refused`)
      if (filterReconSettings({ [doc.key]: doc.max + 1 }).ok) {
        problems.push(`${doc.key}: max + 1 accepted`)
      }
    }
    expect(problems).toEqual([])
  })

  test('every field describe does NOT advertise is refused, naming it', () => {
    const shown = new Set(advertised.map(s => s.key))
    const problems: string[] = []
    for (const key of Object.keys(registry.fields)) {
      if (shown.has(key)) continue
      const spec = registry.fields[key]
      const r = filterReconSettings({ [key]: legalValue(key, spec) })
      if (r.ok) problems.push(`${key}: unadvertised but accepted`)
      else if (!r.error.includes(key)) problems.push(`${key}: refused without naming the field`)
    }
    expect(problems).toEqual([])
  })

  test('the advertised set is exactly the permitted set', () => {
    expect(advertised.map(s => s.key).sort()).toEqual([...permittedKeys('update')].sort())
  })

  test('a refusal always names the field', () => {
    // A batch of writes refuses as a whole, so the message has to say which key
    // caused it or the caller cannot fix the batch.
    for (const key of ['targetDomain', 'roeEnabled', 'cypherfixGithubToken', 'notAColumn']) {
      const r = filterReconSettings({ naabuThreads: 25, [key]: 'x' })
      expect(r.ok).toBe(false)
      if (!r.ok) expect(r.error, key).toContain(key)
    }
  })
})

// --- T45: the disposition round-trip -------------------------------------------------

describe('T45 each disposition behaves the way it is documented', () => {
  test('every create_only field is refused on update and accepted on create', () => {
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'create_only')) {
      const value = legalValue(f.key, f)
      const update = filterReconSettings({ [f.key]: value }, { mode: 'update' })
      if (update.ok) problems.push(`${f.key}: settable on an existing project`)
      else if (!/create_project/.test(update.error)) {
        problems.push(`${f.key}: refused without naming the right tool`)
      }
      const create = filterReconSettings({ [f.key]: value }, { mode: 'create' })
      if (!create.ok) problems.push(`${f.key}: refused at CREATE too (${create.error})`)
    }
    expect(problems).toEqual([])
  })

  test('every never field is refused in both modes, by name', () => {
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'never')) {
      for (const mode of ['update', 'create'] as const) {
        const r = filterReconSettings({ [f.key]: legalValue(f.key, f) }, { mode })
        if (r.ok) problems.push(`${f.key}: accepted in ${mode} mode`)
        else if (!r.error.includes(f.key)) problems.push(`${f.key}: ${mode} refusal does not name it`)
      }
    }
    expect(problems).toEqual([])
  })

  test('every tighten_only field is refused without the engagement permission', () => {
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'tighten_only')) {
      const r = filterReconSettings({ [f.key]: legalValue(f.key, f) })
      if (r.ok) problems.push(`${f.key}: writable through update_recon_settings`)
      else if (!/tighten_engagement_roe/.test(r.error)) {
        problems.push(`${f.key}: refused without naming the right tool`)
      }
    }
    expect(problems).toEqual([])
  })

  test('every tighten_only field accepts the safe direction and refuses the other', () => {
    // Both directions per field, generated from the field's own shape, so a new
    // RoE column is covered the day it is added.
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'tighten_only')) {
      let current: unknown
      let safe: unknown
      let unsafe: unknown
      switch (f.tighten) {
        case 'decrease':
          current = 10; safe = 5; unsafe = 50; break
        case 'increase':
          current = 10; safe = 50; unsafe = 5; break
        case 'superset':
          current = ['a']; safe = ['a', 'b']; unsafe = []; break
        case 'true_to_false':
          current = true; safe = false; unsafe = undefined; break
        case 'false_to_true':
          current = false; safe = true; unsafe = undefined; break
        default:
          continue // 'narrow': no machine-checkable direction
      }
      if (checkTighten(f.key, f, current, safe)) {
        problems.push(`${f.key}: the SAFE direction was refused`)
      }
      if (unsafe !== undefined && !checkTighten(f.key, f, current, unsafe)) {
        problems.push(`${f.key}: the LOOSENING direction was accepted`)
      }
    }
    expect(problems).toEqual([])
  })

  test('the rate ceiling may never be removed once it exists', () => {
    // 0 means NO ceiling, so `3 -> 0` reads as a decrease and is the one move
    // that would leave the engagement unlimited.
    const spec = registry.fields.roeGlobalMaxRps
    expect(checkTighten('roeGlobalMaxRps', spec, 3, 0)).toMatch(/NO ceiling/)
    expect(checkTighten('roeGlobalMaxRps', spec, 3, 1)).toBeNull()
    expect(checkTighten('roeGlobalMaxRps', spec, 3, 10)).toMatch(/only decrease/)
    // Setting a ceiling where there was none IS a tightening, whatever the
    // arithmetic says.
    expect(checkTighten('roeGlobalMaxRps', spec, 0, 3)).toBeNull()
  })

  test('roeEnabled may be switched on and never off', () => {
    const spec = registry.fields.roeEnabled
    expect(checkTighten('roeEnabled', spec, false, true)).toBeNull()
    expect(checkTighten('roeEnabled', spec, true, false)).toMatch(/false to true/)
  })

  test('an exclusion list may grow and never shrink', () => {
    const spec = registry.fields.roeExcludedHosts
    expect(checkTighten('roeExcludedHosts', spec, ['a'], ['a', 'b'])).toBeNull()
    expect(checkTighten('roeExcludedHosts', spec, ['a', 'b'], ['a'])).toMatch(/only grow/)
  })

  test('a tighten write with the permission but no current values is refused', () => {
    // Permitting a move whose direction could not be checked is the one failure
    // this layer cannot afford.
    const r = filterReconSettings({ roeGlobalMaxRps: 1 }, { allowTighten: true })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/current values/)
  })

  test('a tighten write with the permission and current values goes through', () => {
    const r = filterReconSettings(
      { roeGlobalMaxRps: 1 },
      { allowTighten: true, current: { roeGlobalMaxRps: 3 } }
    )
    expect(r.ok).toBe(true)
  })
})

// --- the headline numbers, asserted ----------------------------------------------------

describe('the surface is the size it claims to be', () => {
  test('most of the model is settable and the closed set is small', () => {
    const total = Object.keys(registry.fields).length
    expect(permittedKeys('update').length / total).toBeGreaterThan(0.85)
    expect(fieldsWhere(f => f.mcp === 'never').length).toBeLessThan(25)
  })

  test('every rate limit is reachable, not three of fifteen', () => {
    const rates = fieldsWhere(f => f.unit === 'rps')
    expect(rates.length).toBeGreaterThanOrEqual(15)
    expect(rates.filter(f => f.mcp !== 'settable')).toEqual([])
  })

  test('every settable field carries a bound or a validator', () => {
    const naked = fieldsWhere(f => f.mcp === 'settable').filter(
      f => f.type !== 'boolean' && !f.bounds && !f.validator && !f.values
    )
    expect(naked.map(f => f.key)).toEqual([])
  })
})
