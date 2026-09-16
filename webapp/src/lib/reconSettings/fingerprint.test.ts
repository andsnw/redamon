/**
 * T18: the queued-job fingerprint is a registry query.
 *
 * `JobQueue.settingsHash` is taken at enqueue and re-checked at dispatch; a
 * change moves the job to needs_review instead of silently running the new
 * configuration. The mechanism was already there. Its INPUT list was six fields
 * for `full_recon` and no `roe*` field at all.
 *
 * That was survivable while 126 columns were mutable. It is not once most of
 * the model is, because queued work outlives the token that created it: enqueue
 * under a 3 rps ceiling, raise the ceiling, dispatch, and a scope-compliant
 * configuration has become a non-compliant run with nothing failing.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import { FINGERPRINT_FIELDS, settingsFingerprint } from '@/lib/jobQueue'
import { fieldsWhere, fingerprintFields, fingerprintKinds, loadRegistry } from './registry'

const registry = loadRegistry()

describe('T18 every kind has a derived field set', () => {
  test('the exported table is exactly the derived one', () => {
    for (const kind of fingerprintKinds()) {
      expect(FINGERPRINT_FIELDS[kind], kind).toEqual(fingerprintFields(kind))
    }
  })

  test('every kind the queue knows about is covered', () => {
    // A kind with no entry has its guard SILENTLY DISABLED: countQueuedJobs-
    // NeedingReview skips a kind that is not in the table, and
    // settingsFingerprint hashes an empty object for it.
    const KINDS = [
      'full_recon', 'partial_recon', 'gvm', 'github_hunt', 'trufflehog',
      'supply_chain', 'supply_chain_repo', 'ai_attack',
    ]
    for (const kind of KINDS) {
      expect(FINGERPRINT_FIELDS[kind], `${kind} has no fingerprint field set`).toBeDefined()
    }
  })

  test('no kind hashes an empty set', () => {
    // An empty list hashes a constant, which is a guard that always passes.
    const empty = fingerprintKinds().filter(k => FINGERPRINT_FIELDS[k].length === 0)
    expect(empty).toEqual([])
  })

  test('every named field is a real Prisma column', () => {
    const known = new Set(Object.keys(registry.fields))
    const ghosts: string[] = []
    for (const kind of fingerprintKinds()) {
      for (const f of FINGERPRINT_FIELDS[kind]) if (!known.has(f)) ghosts.push(`${kind}: ${f}`)
    }
    // A field that no longer exists is skipped by settingsFingerprint, so it
    // contributes nothing and silently narrows the guard.
    expect(ghosts).toEqual([])
  })
})

describe('T18 the engagement agreement is covered for every kind', () => {
  const ROE = fieldsWhere(f => f.mcp === 'tighten_only').map(f => f.key)

  test('the whole RoE block is in every kind', () => {
    expect(ROE.length).toBeGreaterThan(30)
    for (const kind of fingerprintKinds()) {
      const missing = ROE.filter(f => !FINGERPRINT_FIELDS[kind].includes(f))
      expect(missing, `${kind} does not fingerprint: ${missing.slice(0, 5).join(', ')}`).toEqual([])
    }
  })

  test('raising the rate ceiling after enqueue invalidates the hash', () => {
    // The exact path the old six-field list left open.
    const base = { targetDomain: 'example.com', roeEnabled: true, roeGlobalMaxRps: 3 }
    const before = settingsFingerprint('full_recon', base)
    const after = settingsFingerprint('full_recon', { ...base, roeGlobalMaxRps: 500 })
    expect(after).not.toBe(before)
  })

  test('adding an excluded host after enqueue invalidates the hash', () => {
    const base = { targetDomain: 'example.com', roeExcludedHosts: ['a.example.com'] }
    const before = settingsFingerprint('full_recon', base)
    const after = settingsFingerprint('full_recon', { ...base, roeExcludedHosts: [] })
    expect(after).not.toBe(before)
  })

  test('changing a per-tool rate after enqueue invalidates the hash', () => {
    const base = { targetDomain: 'example.com', nucleiRateLimit: 10 }
    expect(settingsFingerprint('full_recon', { ...base, nucleiRateLimit: 500 }))
      .not.toBe(settingsFingerprint('full_recon', base))
  })
})

describe('T18 each kind stays scoped to what it actually scans', () => {
  test('a pipeline kind ignores a standalone scanner s settings', () => {
    // A gvm port list changing must not make a queued full recon re-confirm.
    const base = { targetDomain: 'example.com' }
    expect(settingsFingerprint('full_recon', { ...base, gvmPortList: 'all' }))
      .toBe(settingsFingerprint('full_recon', base))
  })

  test('a standalone kind ignores a pipeline tool s settings', () => {
    const base = { gvmScanTargets: ['10.0.0.1'] }
    expect(settingsFingerprint('gvm', { ...base, ffufThreads: 200 }))
      .toBe(settingsFingerprint('gvm', base))
  })

  test('each standalone kind still covers its own targets', () => {
    expect(FINGERPRINT_FIELDS.gvm).toContain('gvmScanTargets')
    expect(FINGERPRINT_FIELDS.github_hunt).toContain('githubTargetOrg')
    expect(FINGERPRINT_FIELDS.supply_chain).toContain('supplyChainRepoUrl')
  })

  test('the pipeline kinds cover the six fields the hand-written list named', () => {
    // The replacement must be a superset, or the refactor lost a guard.
    for (const kind of ['full_recon', 'partial_recon']) {
      for (const f of [
        'targetDomain', 'ipMode', 'targetIps', 'scanModules',
        'targetGuardrailEnabled', 'stealthMode',
      ]) {
        expect(FINGERPRINT_FIELDS[kind], `${kind} lost ${f}`).toContain(f)
      }
    }
  })

  test('the standalone kinds cover the fields their hand-written lists named', () => {
    const SHIPPED: Record<string, string[]> = {
      gvm: ['gvmScanConfig', 'gvmScanTargets', 'gvmPortList'],
      github_hunt: [
        'githubTargetOrg', 'githubTargetRepos', 'githubScanMembers',
        'githubScanGists', 'githubScanCommits',
      ],
      trufflehog: [
        'trufflehogNoVerification', 'trufflehogResultTypes',
        'trufflehogIncludeDetectors', 'trufflehogExcludeDetectors',
      ],
      supply_chain: [
        'supplyChainInputMode', 'supplyChainRepoUrl', 'supplyChainRepoRef',
        'supplyChainRepoScope', 'supplyChainDeepAnalysisEnabled',
      ],
    }
    for (const [kind, fields] of Object.entries(SHIPPED)) {
      const missing = fields.filter(f => !FINGERPRINT_FIELDS[kind].includes(f))
      expect(missing, `${kind} lost: ${missing.join(', ')}`).toEqual([])
    }
  })

  test('supplyChainSbomFile is the one deliberate omission', () => {
    // It is upload-managed and therefore mcp: never, so no surface can change
    // it without also replacing the file on disk. The upload endpoint is the
    // writer, and it is not a path a queued job can be re-pointed through.
    expect(registry.fields.supplyChainSbomFile.mcp).toBe('never')
    expect(registry.fields.supplyChainSbomFile.deny_reason).toBe('upload-managed')
  })
})

describe('T18 the hash behaves', () => {
  test('it is stable across key order', () => {
    const a = settingsFingerprint('full_recon', { targetDomain: 'x', ipMode: false })
    const b = settingsFingerprint('full_recon', { ipMode: false, targetDomain: 'x' })
    expect(a).toBe(b)
  })

  test('it is stable across array order', () => {
    const a = settingsFingerprint('full_recon', { targetIps: ['1.1.1.1', '2.2.2.2'] })
    const b = settingsFingerprint('full_recon', { targetIps: ['2.2.2.2', '1.1.1.1'] })
    expect(a).toBe(b)
  })

  test('an unknown kind hashes nothing rather than throwing', () => {
    expect(() => settingsFingerprint('not_a_kind', { targetDomain: 'x' })).not.toThrow()
  })
})
