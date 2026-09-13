/**
 * The recon-settings allowlist.
 *
 * This is the control that turns "MCP cannot change the target" from a
 * sentence in a design doc into something the code enforces. The tests are
 * written so that a future field swept in by a pattern change fails LOUDLY:
 *
 *  - the hand-named dangerous fields are asserted by name
 *  - whole dangerous CLASSES are asserted by regex, so a new
 *    `somethingDockerImage` or `newToolCustomHeaders` cannot slip in
 *  - every Project scalar column must appear in ALLOW or DENY, so a new Prisma
 *    field fails this file until someone classifies it
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { Prisma } from '@prisma/client'

import {
  RECON_SETTINGS_ALLOWLIST,
  RECON_SETTINGS_DENYLIST,
  DENY_REASON_DOC,
  ALLOWED_SETTING_KEYS,
  SCAN_MODULE_VALUES,
  filterReconSettings,
  isAllowedSetting,
  projectReconSettings,
  reconSettingsSelect,
} from './reconSettingsAllowlist'

const allowKeys = Object.keys(RECON_SETTINGS_ALLOWLIST)

// --- coverage: the control that survives a codebase adding fields weekly ------

describe('every Project column is classified', () => {
  test('ALLOW and DENY together cover Prisma.ProjectScalarFieldEnum', () => {
    const columns = Object.keys(Prisma.ProjectScalarFieldEnum)
    const unclassified = columns.filter(
      c => !(c in RECON_SETTINGS_ALLOWLIST) && !(c in RECON_SETTINGS_DENYLIST)
    )
    expect(
      unclassified,
      'New Project column(s) are unclassified. Add each to the ALLOW or DENY table ' +
      'in reconSettingsAllowlist.generated.ts. Denying is the safe default; a field ' +
      'is only allowlisted if it is genuine recon tuning WITH a ProjectForm bound.'
    ).toEqual([])
  })

  test('no column is in both tables', () => {
    const both = allowKeys.filter(k => k in RECON_SETTINGS_DENYLIST)
    expect(both).toEqual([])
  })

  test('the classification map does not invent columns Prisma does not have', () => {
    const columns = new Set(Object.keys(Prisma.ProjectScalarFieldEnum))
    const ghosts = [...allowKeys, ...Object.keys(RECON_SETTINGS_DENYLIST)].filter(
      k => !columns.has(k)
    )
    expect(ghosts, 'stale entries for columns that no longer exist').toEqual([])
  })

  test('every deny reason has documentation', () => {
    for (const reason of Object.values(RECON_SETTINGS_DENYLIST)) {
      expect(DENY_REASON_DOC[reason], `no doc for reason '${reason}'`).toBeTruthy()
    }
  })
})

// --- the named fields from the threat table ------------------------------------

describe('the fields that make this an attack-launching credential are denied', () => {
  // "update_recon_settings({targetDomain: 'victim.com', targetGuardrailEnabled:
  // false}) then start_recon()" is the whole reason this file exists.
  test.each([
    ['targetDomain', 'engagement scope'],
    ['subdomainList', 'seeds the scan'],
    ['targetIps', 'engagement scope'],
    ['ipMode', 'engagement scope'],
    ['domainBatchMode', 'engagement scope'],
    ['domainBatchHosts', 'engagement scope'],
    ['targetGuardrailEnabled', 'a scope control'],
    ['stealthMode', 'intrusiveness'],
    ['nucleiInteractsh', 'public OAST collector'],
    ['wappalyzerNpmVersion', 'fetched by the scan container'],
    ['nucleiCustomTemplates', 'attacker-supplied file'],
    ['ffufWordlist', 'attacker-supplied file'],
    ['jsReconCustomPatterns', 'ReDoS surface'],
    ['githubTargetOrg', "another scan's target"],
    ['supplyChainRepoUrl', 'becomes a git clone argument'],
    ['gvmScanTargets', "another scan's target"],
    ['userId', 'ownership'],
    ['aiInPipeline', 'billable LLM spend'],
    ['activationState', 'a lock flag, not a setting'],
    ['reconPresetId', 'out of scope'],
  ])('%s is denied (%s)', field => {
    expect(isAllowedSetting(field)).toBe(false)
    expect(RECON_SETTINGS_DENYLIST[field]).toBeTruthy()
  })
})

// --- whole classes, so a NEW field of the same shape cannot slip in -------------

describe('no allowlisted key belongs to a denied class', () => {
  const CLASSES: [string, RegExp][] = [
    ['docker image', /DockerImage$/],
    ['RoE', /^roe/],
    ['agent', /^agent/],
    ['fireteam', /^fireteam/],
    ['custom headers', /CustomHeaders$/],
    ['wordlist or template', /(Wordlist|Template|UploadedFiles?|CustomPatterns?|TamperScripts)/],
    ['out-of-band callback', /(Oob[A-Z]|Interactsh|Callback)/],
    ['credential', /(ApiKey|Token|Secret|Password|Credential)/],
    ['model / LLM', /(Model$|^ai[A-Z]|Ai[A-Z]|^llm|Prompt)/],
    ['SSRF / origin discovery', /^(ssrf|originDiscovery)/],
    ['exploitation technique', /^(rce|pathTraversal|ssti|xxe|sqli|idor|xss|lfi|webCachePoison)/],
    ['DoS', /^dos/],
    ['auth profile', /^authProfile/],
  ]

  test.each(CLASSES)('no %s field is allowlisted', (_label, pattern) => {
    expect(allowKeys.filter(k => pattern.test(k))).toEqual([])
  })
})

describe('the allowlist is what it claims to be', () => {
  test('it is frozen', () => {
    expect(Object.isFrozen(RECON_SETTINGS_ALLOWLIST)).toBe(true)
    expect(Object.isFrozen(RECON_SETTINGS_DENYLIST)).toBe(true)
  })

  test('every numeric carries an explicit min and max', () => {
    for (const [key, spec] of Object.entries(RECON_SETTINGS_ALLOWLIST)) {
      if (spec.kind !== 'number') continue
      expect(Number.isFinite(spec.min), `${key} has no min`).toBe(true)
      expect(Number.isFinite(spec.max), `${key} has no max`).toBe(true)
      expect(spec.max, `${key} has max <= min`).toBeGreaterThan(spec.min)
    }
  })

  test('it is small enough to be reviewable', () => {
    // A positive allowlist that grew to hundreds of entries would have stopped
    // being a decision and become a rubber stamp.
    expect(allowKeys.length).toBeLessThan(200)
    expect(allowKeys.length).toBeGreaterThan(20)
  })

  test('it is a strict minority of the Project columns', () => {
    const columns = Object.keys(Prisma.ProjectScalarFieldEnum).length
    expect(allowKeys.length / columns).toBeLessThan(0.25)
  })
})

// --- filtering behaviour ---------------------------------------------------------

describe('filterReconSettings fails closed', () => {
  test('it accepts an allowlisted value', () => {
    const r = filterReconSettings({ naabuThreads: 25 })
    expect(r.ok).toBe(true)
    if (!r.ok) throw new Error('unreachable')
    expect(r.data).toEqual({ naabuThreads: 25 })
  })

  test('a denied key rejects the WHOLE call, naming the key', () => {
    const r = filterReconSettings({ naabuThreads: 25, targetDomain: 'victim.com' })
    expect(r.ok).toBe(false)
    if (r.ok) throw new Error('unreachable')
    expect(r.key).toBe('targetDomain')
    expect(r.error).toContain('targetDomain')
  })

  test('a denied key is never silently stripped', () => {
    // Stripping would let the caller believe the change applied.
    const r = filterReconSettings({ targetGuardrailEnabled: false })
    expect(r.ok).toBe(false)
  })

  test('the rejection explains the CLASS, not just "no"', () => {
    const r = filterReconSettings({ roeEnabled: false })
    if (r.ok) throw new Error('unreachable')
    expect(r.error).toMatch(/engagement agreement/)
  })

  test('an unknown key (a column added since) is refused', () => {
    const r = filterReconSettings({ someBrandNewField: 1 })
    expect(r.ok).toBe(false)
  })

  test('a prototype-pollution key is refused', () => {
    for (const key of ['__proto__', 'constructor', 'prototype']) {
      expect(filterReconSettings({ [key]: {} }).ok).toBe(false)
    }
  })

  test('an empty or non-object input is refused', () => {
    for (const bad of [{}, null, undefined, [], 'x', 42]) {
      expect(filterReconSettings(bad).ok).toBe(false)
    }
  })
})

describe('value validation mirrors the ProjectForm bounds', () => {
  test('a number above the UI max is refused, naming the bound', () => {
    const spec = RECON_SETTINGS_ALLOWLIST.naabuThreads
    if (spec.kind !== 'number') throw new Error('unreachable')
    const r = filterReconSettings({ naabuThreads: spec.max + 1 })
    expect(r.ok).toBe(false)
    if (r.ok) throw new Error('unreachable')
    expect(r.error).toContain(String(spec.max))
  })

  test('a number below the UI min is refused', () => {
    const spec = RECON_SETTINGS_ALLOWLIST.naabuThreads
    if (spec.kind !== 'number') throw new Error('unreachable')
    expect(filterReconSettings({ naabuThreads: spec.min - 1 }).ok).toBe(false)
  })

  test('an out-of-range value is never clamped', () => {
    const r = filterReconSettings({ naabuThreads: 999_999 })
    expect(r.ok).toBe(false)
  })

  test('a non-integer, NaN or Infinity is refused', () => {
    for (const bad of [1.5, NaN, Infinity, -Infinity, '25', null]) {
      expect(filterReconSettings({ naabuThreads: bad }).ok).toBe(false)
    }
  })

  test('a boolean field refuses a truthy non-boolean', () => {
    expect(filterReconSettings({ naabuEnabled: true }).ok).toBe(true)
    for (const bad of ['true', 1, 'yes', {}]) {
      expect(filterReconSettings({ naabuEnabled: bad }).ok).toBe(false)
    }
  })

  test('scanModules is validated against its enum', () => {
    expect(filterReconSettings({ scanModules: ['port_scan', 'http_probe'] }).ok).toBe(true)
    expect(filterReconSettings({ scanModules: ['rm -rf /'] }).ok).toBe(false)
    expect(filterReconSettings({ scanModules: 'port_scan' }).ok).toBe(false)
    for (const m of SCAN_MODULE_VALUES) {
      expect(filterReconSettings({ scanModules: [m] }).ok).toBe(true)
    }
  })

  test('a severity list is validated against its vocabulary', () => {
    expect(filterReconSettings({ nucleiSeverity: ['high', 'critical'] }).ok).toBe(true)
    expect(filterReconSettings({ nucleiSeverity: ['catastrophic'] }).ok).toBe(false)
    expect(filterReconSettings({ nucleiSeverity: ['-x; whoami'] }).ok).toBe(false)
  })

  test('a status-code list must contain codes, not free text', () => {
    expect(filterReconSettings({ httpxMatchCodes: ['200', '301-399'] }).ok).toBe(true)
    expect(filterReconSettings({ httpxMatchCodes: ['$(id)'] }).ok).toBe(false)
  })
})

// --- reading back ------------------------------------------------------------------

describe('projectReconSettings returns only the allowlisted subset', () => {
  test('a credential in the row never reaches the result', () => {
    const out = projectReconSettings({
      naabuThreads: 25,
      targetDomain: 'example.com',
      cypherfixGithubToken: 'ghp_secret',
      userId: 'owner',
    })
    expect(out).toEqual({ naabuThreads: 25 })
  })

  test('missing columns are omitted rather than nulled', () => {
    expect(projectReconSettings({ naabuThreads: 25 })).toEqual({ naabuThreads: 25 })
  })

  test('the prisma select covers exactly the allowlist', () => {
    expect(Object.keys(reconSettingsSelect()).sort()).toEqual([...ALLOWED_SETTING_KEYS].sort())
  })
})
