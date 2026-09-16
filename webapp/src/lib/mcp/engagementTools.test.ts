/**
 * The four engagement tools, exercised through their real handlers.
 *
 * What they are for, stated once so the assertions read as consequences rather
 * than as a list: an agent holding an MCP token must be able to take a scope
 * document and stand up a project that PROVABLY cannot violate it. Every test
 * below is one way that could fail quietly.
 *
 * T24 lives here too. Each of these is a new state-changing tool, and a tool
 * that skips a guard the others keep is a hole in a control that holds
 * everywhere else on the surface: the scope check, a rate-limit bucket, the busy
 * check, and an audit row.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  createProject: vi.fn(),
  findProject: vi.fn(),
  updateProject: vi.fn(),
  updateManyProject: vi.fn(),
  createAuthorization: vi.fn(),
  findFirstAuthorization: vi.fn(),
  findUniqueAuthorization: vi.fn(),
  findManyAuthorization: vi.fn(),
  countAuthorization: vi.fn(),
  transaction: vi.fn(),
  busy: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      create: (...a: unknown[]) => h.createProject(...a),
      findUnique: (...a: unknown[]) => h.findProject(...a),
      update: (...a: unknown[]) => h.updateProject(...a),
      updateMany: (...a: unknown[]) => h.updateManyProject(...a),
    },
    engagementAuthorization: {
      create: (...a: unknown[]) => h.createAuthorization(...a),
      findFirst: (...a: unknown[]) => h.findFirstAuthorization(...a),
      findUnique: (...a: unknown[]) => h.findUniqueAuthorization(...a),
      findMany: (...a: unknown[]) => h.findManyAuthorization(...a),
      count: (...a: unknown[]) => h.countAuthorization(...a),
    },
    $transaction: (fn: (tx: unknown) => unknown) => h.transaction(fn, client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: (...a: unknown[]) => h.busy(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { McpScopeError, __resetRateLimiter } from '@/lib/mcpAuth'
import {
  attachEngagementAuthorization,
  createProject,
  listEngagementAuthorizations,
  preflightScopeCheck,
  tightenEngagementRoe,
} from './engagementTools'
import type { McpContext } from './tools'

const ALL_SCOPES = ['recon:read', 'project:create', 'engagement:authorize'] as const

const ctx = (scopes: readonly string[] = ALL_SCOPES): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const AUTH = {
  documentSha256: 'a'.repeat(64),
  documentKind: 'hackerone_program',
  programHandle: 'nba-public',
  issuedAt: '2026-01-01T00:00:00.000Z',
  summary: '428 in-scope, 28 excluded, 3 rps ceiling',
}

const projectRow = (over: Record<string, unknown> = {}) => ({
  id: 'p1',
  userId: 'owner',
  updatedAt: new Date('2026-01-01T00:00:00.000Z'),
  engagementKind: 'internal',
  engagementIdentityHeader: '',
  roeEnabled: false,
  roeGlobalMaxRps: 0,
  targetDomain: 'example.com',
  targetIps: [],
  ipMode: false,
  domainBatchMode: false,
  domainBatchHosts: [],
  targetGuardrailEnabled: true,
  roeExcludedHosts: [],
  roeForbiddenTools: [],
  roeForbiddenCategories: [],
  roeAllowDos: false,
  roeAllowDataExfiltration: false,
  scanModules: ['domain_discovery', 'port_scan'],
  naabuRateLimit: 1000,
  nucleiRateLimit: 150,
  takeoverRateLimit: 50,
  ffufRate: 0,
  nucleiDockerImage: 'projectdiscovery/nuclei:latest',
  naabuEnabled: true,
  ffufEnabled: true,
  ffufWordlist: '/usr/share/seclists/Discovery/Web-Content/common.txt',
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.busy.mockResolvedValue(null)
  h.findProject.mockResolvedValue(projectRow())
  h.createProject.mockResolvedValue({ id: 'p1', name: 'test' })
  h.createAuthorization.mockResolvedValue({ id: 'auth1', recordedAt: new Date() })
  h.findFirstAuthorization.mockResolvedValue(null)
  h.findUniqueAuthorization.mockResolvedValue(null)
  h.findManyAuthorization.mockResolvedValue([])
  h.countAuthorization.mockResolvedValue(0)
  h.updateProject.mockResolvedValue({})
  h.updateManyProject.mockResolvedValue({ count: 1 })
  h.transaction.mockImplementation((fn, client) => fn(client))
  h.audit.mockResolvedValue(undefined)
})

// --- create_project -----------------------------------------------------------------

describe('create_project fixes scope, and only here', () => {
  test('it needs project:create', async () => {
    await expect(createProject(ctx(['recon:read']), { name: 'x', engagementKind: 'internal', targetDomain: 'a.tld' }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('a single domain creates a project', async () => {
    const r = await createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
    })
    expect(r.created).toBe(true)
    expect(h.createProject.mock.calls[0][0].data.targetDomain).toBe('example.com')
  })

  test('no targeting mode is refused, naming all three', async () => {
    await expect(createProject(ctx(), { name: 'test', engagementKind: 'internal' }))
      .rejects.toThrow(/targetDomain.*targetIps.*domainBatchHosts/s)
  })

  test('two targeting modes are refused rather than resolved', async () => {
    // Picking one for the caller would scan something it did not ask for.
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal',
      targetDomain: 'example.com', targetIps: ['10.0.0.1'],
    })).rejects.toThrow(/mutually exclusive/)
  })

  test('the domain-batch grouping is derived server-side', async () => {
    // The grouping decides the run order, so a client-supplied one is a control
    // the server would be taking from the caller's word.
    await createProject(ctx(), {
      name: 'test', engagementKind: 'internal',
      domainBatchHosts: ['a.example.com', 'b.example.com'],
    })
    const data = h.createProject.mock.calls[0][0].data
    expect(data.domainBatchMode).toBe(true)
    expect(Array.isArray(data.domainBatchGroups)).toBe(true)
    expect(data.domainBatchGroups).not.toHaveLength(0)
  })

  test('the owner is the TOKEN owner, never a body-supplied one', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      settings: { userId: 'someone-else' } as never,
    }).catch(() => {})
    if (h.createProject.mock.calls.length > 0) {
      expect(h.createProject.mock.calls[0][0].data.userId).toBe('owner')
    }
  })
})

describe('create_project enforces the third-party rule before writing anything', () => {
  test('third_party with no ceiling is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      authorization: AUTH,
    })).rejects.toThrow(/rate ceiling/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('third_party with a 0 ceiling is refused, saying what 0 means', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 0 },
      authorization: AUTH,
    })).rejects.toThrow(/NO ceiling/)
  })

  test('third_party with no authorization is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
    })).rejects.toThrow(/authorized it/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('third_party with both is created, and the authorization with it', async () => {
    const r = await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
      authorization: AUTH,
    })
    expect(r.created).toBe(true)
    expect(h.createAuthorization).toHaveBeenCalled()
    expect(h.createAuthorization.mock.calls[0][0].data.documentSha256).toBe(AUTH.documentSha256)
  })

  test('the project and its authorization are written in ONE transaction', async () => {
    // A project that exists without the record that authorized it is exactly
    // the state the third-party rule is meant to make impossible.
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
      authorization: AUTH,
    })
    expect(h.transaction).toHaveBeenCalledTimes(1)
  })
})

describe('create_project takes a digest, never the document', () => {
  test('documentText is digested here and not stored', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, documentSha256: undefined, documentText: 'in scope: *.example.com' },
    })
    const data = h.createAuthorization.mock.calls[0][0].data
    expect(data.documentSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify(data)).not.toContain('in scope')
  })

  test('a malformed digest is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, documentSha256: 'not-a-digest' },
    })).rejects.toThrow(/64 lower-case hex/)
  })

  test('a future issuedAt is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, issuedAt: new Date(Date.now() + 86_400_000).toISOString() },
    })).rejects.toThrow(/future/)
  })

  test('recordedAt is the server clock, never the caller s', async () => {
    // A timestamp a caller can choose proves nothing.
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, recordedAt: '1999-01-01T00:00:00.000Z' } as never,
    })
    expect(h.createAuthorization.mock.calls[0][0].data).not.toHaveProperty('recordedAt')
  })

  test('the writing token is recorded, so a revoked one stays attributable', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      roe: { roeEnabled: true, roeGlobalMaxRps: 3 },
      authorization: AUTH,
    })
    expect(h.createAuthorization.mock.calls[0][0].data.recordedByTokenId).toBe('t1')
  })
})

describe('create_project is safe to retry', () => {
  test('the same idempotency key returns the FIRST project', async () => {
    // A retry is the normal failure path for an unattended loop, and a retry
    // that creates a second project is two engagements where the operator
    // authorized one.
    h.findUniqueAuthorization.mockResolvedValue({
      projectId: 'p1', project: { userId: 'owner', name: 'first' },
    })
    const r = await createProject(ctx(), {
      name: 'second', engagementKind: 'internal', targetDomain: 'example.com',
      idempotencyKey: 'nba-public-abc12345',
    })
    expect(r.created).toBe(false)
    expect(r.projectId).toBe('p1')
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('another account s idempotency key is refused, not returned', async () => {
    h.findUniqueAuthorization.mockResolvedValue({
      projectId: 'p1', project: { userId: 'someone-else', name: 'theirs' },
    })
    await expect(createProject(ctx(), {
      name: 'x', engagementKind: 'internal', targetDomain: 'example.com',
      idempotencyKey: 'nba-public-abc12345',
    })).rejects.toThrow(/another account/)
  })

  test('the key is checked BEFORE anything is written', async () => {
    h.findUniqueAuthorization.mockResolvedValue({
      projectId: 'p1', project: { userId: 'owner', name: 'first' },
    })
    await createProject(ctx(), {
      name: 'x', engagementKind: 'internal', targetDomain: 'example.com',
      idempotencyKey: 'k'.repeat(12),
    })
    expect(h.transaction).not.toHaveBeenCalled()
  })
})

describe('create_project validates what it writes', () => {
  test('a non-RoE field in the roe block is refused by name', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      roe: { naabuThreads: 25 },
    })).rejects.toThrow(/naabuThreads/)
  })

  test('an out-of-bounds tuning value is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      settings: { naabuThreads: 999_999 },
    })).rejects.toThrow(/between/)
  })

  test('an identity header that would re-point the request is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      engagementIdentityHeader: 'Host: victim.com',
    })).rejects.toThrow(/host/)
  })

  test('an ordinary identity header is accepted', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      engagementIdentityHeader: 'X-Bug-Bounty: my-handle',
    })
    expect(h.createProject.mock.calls[0][0].data.engagementIdentityHeader)
      .toBe('X-Bug-Bounty: my-handle')
  })
})

// --- tighten_engagement_roe ------------------------------------------------------------

describe('tighten_engagement_roe moves one direction', () => {
  test('it needs project:create, not recon:settings', async () => {
    await expect(tightenEngagementRoe(ctx(['recon:settings']), 'p1', { roeGlobalMaxRps: 1 }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('lowering the ceiling is accepted', async () => {
    h.findProject.mockResolvedValue(projectRow({ roeEnabled: true, roeGlobalMaxRps: 3 }))
    const r = await tightenEngagementRoe(ctx(), 'p1', { roeGlobalMaxRps: 1 })
    expect(r.tightened).toEqual({ roeGlobalMaxRps: 1 })
  })

  test('raising the ceiling is refused', async () => {
    h.findProject.mockResolvedValue(projectRow({ roeEnabled: true, roeGlobalMaxRps: 3 }))
    await expect(tightenEngagementRoe(ctx(), 'p1', { roeGlobalMaxRps: 10 }))
      .rejects.toThrow(/only decrease/)
    expect(h.updateProject).not.toHaveBeenCalled()
  })

  test('removing the ceiling is refused, because 0 means none', async () => {
    h.findProject.mockResolvedValue(projectRow({ roeEnabled: true, roeGlobalMaxRps: 3 }))
    await expect(tightenEngagementRoe(ctx(), 'p1', { roeGlobalMaxRps: 0 }))
      .rejects.toThrow(/NO ceiling/)
  })

  test('growing an exclusion list is accepted and shrinking it is not', async () => {
    h.findProject.mockResolvedValue(projectRow({ roeExcludedHosts: ['a.example.com'] }))
    await expect(tightenEngagementRoe(ctx(), 'p1', {
      roeExcludedHosts: ['a.example.com', 'b.example.com'],
    })).resolves.toBeTruthy()
    await expect(tightenEngagementRoe(ctx(), 'p1', { roeExcludedHosts: [] }))
      .rejects.toThrow(/only grow/)
  })

  test('a non-RoE field is refused by name', async () => {
    await expect(tightenEngagementRoe(ctx(), 'p1', { naabuThreads: 25 }))
      .rejects.toThrow(/naabuThreads/)
  })

  test('it is refused while a scan is writing the graph', async () => {
    // The running scan read its Rules of Engagement at start. A tightening
    // accepted mid-scan is one that silently did not apply, which is worse than
    // a refused one.
    h.busy.mockResolvedValue('a full recon is running')
    await expect(tightenEngagementRoe(ctx(), 'p1', { roeGlobalMaxRps: 1 }))
      .rejects.toThrow(/will not see the change/)
  })

  test('a stale expectedUpdatedAt is a conflict, not an overwrite', async () => {
    h.findProject.mockResolvedValue(projectRow({ roeEnabled: true, roeGlobalMaxRps: 3 }))
    h.updateManyProject.mockResolvedValue({ count: 0 })
    await expect(tightenEngagementRoe(ctx(), 'p1', { roeGlobalMaxRps: 1 }, '2020-01-01T00:00:00.000Z'))
      .rejects.toThrow(/changed since you read it/)
  })

  test('it writes an audit row with a before and an after', async () => {
    h.findProject.mockResolvedValue(projectRow({ roeEnabled: true, roeGlobalMaxRps: 3 }))
    await tightenEngagementRoe(ctx(), 'p1', { roeGlobalMaxRps: 1 })
    const row = h.audit.mock.calls[0][0]
    expect(row.action).toBe('mcp.tighten_roe')
    expect(row.before).toEqual({ roeGlobalMaxRps: 3 })
    expect((row.after as Record<string, unknown>).changes).toEqual({ roeGlobalMaxRps: 1 })
  })
})

// --- attach_engagement_authorization -------------------------------------------------------

describe('attach_engagement_authorization is append-only', () => {
  test('it needs engagement:authorize, which project:create does not imply', async () => {
    await expect(attachEngagementAuthorization(ctx(['project:create']), 'p1', AUTH))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('it creates rather than updating', async () => {
    await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(h.createAuthorization).toHaveBeenCalled()
  })

  test('it reports what it supersedes without removing it', async () => {
    h.findFirstAuthorization.mockResolvedValue({ id: 'auth0', programHandle: 'nba-public' })
    const r = await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(r.supersedes).toBe('auth0')
    expect(r.note).toMatch(/Append-only/)
  })

  test('a DIFFERENT program is flagged, and does not re-point the project', async () => {
    // A project quietly re-authorized against another program's scope is the
    // failure this note exists for.
    h.findFirstAuthorization.mockResolvedValue({ id: 'auth0', programHandle: 'other-program' })
    const r = await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(r.note).toMatch(/DIFFERENT program/)
    expect(r.note).toMatch(/still the one it was created with/)
  })

  test('it writes an audit row carrying the digest', async () => {
    await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    const row = h.audit.mock.calls[0][0]
    expect(row.action).toBe('mcp.attach_authorization')
    expect((row.after as Record<string, unknown>).documentSha256).toBe(AUTH.documentSha256)
  })

  test('there is no update or delete path on this module', async () => {
    const mod = await import('./engagementTools')
    const names = Object.keys(mod).join(' ')
    expect(names).not.toMatch(/updateAuthorization|deleteAuthorization|revokeAuthorization/)
  })
})

// --- preflight_scope_check -------------------------------------------------------------

describe('preflight_scope_check reports RESOLVED values', () => {
  test('it needs only recon:read', async () => {
    await expect(preflightScopeCheck(ctx([]), 'p1')).rejects.toBeInstanceOf(McpScopeError)
    await expect(preflightScopeCheck(ctx(['recon:read']), 'p1')).resolves.toBeTruthy()
  })

  test('a rate above the ceiling is reported at the ceiling, not as written', async () => {
    h.findProject.mockResolvedValue(projectRow({
      roeEnabled: true, roeGlobalMaxRps: 3, naabuRateLimit: 1000,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    const naabu = r.resolvedRates.find(x => x.field === 'naabuRateLimit')!
    expect(naabu.written).toBe(1000)
    expect(naabu.resolved).toBe(3)
    expect(naabu.capped).toBe(true)
  })

  test('a zero that means unlimited is reported at the ceiling too', async () => {
    // The failure a `value > ceiling` check cannot see.
    h.findProject.mockResolvedValue(projectRow({
      roeEnabled: true, roeGlobalMaxRps: 3, ffufRate: 0,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    const ffuf = r.resolvedRates.find(x => x.field === 'ffufRate')!
    expect(ffuf.resolved).toBe(3)
    expect(ffuf.wasUnlimited).toBe(true)
  })

  test('with no ceiling, a zero rate is reported as unlimited rather than as zero', async () => {
    const r = await preflightScopeCheck(ctx(), 'p1')
    const ffuf = r.resolvedRates.find(x => x.field === 'ffufRate')!
    expect(ffuf.resolved).toBe(0)
    expect(ffuf.wasUnlimited).toBe(true)
  })

  test('no rate ever resolves above the ceiling', async () => {
    h.findProject.mockResolvedValue(projectRow({
      roeEnabled: true, roeGlobalMaxRps: 3,
      naabuRateLimit: 5000, nucleiRateLimit: 500, takeoverRateLimit: 500,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.ratesExceedingCeiling).toEqual([])
    for (const rate of r.resolvedRates) expect(rate.resolved, rate.field).toBeLessThanOrEqual(3)
  })

  test('a non-allowlisted image is reported as pinned', async () => {
    // get_recon_settings will echo what was written. This is the only place a
    // caller learns which image actually runs.
    h.findProject.mockResolvedValue(projectRow({ nucleiDockerImage: 'attacker/evil:latest' }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    const rewrite = r.rewrittenAtScanStart.find(x => x.field === 'nucleiDockerImage')!
    expect(rewrite.written).toBe('attacker/evil:latest')
    expect(rewrite.willRun).toBe('projectdiscovery/nuclei:latest')
  })

  test('a shipped image is NOT reported as rewritten', async () => {
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.rewrittenAtScanStart.some(x => x.field === 'nucleiDockerImage')).toBe(false)
  })

  test('an escaping wordlist path is reported as dropped', async () => {
    h.findProject.mockResolvedValue(projectRow({ ffufWordlist: '/etc/shadow' }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.rewrittenAtScanStart.some(x => x.field === 'ffufWordlist')).toBe(true)
  })

  test('a tool enabled in a phase that is not running is named as a silent no-op', async () => {
    // The two-level model biting: the scan succeeds, that tool never runs, and
    // no result field says why.
    h.findProject.mockResolvedValue(projectRow({
      scanModules: ['domain_discovery'], ffufEnabled: true,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.silentNoOps.some(x => x.field === 'ffufEnabled')).toBe(true)
  })

  test('a tool enabled in a phase that IS running is not a no-op', async () => {
    h.findProject.mockResolvedValue(projectRow({
      scanModules: ['domain_discovery', 'port_scan'], naabuEnabled: true,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.silentNoOps.some(x => x.field === 'naabuEnabled')).toBe(false)
  })

  test('startable is false exactly when start_recon would refuse', async () => {
    h.findProject.mockResolvedValue(projectRow({
      engagementKind: 'third_party', roeEnabled: true, roeGlobalMaxRps: 3,
    }))
    h.countAuthorization.mockResolvedValue(0)
    expect((await preflightScopeCheck(ctx(), 'p1')).startable).toBe(false)

    h.countAuthorization.mockResolvedValue(1)
    expect((await preflightScopeCheck(ctx(), 'p1')).startable).toBe(true)
  })

  test('it returns no credential and no client identity', async () => {
    h.findProject.mockResolvedValue(projectRow({
      cypherfixGithubToken: 'ghp_secret',
      roeClientContactEmail: 'someone@client.example',
      graphqlAuthValue: 'Bearer secret',
    }))
    const serialised = JSON.stringify(await preflightScopeCheck(ctx(), 'p1'))
    expect(serialised).not.toContain('ghp_secret')
    expect(serialised).not.toContain('client.example')
    expect(serialised).not.toContain('Bearer secret')
  })

  test('a missing project is refused, not reported as an empty one', async () => {
    // assertMcpProjectAccess gets there first and refuses with the same message
    // it uses for another account's project. That is deliberate: distinguishing
    // "does not exist" from "not yours" is a project enumeration oracle.
    h.findProject.mockResolvedValue(null)
    await expect(preflightScopeCheck(ctx(), 'p1')).rejects.toThrow(/not found/)
  })
})

describe('list_engagement_authorizations', () => {
  test('it returns the history newest first and says it is append-only', async () => {
    h.findManyAuthorization.mockResolvedValue([{ id: 'auth2' }, { id: 'auth1' }])
    const r = await listEngagementAuthorizations(ctx(), 'p1')
    expect(r.authorizations).toHaveLength(2)
    expect(h.findManyAuthorization.mock.calls[0][0].orderBy).toEqual({ recordedAt: 'desc' })
    expect(r.note).toMatch(/Append-only/)
  })

  test('an empty list is a real answer for an internal engagement', async () => {
    const r = await listEngagementAuthorizations(ctx(), 'p1')
    expect(r.authorizations).toEqual([])
  })
})

// --- T24: the guards every state-changing tool keeps ----------------------------------------

describe('T24 every new tool joins the guards the others keep', () => {
  test('each state-changing tool writes an audit row', async () => {
    await createProject(ctx(), { name: 'a', engagementKind: 'internal', targetDomain: 'a.tld' })
    expect(h.audit).toHaveBeenCalledTimes(1)

    h.audit.mockClear()
    await tightenEngagementRoe(ctx(), 'p1', { roeExcludedHosts: ['a.tld'] })
    expect(h.audit).toHaveBeenCalledTimes(1)

    h.audit.mockClear()
    await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(h.audit).toHaveBeenCalledTimes(1)
  })

  test('each read-only tool writes none', async () => {
    await preflightScopeCheck(ctx(), 'p1')
    await listEngagementAuthorizations(ctx(), 'p1')
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('every tool taking a projectId asserts access to it', async () => {
    // assertMcpProjectAccess loads the project and compares its owner. A tool
    // that skipped it would read another account's engagement.
    h.findProject.mockResolvedValue({ ...projectRow(), userId: 'someone-else' })
    for (const call of [
      () => tightenEngagementRoe(ctx(), 'p1', { roeExcludedHosts: ['a'] }),
      () => attachEngagementAuthorization(ctx(), 'p1', AUTH),
      () => preflightScopeCheck(ctx(), 'p1'),
      () => listEngagementAuthorizations(ctx(), 'p1'),
    ]) {
      await expect(call()).rejects.toThrow()
    }
  })
})
