/**
 * The MCP read tools.
 *
 * Two rules dominate these tests, because breaking either produces a FALSE
 * NEGATIVE in a security tool rather than a visible error:
 *
 *  - a dependency failure is never an empty result. "Nothing found" and
 *    "could not ask" must not look the same to an agent writing a report.
 *  - ownership is checked before anything else, and a foreign project is
 *    indistinguishable from a missing one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  findManyProjects: vi.fn(),
  findVersion: vi.fn(),
  orchestratorFetch: vi.fn(),
  isActivating: vi.fn(),
  busy: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findProject(...a),
      findMany: (...a: unknown[]) => h.findManyProjects(...a),
    },
    scanVersion: { findFirst: (...a: unknown[]) => h.findVersion(...a) },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.isActivating(...a) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: (...a: unknown[]) => h.busy(...a) }))

import { McpScopeError, McpAccessDenied, __resetRateLimiter, __resetLlmBudget } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { __resetSchemaCache } from './graphClient'
import {
  getReconSettings,
  getReconStatus,
  graphSchema,
  graphSummary,
  listProjects,
  queryGraph,
  resolveLiveGraphState,
  type McpContext,
} from './tools'

const ctx = (scopes: string[] = ['recon:read']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const ownNode = (label: string) => ({
  _kind: 'node', labels: [label], properties: { user_id: 'owner', project_id: 'p1' },
})

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
  __resetRateLimiter()
  __resetLlmBudget()
  __resetSchemaCache()
  vi.stubGlobal('fetch', h.fetch)
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.findManyProjects.mockResolvedValue([{ id: 'p1', name: 'Target', targetDomain: 'x.tld' }])
  h.findVersion.mockResolvedValue({ id: 'v3', seq: 3, label: 'Scan 3', createdAt: new Date() })
  h.isActivating.mockResolvedValue(false)
  h.busy.mockResolvedValue(null)
})

// --- list_projects -------------------------------------------------------------

describe('list_projects', () => {
  test('is scoped to the token owner, so other ids cannot be enumerated', async () => {
    await listProjects(ctx())
    expect(h.findManyProjects).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'owner' } })
    )
  })

  test('needs recon:read', async () => {
    await expect(listProjects(ctx([]))).rejects.toBeInstanceOf(McpScopeError)
  })

  test('never selects a credential-bearing column', async () => {
    await listProjects(ctx())
    const select = h.findManyProjects.mock.calls[0][0].select
    for (const key of Object.keys(select)) {
      expect(key).not.toMatch(/Token|ApiKey|Secret|Password|authProfile/)
    }
  })

  test('does not fan out to the orchestrator', async () => {
    // That is what get_recon_status is for; a list must stay cheap.
    await listProjects(ctx())
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

// --- get_recon_status ----------------------------------------------------------

describe('get_recon_status', () => {
  test('returns the orchestrator status', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'running', current_phase: 'port_scan' }),
    })
    const r = await getReconStatus(ctx(), 'p1')
    expect(r).toMatchObject({ status: 'running', currentPhase: 'port_scan', failed: false })
  })

  // REGRESSION (audit finding F5): the raw ReconState carries `container_id`
  // and an `error` populated with raw exception text. A Docker SDK failure
  // embeds the deployment's absolute HOST PATHS and image names, and returning
  // it verbatim handed an untrusted agent reconnaissance about the host, then
  // put it in a model's context. errors.ts forbids exactly that everywhere else.
  test('REGRESSION: the raw orchestrator body is NOT passed through', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'error',
        container_id: 'a1b2c3d4e5f6',
        error: 'invalid mount config for type "bind": bind source path does not '
             + 'exist: /home/operator/deploy/redamon/recon',
      }),
    })
    const r = await getReconStatus(ctx(), 'p1')
    const serialised = JSON.stringify(r)

    expect(serialised).not.toContain('/home/operator')
    expect(serialised).not.toContain('a1b2c3d4e5f6')
    expect(serialised).not.toMatch(/bind source path/)
    // The FACT of failure still reaches the caller; only the detail does not.
    expect(r.failed).toBe(true)
    expect(r.status).toBe('error')
  })

  test('an unreachable orchestrator is "unknown", NEVER "not running"', async () => {
    h.orchestratorFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(getReconStatus(ctx(), 'p1')).rejects.toThrow(/unknown/i)
  })

  test('a non-200 is "unknown" too', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 502, json: async () => ({}) })
    await expect(getReconStatus(ctx(), 'p1')).rejects.toThrow(/unknown/i)
  })

  test("another user's project is refused before the orchestrator is called", async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(getReconStatus(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

// --- get_recon_settings ---------------------------------------------------------

describe('get_recon_settings', () => {
  test('returns only the allowlisted subset', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 25, nucleiEnabled: true })

    const r = await getReconSettings(ctx(), 'p1')
    expect(r.settings).toEqual({ naabuThreads: 25, nucleiEnabled: true })
  })

  test('the prisma select is built FROM the allowlist, so no secret is loaded', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({})
    await getReconSettings(ctx(), 'p1')

    const select = h.findProject.mock.calls[1][0].select
    for (const key of Object.keys(select)) {
      expect(key).not.toMatch(/Token|ApiKey|Secret|Password|DockerImage|^roe|^target/)
    }
  })
})

// --- graph_summary ----------------------------------------------------------------

describe('graph_summary', () => {
  const okSummary = () =>
    h.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        nodes: [{ label: 'IP', count: 12 }],
        relationships: [{ type: 'RESOLVES_TO', count: 8 }],
      }),
    })

  test('returns counts per label and the current version', async () => {
    okSummary()
    const r = await graphSummary(ctx(), 'p1')
    expect(r.nodes).toEqual([{ label: 'IP', count: 12 }])
    expect(r.scanVersion).toMatchObject({ seq: 3 })
  })

  test('it uses the FIXED summary op, not caller-supplied Cypher', async () => {
    okSummary()
    await graphSummary(ctx(), 'p1')
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.op).toBe('summary')
    expect(body.cypher).toBeUndefined()
  })

  test('it carries the FULL tenant key, not project_id alone', async () => {
    okSummary()
    await graphSummary(ctx(), 'p1')
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.user_id).toBe('owner')
    expect(body.project_id).toBe('p1')
  })

  test('a graph failure is a plain failure, NEVER an empty summary', async () => {
    // An empty summary reads as "nothing has ever been scanned", which is the
    // false negative graph_summary exists to prevent.
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(graphSummary(ctx(), 'p1')).rejects.toThrow(/unavailable/i)
  })

  test('a non-200 from the agent also fails rather than returning zeros', async () => {
    h.fetch.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) })
    await expect(graphSummary(ctx(), 'p1')).rejects.toBeInstanceOf(McpToolError)
  })

  test('a scan in flight is reported, with a warning', async () => {
    okSummary()
    h.busy.mockResolvedValue('a full recon scan is running')
    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('scan_running')
    expect(r.warning).toMatch(/not settled/i)
  })

  test('an activation in flight is reported, with a warning', async () => {
    okSummary()
    h.isActivating.mockResolvedValue(true)
    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('activating')
    expect(r.warning).toBeTruthy()
  })

  test('a settled graph carries no warning', async () => {
    okSummary()
    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('stable')
    expect(r.warning).toBeUndefined()
  })
})

describe('resolveLiveGraphState', () => {
  test('activation outranks a running scan', async () => {
    h.isActivating.mockResolvedValue(true)
    h.busy.mockResolvedValue('a scan is running')
    expect(await resolveLiveGraphState('p1')).toBe('activating')
  })
})

// --- graph_schema -------------------------------------------------------------------

describe('graph_schema', () => {
  test('returns the schema document', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ schema: 'NODE TYPES ...' }) })
    expect(await graphSchema(ctx())).toEqual({ schema: 'NODE TYPES ...' })
  })

  test('it is cached, so it cannot fail on a dependency after the first read', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ schema: 'NODE TYPES ...' }) })
    await graphSchema(ctx())
    h.fetch.mockRejectedValue(new Error('agent down'))
    expect(await graphSchema(ctx())).toEqual({ schema: 'NODE TYPES ...' })
    expect(h.fetch).toHaveBeenCalledOnce()
  })

  test('it takes no projectId, so it exposes no tenant data', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ schema: 'x' }) })
    await graphSchema(ctx())
    expect(h.findProject).not.toHaveBeenCalled()
  })
})

// --- query_graph ---------------------------------------------------------------------

describe('query_graph argument handling', () => {
  test('exactly one of question or cypher is required', async () => {
    await expect(queryGraph(ctx(), 'p1', {})).rejects.toThrow(/exactly one/i)
    await expect(queryGraph(ctx(), 'p1', { question: 'q', cypher: 'MATCH (n:IP) RETURN n' }))
      .rejects.toThrow(/exactly one/i)
  })

  test('raw cypher needs the graph:cypher scope', async () => {
    await expect(queryGraph(ctx(['recon:read']), 'p1', { cypher: 'MATCH (n:IP) RETURN n' }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('a natural-language question needs only recon:read', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await expect(queryGraph(ctx(['recon:read']), 'p1', { question: 'list ips' })).resolves.toBeTruthy()
  })
})

describe('query_graph', () => {
  test('returns records and the generated cypher', async () => {
    h.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ records: [{ n: ownNode('IP') }], cypher: 'MATCH (i:IP) RETURN i' }),
    })
    const r = await queryGraph(ctx(), 'p1', { question: 'list ips' })
    expect(r.records).toHaveLength(1)
    expect(r.cypher).toBe('MATCH (i:IP) RETURN i')
  })

  test('it reports truncation rather than silently shortening', async () => {
    h.fetch.mockResolvedValue({
      ok: true, json: async () => ({ records: [], truncated: true }),
    })
    expect((await queryGraph(ctx(), 'p1', { question: 'everything' })).truncated).toBe(true)
  })

  test('the resolved identity is sent, never one from the arguments', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'list ips' })
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.user_id).toBe('owner')
    expect(body.project_id).toBe('p1')
  })

  test('it never goes through the webapp text-to-cypher proxy', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'list ips' })
    expect(h.fetch.mock.calls[0][0]).not.toContain('/api/agent/text-to-cypher')
    expect(h.fetch.mock.calls[0][0]).toContain('/graph/nl-query')
  })

  test('raw cypher goes to graph/exec marked as MCP-originated', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(['recon:read', 'graph:cypher']), 'p1', { cypher: 'MATCH (n:IP) RETURN n' })
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.op).toBe('cypher')
    expect(body.source).toBe('mcp')
  })

  test("a cross-tenant row in the RESULT drops the whole response", async () => {
    // Defence in depth: even if the server-side filter regressed.
    h.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        records: [
          { n: ownNode('IP') },
          { n: { _kind: 'node', labels: ['IP'], properties: { user_id: 'mallory', project_id: 'pX' } } },
        ],
      }),
    })
    await expect(queryGraph(ctx(), 'p1', { question: 'list ips' })).rejects.toThrow(/safety check/i)
  })

  test('a generation failure is distinguishable from an execution failure', async () => {
    h.fetch.mockResolvedValue({
      ok: false, status: 422,
      json: async () => ({ error: 'Could not generate a valid query.', stage: 'generate' }),
    })
    await expect(queryGraph(ctx(), 'p1', { question: 'nonsense' }))
      .rejects.toMatchObject({ code: 'generate_failed' })

    h.fetch.mockResolvedValue({
      ok: false, status: 413,
      json: async () => ({ error: 'result too large, narrow your query', stage: 'execute' }),
    })
    await expect(queryGraph(ctx(), 'p1', { question: 'everything' }))
      .rejects.toMatchObject({ code: 'execute_failed' })
  })

  test('an unreachable agent is an error, never an empty record set', async () => {
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(queryGraph(ctx(), 'p1', { question: 'list ips' }))
      .rejects.toMatchObject({ code: 'agent_unreachable' })
  })

  test('the per-token LLM budget is enforced on the question path', async () => {
    vi.stubEnv('MCP_LLM_DAILY_BUDGET', '1')
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'q1' })
    await expect(queryGraph(ctx(), 'p1', { question: 'q2' })).rejects.toThrow(/budget/i)
  })

  test('the raw-cypher path does not consume the LLM budget', async () => {
    vi.stubEnv('MCP_LLM_DAILY_BUDGET', '1')
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    const c = ctx(['recon:read', 'graph:cypher'])
    await queryGraph(c, 'p1', { cypher: 'MATCH (n:IP) RETURN n' })
    await expect(queryGraph(c, 'p1', { cypher: 'MATCH (n:Host) RETURN n' })).resolves.toBeTruthy()
  })

  test('ownership is checked before any agent call', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(queryGraph(ctx(), 'p1', { question: 'q' })).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('rate limiting applies per tool class', () => {
  test('the query bucket refuses once exhausted', async () => {
    vi.stubEnv('MCP_RATE_QUERY_PER_MIN', '1')
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'q1' })
    await expect(queryGraph(ctx(), 'p1', { question: 'q2' })).rejects.toThrow(/rate limit/i)
  })

  test('the refusal says when to retry', async () => {
    vi.stubEnv('MCP_RATE_READ_PER_MIN', '1')
    await listProjects(ctx())
    await expect(listProjects(ctx())).rejects.toThrow(/try again in \d+s/i)
  })
})

// =============================================================================
// REGRESSION: expectedUpdatedAt was unobtainable (audit finding F7)
// =============================================================================

describe('REGRESSION: get_recon_settings returns the concurrency token', () => {
  test('updatedAt is returned so expectedUpdatedAt can be passed back', async () => {
    // update_recon_settings' own description says "Read get_recon_settings
    // first ... pass expectedUpdatedAt from a prior read". updatedAt is
    // classified 'identity' in the allowlist, so it was excluded from the
    // select and the anti-clobber control was dead in its documented flow.
    const when = new Date('2026-09-13T10:00:00.000Z')
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 25, updatedAt: when })

    const r = await getReconSettings(ctx(), 'p1')
    expect(r.updatedAt).toBe('2026-09-13T10:00:00.000Z')
  })

  test('updatedAt is METADATA, not smuggled into the settings object', async () => {
    // It must not look settable: it is not in the allowlist and a write to it
    // would be refused.
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 25, updatedAt: new Date() })

    const r = await getReconSettings(ctx(), 'p1')
    expect(r.settings).not.toHaveProperty('updatedAt')
  })
})

// =============================================================================
// REGRESSION: graph_summary sampled liveGraphState BEFORE the counts (F8)
// =============================================================================

describe('REGRESSION: the live-graph state is sampled AFTER the counts', () => {
  test('a scan starting mid-call reports scan_running, not stable', async () => {
    // Sampling first meant a scan that began between the state read and the
    // count read was reported `stable` alongside mid-wipe near-zero counts -
    // the exact false negative the field exists to prevent. Reading it after
    // makes the same race over-warn instead.
    h.busy.mockResolvedValue(null)
    h.fetch.mockImplementation(async () => {
      // The scan starts while the counts are being read.
      h.busy.mockResolvedValue('a full recon scan is running')
      return { ok: true, json: async () => ({ nodes: [], relationships: [] }) }
    })

    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('scan_running')
    expect(r.warning).toBeTruthy()
  })
})
