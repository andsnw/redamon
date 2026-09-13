/**
 * The inbound MCP tool surface.
 *
 * Each tool takes an explicit `projectId` and calls `assertMcpProjectAccess`
 * FIRST. A personal access token resolves to exactly one user; there is no
 * admin act-as here, and no tool trusts an identity from its arguments.
 *
 * Two rules run through all of it:
 *
 *  - NEVER report a dependency failure as an empty result. An empty result
 *    means "nothing found". Conflating the two produces a false negative in a
 *    security tool: an agent told "no malicious dependencies" cannot tell
 *    whether the scan ran and found nothing or never ran at all.
 *  - Every outbound call carries an explicit timeout, never an inherited
 *    unbounded default.
 *
 * The tool DESCRIPTIONS are LLM-facing content, not code comments: they are
 * sized for the model that reads them at runtime.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { isActivationInProgress } from '@/lib/activationLock'
import { describeScanWriters } from '@/lib/graphWriters'
import {
  assertMcpProjectAccess,
  checkLlmBudget,
  checkRateLimit,
  requireScope,
  type ResolvedMcpToken,
} from '@/lib/mcpAuth'
import { projectReconSettings, reconSettingsSelect } from '@/lib/reconSettingsAllowlist'
import { McpToolError } from '@/lib/mcp/errors'
import { assertTenantScoped, TenantViolation } from '@/lib/mcp/graphGuard'
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { execCypher, graphSchemaDoc, nlQuery, type GraphRecords } from '@/lib/mcp/graphClient'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export interface McpContext {
  token: ResolvedMcpToken
}

/**
 * Enforce a bucket, reporting when to retry rather than failing generically.
 *
 * `perProject` drops the token from the key. Buckets that exist to protect the
 * CALLER (read/query/write budgets) are per token; the one that exists to
 * protect a RESOURCE - the start bucket, which guards the version retention
 * window - has to be per project, or a user holding N tokens gets N times the
 * documented rate against the same project.
 */
export function enforceRate(
  ctx: McpContext,
  bucket: Parameters<typeof checkRateLimit>[0],
  scopeKey = '',
  opts: { perProject?: boolean } = {}
): void {
  const d = checkRateLimit(bucket, opts.perProject ? '*' : ctx.token.tokenId, scopeKey)
  if (!d.allowed) {
    throw new McpToolError(
      `Rate limit reached for this token. Try again in ${d.retryAfterSeconds}s.`,
      'rate_limited'
    )
  }
}

/**
 * Post-validate a graph result, then hand it back.
 *
 * A tenant violation drops the WHOLE response and audits at error level: a
 * partial answer is indistinguishable from a complete one and would be acted
 * on as if it were.
 */
function guardGraphResult(
  result: GraphRecords,
  ctx: McpContext,
  projectId: string,
  tool: string
): GraphRecords {
  try {
    assertTenantScoped(result.records, ctx.token.userId, projectId)
  } catch (err) {
    if (err instanceof TenantViolation) {
      console.error(
        `[mcp][SECURITY] tenant post-validation failed tool=${tool} ` +
        `token=${ctx.token.tokenPrefix} project=${projectId}`,
        JSON.stringify(err.detail)
      )
      throw new McpToolError('The query result failed a safety check and was discarded.', 'tenant_violation')
    }
    throw err
  }
  return result
}

// --- reads --------------------------------------------------------------------

export async function listProjects(ctx: McpContext) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  // `where: { userId }` is the enumeration boundary: an external agent can
  // never see another user's project ids, so it can never name one.
  const projects = await prisma.project.findMany({
    where: { userId: ctx.token.userId },
    select: {
      id: true, name: true, targetDomain: true, targetIps: true,
      ipMode: true, domainBatchMode: true, updatedAt: true,
    },
    orderBy: { updatedAt: 'desc' },
  })
  return { projects }
}

export async function getReconStatus(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  let resp: Response
  try {
    resp = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/status`)
  } catch (err) {
    console.error('[mcp] orchestrator status unreachable:', err)
    // NOT "idle". The webapp's own /api/recon/[id]/status answers a synthetic
    // idle here, and reporting "not running" for "cannot tell" is exactly the
    // false negative this surface must not produce.
    throw new McpToolError('Scan status is unknown: the orchestrator is unreachable.', 'status_unknown')
  }
  if (!resp.ok) {
    console.error(`[mcp] orchestrator status returned ${resp.status}`)
    throw new McpToolError('Scan status is unknown.', 'status_unknown')
  }
  return projectReconState(await resp.json())
}

/**
 * Project the orchestrator's ReconState onto the fields an external caller
 * needs, dropping the rest.
 *
 * The raw state carries `container_id` and an `error` populated with raw
 * exception text - a Docker SDK failure embeds the deployment's absolute host
 * paths and image names. Returning it verbatim would hand an untrusted agent
 * reconnaissance about the host and then place it in a model's context, which
 * is exactly what errors.ts forbids everywhere else.
 */
function projectReconState(raw: unknown): Record<string, unknown> {
  const s = (raw ?? {}) as Record<string, unknown>
  return {
    status: s.status ?? 'unknown',
    currentPhase: s.current_phase ?? s.currentPhase ?? null,
    phaseNumber: s.phase_number ?? s.phaseNumber ?? null,
    startedAt: s.started_at ?? s.startedAt ?? null,
    completedAt: s.completed_at ?? s.completedAt ?? null,
    // A boolean, never the text: "it failed" is actionable, the exception is not.
    failed: s.status === 'error' || Boolean(s.error),
  }
}

export async function getReconSettings(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  // Selected BY the allowlist, so no credential-bearing column is ever loaded,
  // let alone returned.
  const row = await prisma.project.findUnique({
    where: { id: projectId },
    select: { ...reconSettingsSelect(), updatedAt: true },
  })
  if (!row) throw new McpToolError('Project not found', 'not_found')
  return {
    projectId,
    // Returned as METADATA, not as a setting: update_recon_settings tells the
    // caller to pass it back as `expectedUpdatedAt`, and without it here that
    // anti-clobber control was unreachable through its own documented flow.
    updatedAt: (row as { updatedAt?: Date }).updatedAt?.toISOString() ?? null,
    settings: projectReconSettings(row as Record<string, unknown>),
  }
}

/**
 * What does this project actually contain?
 *
 * Exists because "no results" has two very different causes: the scan ran and
 * the project is clean, or that surface was never scanned. An agent that cannot
 * tell them apart reports the second as the first.
 */
export async function graphSummary(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const version = await prisma.scanVersion.findFirst({
    where: { projectId, isCurrent: true },
    select: { id: true, seq: true, label: true, createdAt: true },
  })

  // Counts FIRST, then the state. Sampling the state first meant a scan that
  // started in between was reported as `stable` alongside mid-wipe near-zero
  // counts - the exact false negative this field exists to prevent. This way
  // the same race over-warns instead: the counts predate the wipe and the
  // state still says the graph is moving.
  const summary = await summaryCounts(ctx, projectId)
  const liveGraphState = await resolveLiveGraphState(projectId)

  return {
    projectId,
    // Prepended deliberately: counts taken during a wipe or a version swap are
    // near-zero, which a reader would otherwise take for "never scanned".
    liveGraphState,
    ...(liveGraphState !== 'stable'
      ? {
          warning:
            'The live graph is being rewritten right now, so these counts are not settled. ' +
            'Re-check once the state is "stable".',
        }
      : {}),
    scanVersion: version,
    nodes: summary.nodes,
    relationships: summary.relationships,
  }
}

export type LiveGraphState = 'stable' | 'scan_running' | 'activating'

export async function resolveLiveGraphState(projectId: string): Promise<LiveGraphState> {
  if (await isActivationInProgress(projectId)) return 'activating'
  if (await describeScanWriters(projectId)) return 'scan_running'
  return 'stable'
}

async function summaryCounts(ctx: McpContext, projectId: string) {
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}/graph/exec`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        op: 'summary',
        user_id: ctx.token.userId,
        project_id: projectId,
        source: 'mcp',
      }),
      signal: AbortSignal.timeout(60_000),
    })
  } catch (err) {
    console.error('[mcp] graph summary transport error:', err)
    // Plain failure, never an empty summary: an empty summary reads as
    // "nothing has ever been scanned".
    throw new McpToolError('The graph service is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) {
    console.error(`[mcp] graph summary failed (${resp.status})`)
    throw new McpToolError('The graph summary could not be read.', 'agent_failed')
  }
  return (await resp.json()) as {
    nodes: { label: string; count: number }[]
    relationships: { type: string; count: number }[]
  }
}

export async function graphSchema(ctx: McpContext) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  // No projectId, no database, no tenant data: it is derived from code, so it
  // still answers when Neo4j and Postgres are down.
  return { schema: await graphSchemaDoc() }
}

export async function queryGraph(
  ctx: McpContext,
  projectId: string,
  args: { question?: string; cypher?: string }
) {
  requireScope(ctx.token, 'recon:read')
  const question = typeof args.question === 'string' ? args.question.trim() : ''
  const cypher = typeof args.cypher === 'string' ? args.cypher.trim() : ''

  if (!!question === !!cypher) {
    throw new McpToolError('Provide exactly one of "question" or "cypher".', 'bad_args')
  }
  if (cypher) requireScope(ctx.token, 'graph:cypher')

  await assertMcpProjectAccess(ctx.token.userId, projectId)

  let result: GraphRecords
  if (question) {
    // The NL path spends the project owner's provider key, so it is budgeted
    // per token on top of the agent's own per-user daily cap.
    enforceRate(ctx, 'query')
    const budget = checkLlmBudget(ctx.token.tokenId)
    if (!budget.allowed) {
      throw new McpToolError(
        `This token's daily query budget (${budget.limit}) is spent. It resets at ${budget.resetsAt}.`,
        'budget_exhausted'
      )
    }
    result = await nlQuery(ctx.token.userId, projectId, question)
  } else {
    enforceRate(ctx, 'read')
    result = await execCypher(ctx.token.userId, projectId, cypher)
  }

  const guarded = guardGraphResult(result, ctx, projectId, 'query_graph')
  return {
    projectId,
    records: guarded.records,
    // Transparency: the caller should see what its question became.
    ...(guarded.cypher ? { cypher: guarded.cypher } : {}),
    ...(guarded.truncated ? { truncated: true } : {}),
  }
}
