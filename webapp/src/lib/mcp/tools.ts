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
import { execCypher, graphSchemaDoc, nlQuery, type GraphRecords } from '@/lib/mcp/graphClient'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export interface McpContext {
  token: ResolvedMcpToken
}

/** Enforce a bucket, reporting when to retry rather than failing generically. */
export function enforceRate(
  ctx: McpContext,
  bucket: Parameters<typeof checkRateLimit>[0],
  scopeKey = ''
): void {
  const d = checkRateLimit(bucket, ctx.token.tokenId, scopeKey)
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
  return await resp.json()
}

export async function getReconSettings(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  // Selected BY the allowlist, so no credential-bearing column is ever loaded,
  // let alone returned.
  const row = await prisma.project.findUnique({
    where: { id: projectId },
    select: reconSettingsSelect(),
  })
  if (!row) throw new McpToolError('Project not found', 'not_found')
  return { projectId, settings: projectReconSettings(row as Record<string, unknown>) }
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

  const [liveGraphState, version] = await Promise.all([
    resolveLiveGraphState(projectId),
    prisma.scanVersion.findFirst({
      where: { projectId, isCurrent: true },
      select: { id: true, seq: true, label: true, createdAt: true },
    }),
  ])

  const summary = await summaryCounts(ctx, projectId)

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
  const { agentBaseUrl } = await import('@/lib/agentFetch')
  const { internalKeyHeaders } = await import('@/lib/agentAuth')

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
