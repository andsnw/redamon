/**
 * The four tools that open, tighten, authorize and verify an engagement.
 *
 * Together they close the gap between "an agent can configure every parameter of
 * the pipeline" and "an agent can stand up a project that provably cannot
 * violate its scope". Configuring was already possible; the rest was not, and a
 * pipeline whose compliance nobody can check is a pipeline nobody should point
 * at a third party.
 *
 *   create_project                     opens an engagement and fixes its scope
 *   tighten_engagement_roe             narrows one, never widens it
 *   attach_engagement_authorization    records what permitted it
 *   preflight_scope_check              proves the configuration fits
 *
 * Every one of them joins the guards the existing write tools already use, and
 * a tool that skipped one would be a hole in a control that holds everywhere
 * else on this surface: the project-access assertion, a rate-limit bucket, the
 * busy check where a running scan would not see the change, optimistic
 * concurrency, and an audit row.
 *
 * `create_project` is the exception to two of them, and both exceptions are
 * structural rather than convenient: there is no project yet to be busy on and
 * no prior `updatedAt` to compare. What it has instead is an idempotency key,
 * which matters more here than usual because an unattended loop's normal
 * failure path is a retry, and a retry that creates a second project with the
 * same scope is two engagements where the operator authorized one.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { validateDomainBatch, MAX_BATCH_HOSTS } from '@/lib/domainBatch'
import {
  currentAuthorization,
  describeEngagement,
  digestScopeDocument,
  effectiveCeiling,
  isDocumentKind,
  isEngagementKind,
  isSha256,
  loadEngagement,
  DOCUMENT_KINDS,
  ENGAGEMENT_KINDS,
  type EngagementProjectRow,
} from '@/lib/engagement'
import { describeScanWriters } from '@/lib/graphWriters'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'
import { checkTighten, filterReconSettings, reconSettingsSelect } from '@/lib/reconSettings/filter'
import { fieldsWhere, field, loadRegistry } from '@/lib/reconSettings/registry'
import { checkHeader } from '@/lib/reconSettings/validators'

// --- create_project -----------------------------------------------------------------

export interface CreateProjectArgs {
  name: string
  description?: string
  engagementKind: string
  /** Exactly one targeting mode. */
  targetDomain?: string
  targetIps?: string[]
  domainBatchHosts?: string[]
  subdomainList?: string[]
  /** The engagement agreement. Fully writable here and tighten-only afterwards. */
  roe?: Record<string, unknown>
  /** Ordinary tuning, applied at creation so the first scan runs configured. */
  settings?: Record<string, unknown>
  engagementIdentityHeader?: string
  /** Required when engagementKind is third_party. */
  authorization?: AuthorizationArgs
  /**
   * Derived from the authorization digest plus the program handle by the caller.
   * A second call with the same key returns the FIRST project rather than
   * creating another.
   */
  idempotencyKey?: string
}

export interface AuthorizationArgs {
  documentSha256?: string
  /** The scope document itself, when the caller has the text rather than a digest. */
  documentText?: string
  documentKind: string
  sourceUrl?: string
  programHandle?: string
  issuedAt: string
  summary?: string
}

function requireTargetingMode(args: CreateProjectArgs) {
  const modes = [
    args.targetDomain?.trim() ? 'targetDomain' : null,
    args.targetIps?.length ? 'targetIps' : null,
    args.domainBatchHosts?.length ? 'domainBatchHosts' : null,
  ].filter(Boolean) as string[]

  if (modes.length === 0) {
    throw new McpToolError(
      'A project needs exactly one targeting mode: targetDomain, targetIps, or ' +
      'domainBatchHosts. None was given.',
      'bad_args'
    )
  }
  if (modes.length > 1) {
    throw new McpToolError(
      `A project has exactly one targeting mode, and ${modes.join(' and ')} were both given. ` +
      'They are mutually exclusive: the pipeline derives its hosts from one of them.',
      'bad_args'
    )
  }
  return modes[0]
}

function normaliseAuthorization(auth: AuthorizationArgs) {
  if (!isDocumentKind(auth.documentKind)) {
    throw new McpToolError(
      `documentKind must be one of ${DOCUMENT_KINDS.join(', ')}.`,
      'bad_args'
    )
  }
  let digest = auth.documentSha256
  if (!digest && typeof auth.documentText === 'string' && auth.documentText.trim()) {
    digest = digestScopeDocument(auth.documentText)
  }
  if (!isSha256(digest)) {
    throw new McpToolError(
      'documentSha256 must be 64 lower-case hex characters, or pass documentText and it ' +
      'will be digested here. The document itself is never stored.',
      'bad_args'
    )
  }
  const issuedAt = new Date(auth.issuedAt)
  if (Number.isNaN(issuedAt.getTime())) {
    throw new McpToolError('issuedAt must be an ISO 8601 timestamp.', 'bad_args')
  }
  if (issuedAt.getTime() > Date.now() + 60_000) {
    throw new McpToolError('issuedAt is in the future.', 'bad_args')
  }
  return {
    documentSha256: digest,
    documentKind: auth.documentKind,
    sourceUrl: (auth.sourceUrl ?? '').trim(),
    programHandle: auth.programHandle?.trim() || null,
    issuedAt,
    summary: (auth.summary ?? '').trim().slice(0, 500),
  }
}

/**
 * Validate the RoE block a creator supplies.
 *
 * Fully writable here, which is the point: the engagement agreement is set when
 * the engagement opens. Afterwards it is tighten-only, and that asymmetry is
 * what `tighten_engagement_roe` below enforces.
 */
function filterRoeAtCreate(roe: Record<string, unknown>): Record<string, unknown> {
  const tightenOnly = new Set(fieldsWhere(f => f.mcp === 'tighten_only').map(f => f.key))
  const unknown = Object.keys(roe).filter(k => !tightenOnly.has(k))
  if (unknown.length > 0) {
    throw new McpToolError(
      `These are not Rules of Engagement fields: ${unknown.join(', ')}. Ordinary tuning goes ` +
      'in `settings`.',
      'bad_args'
    )
  }
  const result = filterReconSettings(roe, { mode: 'create' })
  if (!result.ok) throw new McpToolError(result.error, 'setting_rejected')
  return result.data
}

export async function createProject(ctx: McpContext, args: CreateProjectArgs) {
  requireScope(ctx.token, 'project:create')
  enforceRate(ctx, 'write')

  const name = (args.name ?? '').trim()
  if (!name) throw new McpToolError('A project needs a name.', 'bad_args')
  if (!isEngagementKind(args.engagementKind)) {
    throw new McpToolError(
      `engagementKind must be one of ${ENGAGEMENT_KINDS.join(', ')}. 'third_party' means ` +
      'somebody else\'s estate and requires a rate ceiling and an authorization record.',
      'bad_args'
    )
  }
  const mode = requireTargetingMode(args)

  // A retried loop tick, a duplicated run or two operators acting at once would
  // otherwise produce two projects with the same scope and two authorization
  // records. Checked BEFORE anything is written.
  if (args.idempotencyKey) {
    const existing = await prisma.engagementAuthorization.findUnique({
      where: { idempotencyKey: args.idempotencyKey },
      select: { projectId: true, project: { select: { userId: true, name: true } } },
    })
    if (existing) {
      if (existing.project.userId !== ctx.token.userId) {
        throw new McpToolError(
          'That idempotency key belongs to another account\'s project.',
          'access_denied'
        )
      }
      return {
        projectId: existing.projectId,
        name: existing.project.name,
        created: false,
        note: 'An earlier call with this idempotency key already created this project.',
      }
    }
  }

  const data: Record<string, unknown> = {
    name,
    description: (args.description ?? '').trim(),
    userId: ctx.token.userId,
    createdById: ctx.token.userId,
    engagementKind: args.engagementKind,
  }

  if (mode === 'targetDomain') {
    data.targetDomain = args.targetDomain!.trim()
  } else if (mode === 'targetIps') {
    data.ipMode = true
    data.targetIps = args.targetIps!.map(s => s.trim()).filter(Boolean)
  } else {
    const hosts = args.domainBatchHosts!.map(s => s.trim()).filter(Boolean)
    const validation = validateDomainBatch(hosts)
    if (validation.errors.length > 0) {
      throw new McpToolError(validation.errors.join(' '), 'bad_args')
    }
    data.domainBatchMode = true
    data.domainBatchHosts = hosts
    // The server re-derives the grouping from the raw host list and discards
    // any client-supplied one. That is a control, not a convenience: the
    // grouping decides the run order and therefore what gets scanned together.
    data.domainBatchGroups = validation.groups
  }

  if (args.subdomainList?.length) {
    data.subdomainList = args.subdomainList.map(s => s.trim()).filter(Boolean)
  }

  if (args.engagementIdentityHeader) {
    const problem = checkHeader(args.engagementIdentityHeader)
    if (problem) {
      throw new McpToolError(`engagementIdentityHeader ${problem}.`, 'setting_rejected')
    }
    data.engagementIdentityHeader = args.engagementIdentityHeader
  }

  if (args.roe) Object.assign(data, filterRoeAtCreate(args.roe))

  if (args.settings) {
    const filtered = filterReconSettings(args.settings, { mode: 'create' })
    if (!filtered.ok) throw new McpToolError(filtered.error, 'setting_rejected')
    Object.assign(data, filtered.data)
  }

  // The rule third_party projects live under, checked BEFORE the row exists so
  // a refused creation leaves nothing behind.
  let authorization: ReturnType<typeof normaliseAuthorization> | null = null
  if (args.authorization) authorization = normaliseAuthorization(args.authorization)

  if (args.engagementKind === 'third_party') {
    const ceiling = effectiveCeiling({
      id: '', engagementKind: 'third_party',
      roeEnabled: Boolean(data.roeEnabled),
      roeGlobalMaxRps: Number(data.roeGlobalMaxRps ?? 0),
    })
    if (ceiling === null) {
      throw new McpToolError(
        'A third_party engagement must declare a request-rate ceiling: set roe.roeEnabled ' +
        'true and roe.roeGlobalMaxRps to a non-zero value. Note that 0 means NO ceiling ' +
        'rather than a slow one.',
        'bad_args'
      )
    }
    if (!authorization) {
      throw new McpToolError(
        'A third_party engagement must record what authorized it: pass `authorization` with ' +
        'the scope document\'s digest, its kind and when it was issued.',
        'bad_args'
      )
    }
  }

  const created = await prisma.$transaction(async tx => {
    const project = await tx.project.create({
      data: data as never,
      select: { id: true, name: true },
    })
    if (authorization) {
      await tx.engagementAuthorization.create({
        data: {
          projectId: project.id,
          ...authorization,
          recordedVia: 'mcp',
          recordedByTokenId: ctx.token.tokenId,
          recordedByUserId: ctx.token.userId,
          idempotencyKey: args.idempotencyKey ?? null,
        },
      })
    }
    return project
  })

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.create_project',
    targetType: 'project',
    targetId: created.id,
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      engagementKind: args.engagementKind,
      targetingMode: mode,
      scope: {
        targetDomain: data.targetDomain ?? null,
        targetIps: data.targetIps ?? null,
        domainBatchHosts: data.domainBatchHosts ?? null,
      },
      roe: args.roe ?? null,
      authorizationDigest: authorization?.documentSha256 ?? null,
    },
    source: 'mcp',
  })

  const engagement = await loadEngagement(created.id)
  return {
    projectId: created.id,
    name: created.name,
    created: true,
    engagement,
    note:
      'Scope is fixed now. update_recon_settings refuses every targeting field on an ' +
      'existing project, so a different target means a different project. Call ' +
      'preflight_scope_check before start_recon.',
  }
}

// --- tighten_engagement_roe ------------------------------------------------------------

export async function tightenEngagementRoe(
  ctx: McpContext,
  projectId: string,
  roe: Record<string, unknown>,
  expectedUpdatedAt?: string
) {
  requireScope(ctx.token, 'project:create')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  enforceRate(ctx, 'write')

  // The same guard update_recon_settings has, and for the same reason: recon
  // reads its settings ONCE at container spawn, so a write during a run is
  // inert and accepting it would report success for a change that does nothing.
  // A tightening that silently did not apply is worse than a refused one.
  const busy = await describeScanWriters(projectId)
  if (busy) {
    throw new McpToolError(
      `Cannot change the Rules of Engagement while ${busy} for this project: the running ` +
      'scan read them when it started and will not see the change. Stop it, or wait.',
      'busy'
    )
  }

  const tightenOnly = new Set(fieldsWhere(f => f.mcp === 'tighten_only').map(f => f.key))
  const unknown = Object.keys(roe ?? {}).filter(k => !tightenOnly.has(k))
  if (unknown.length > 0) {
    throw new McpToolError(
      `These are not Rules of Engagement fields: ${unknown.join(', ')}. Ordinary tuning goes ` +
      'through update_recon_settings.',
      'bad_args'
    )
  }

  const before = await prisma.project.findUnique({
    where: { id: projectId },
    select: { ...reconSettingsSelect(), updatedAt: true },
  })
  if (!before) throw new McpToolError('Project not found', 'not_found')

  const filtered = filterReconSettings(roe, {
    mode: 'update',
    allowTighten: true,
    current: before as Record<string, unknown>,
  })
  if (!filtered.ok) throw new McpToolError(filtered.error, 'setting_rejected')

  if (expectedUpdatedAt) {
    const expected = new Date(expectedUpdatedAt)
    if (Number.isNaN(expected.getTime())) {
      throw new McpToolError('expectedUpdatedAt is not a valid timestamp.', 'bad_args')
    }
    const { count } = await prisma.project.updateMany({
      where: { id: projectId, updatedAt: expected },
      data: filtered.data,
    })
    if (count === 0) {
      throw new McpToolError(
        'The project changed since you read it. Re-read get_recon_settings and retry.',
        'conflict'
      )
    }
  } else {
    await prisma.project.update({ where: { id: projectId }, data: filtered.data })
  }

  const changed = Object.keys(filtered.data)
  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.tighten_roe',
    targetType: 'project',
    targetId: projectId,
    before: Object.fromEntries(changed.map(k => [k, (before as Record<string, unknown>)[k]])),
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      changes: Object.fromEntries(changed.map(k => [k, filtered.data[k]])),
    },
    source: 'mcp',
  })

  return {
    projectId,
    tightened: filtered.data,
    engagement: await loadEngagement(projectId),
    note: 'These apply to the NEXT scan. A run already in progress read them when it started.',
  }
}

// --- attach_engagement_authorization -------------------------------------------------------

export async function attachEngagementAuthorization(
  ctx: McpContext,
  projectId: string,
  auth: AuthorizationArgs
) {
  requireScope(ctx.token, 'engagement:authorize')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  enforceRate(ctx, 'write')

  const record = normaliseAuthorization(auth)
  const previous = await currentAuthorization(projectId)

  const created = await prisma.engagementAuthorization.create({
    data: {
      projectId,
      ...record,
      recordedVia: 'mcp',
      recordedByTokenId: ctx.token.tokenId,
      recordedByUserId: ctx.token.userId,
    },
    select: { id: true, recordedAt: true },
  })

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.attach_authorization',
    targetType: 'project',
    targetId: projectId,
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      authorizationId: created.id,
      documentSha256: record.documentSha256,
      documentKind: record.documentKind,
      programHandle: record.programHandle,
      supersedesId: previous?.id ?? null,
    },
    source: 'mcp',
  })

  return {
    projectId,
    authorizationId: created.id,
    recordedAt: created.recordedAt,
    supersedes: previous?.id ?? null,
    note:
      previous && previous.programHandle && previous.programHandle !== record.programHandle
        ? `This records a DIFFERENT program (${previous.programHandle} -> ` +
          `${record.programHandle}) on an existing project. The earlier record is kept; ` +
          'nothing here re-points the project, and its scope is still the one it was ' +
          'created with.'
        : 'Append-only: the earlier records are kept and nothing was overwritten.',
  }
}

// --- preflight_scope_check -------------------------------------------------------------

interface ResolvedRate {
  field: string
  runtimeKey: string | null
  written: number
  /** After the engagement ceiling is applied at scan start. */
  resolved: number
  capped: boolean
  /** True when the written value was 0 and 0 means unlimited for this field. */
  wasUnlimited: boolean
}

/**
 * Apply the ceiling the way `recon/project_settings.py` does.
 *
 * Deliberately a re-implementation of the same rule rather than a call into it,
 * because this runs in the webapp and that runs in a scan container. The two are
 * kept honest by the golden master on the Python side and by this tool's own
 * tests, and the rule is three lines: a value above the ceiling comes down to
 * it, and a 0 that means unlimited comes down to it too.
 */
function resolveRates(row: Record<string, unknown>, ceiling: number | null): ResolvedRate[] {
  const out: ResolvedRate[] = []
  for (const f of fieldsWhere(s => s.roe_capped)) {
    const written = row[f.key]
    if (typeof written !== 'number') continue
    let resolved = written
    let capped = false
    let wasUnlimited = false
    if (ceiling !== null) {
      if (written === 0 && f.zero_means === 'unlimited') {
        resolved = ceiling
        capped = true
        wasUnlimited = true
      } else if (written > ceiling) {
        resolved = ceiling
        capped = true
      }
    } else if (written === 0 && f.zero_means === 'unlimited') {
      wasUnlimited = true
    }
    out.push({
      field: f.key,
      runtimeKey: f.runtime_key,
      written,
      resolved,
      capped,
      wasUnlimited,
    })
  }
  return out
}

const ALLOWED_IMAGE_SUFFIX = 'DockerImage'

/**
 * Read-only proof that the configured pipeline fits the engagement.
 *
 * Without it "the pipeline respects the scope" is an assertion. With it, it is a
 * diff a person checks in ten seconds, and an agent is expected to call it and
 * report it before `start_recon`.
 *
 * The distinction that earns its place: it reports RESOLVED values, not written
 * ones. `get_recon_settings` echoes what a caller wrote, and for the fields the
 * runtime corrects - a rate above the ceiling, a container image outside the
 * shipped set, a wordlist path outside the project directory - those are two
 * different answers. An agent that only read the first would believe a rejected
 * value was accepted.
 */
export async function preflightScopeCheck(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  // The 'query' bucket rather than 'read': this resolves the whole settings
  // tree, the cap list and the authorization record, which is not the cost of
  // an ordinary read.
  enforceRate(ctx, 'query')

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { ...reconSettingsSelect(), id: true, updatedAt: true },
  })
  if (!project) throw new McpToolError('Project not found', 'not_found')

  const row = project as Record<string, unknown>
  const engagement = await loadEngagement(projectId)
  const authorization = await currentAuthorization(projectId)
  const ceiling = engagement.ceilingRps
  const rates = resolveRates(row, ceiling)

  const registry = loadRegistry()
  const rewritten: { field: string; written: unknown; willRun: unknown; why: string }[] = []

  // A docker image outside the shipped set is accepted at the write and pinned
  // at scan start. This is the only place a caller can see which one will run.
  const allowedImages = new Set(
    Object.entries(registry.fields)
      .filter(([k, f]) => k.endsWith(ALLOWED_IMAGE_SUFFIX) && typeof f.default === 'string' && f.default)
      .map(([, f]) => f.default as string)
  )
  for (const [key, value] of Object.entries(row)) {
    if (!key.endsWith(ALLOWED_IMAGE_SUFFIX) || typeof value !== 'string' || !value) continue
    if (allowedImages.has(value)) continue
    rewritten.push({
      field: key,
      written: value,
      willRun: field(key)?.default ?? null,
      why: 'not in the shipped image allowlist; pinned to the default at scan start',
    })
  }

  for (const f of fieldsWhere(s => s.validator === 'project_file')) {
    const value = row[f.key]
    const entries = Array.isArray(value) ? value : [value]
    for (const entry of entries) {
      if (typeof entry !== 'string' || entry === '') continue
      if (/^\/(?:app\/recon\/wordlists|app\/custom_templates|custom-templates|usr\/share\/(?:seclists|wordlists|dirb|dirbuster))\b/.test(entry)) {
        continue
      }
      rewritten.push({
        field: f.key,
        written: entry,
        willRun: f.default ?? null,
        why: 'outside this project\'s wordlist and template directories; dropped at scan start',
      })
    }
  }

  const scanModules = Array.isArray(row.scanModules) ? (row.scanModules as string[]) : []
  const enabledTools = fieldsWhere((f, key) => /Enabled$/.test(key) && row[key] === true)
    .map(f => ({ field: f.key, tool: f.tool, phase: f.phase, traffic: f.traffic }))

  // A module whose phase is not in scanModules will not run whatever its own
  // flag says. That two-level model is the mistake this surface's docs lead
  // with, and reporting it here turns it into something a caller can see.
  const silentNoOps = enabledTools
    .filter(t => t.phase !== 'standalone' && !scanModules.includes(t.phase))
    .map(t => ({
      field: t.field,
      phase: t.phase,
      why: `enabled, but '${t.phase}' is not in scanModules, so it will not run`,
    }))

  const exceeds = rates.filter(r => ceiling !== null && r.resolved > ceiling)

  return {
    projectId,
    engagement,
    authorization,
    scope: {
      targetDomain: row.targetDomain ?? '',
      targetIps: row.targetIps ?? [],
      domainBatchMode: row.domainBatchMode ?? false,
      domainBatchHosts: row.domainBatchHosts ?? [],
      ipMode: row.ipMode ?? false,
      targetGuardrailEnabled: row.targetGuardrailEnabled ?? false,
      excludedHosts: row.roeExcludedHosts ?? [],
      maxBatchHosts: MAX_BATCH_HOSTS,
    },
    ceilingRps: ceiling,
    resolvedRates: rates,
    ratesExceedingCeiling: exceeds,
    rewrittenAtScanStart: rewritten,
    phases: scanModules,
    enabledTools,
    silentNoOps,
    forbidden: {
      tools: row.roeForbiddenTools ?? [],
      categories: row.roeForbiddenCategories ?? [],
      allowDos: row.roeAllowDos ?? false,
      allowDataExfiltration: row.roeAllowDataExfiltration ?? false,
      maxSeverityPhase: row.roeMaxSeverityPhase ?? null,
    },
    identityHeader: row.engagementIdentityHeader ?? '',
    startable: engagement.blockers.length === 0 && exceeds.length === 0,
    notes: [
      'Values here are RESOLVED, not written. get_recon_settings echoes what you wrote; this ' +
        'reports what the scan will actually run with, which differs wherever a validator or ' +
        'the engagement ceiling rewrites a value.',
      'rewrittenAtScanStart is not an error. A container image outside the shipped set and a ' +
        'wordlist path outside the project directory are both corrected rather than refused, ' +
        'and each is logged with a [guardrail] line during the scan.',
      'silentNoOps is the two-level model biting: a tool can be enabled inside a phase that ' +
        'is not running. The scan succeeds, nothing is scanned by that tool, and no result ' +
        'field says why.',
    ],
  }
}

/** Every authorization ever recorded for a project, newest first. */
export async function listEngagementAuthorizations(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  enforceRate(ctx, 'read')

  const rows = await prisma.engagementAuthorization.findMany({
    where: { projectId },
    orderBy: { recordedAt: 'desc' },
    select: {
      id: true, documentSha256: true, documentKind: true, sourceUrl: true,
      programHandle: true, issuedAt: true, recordedAt: true, recordedVia: true,
      recordedByTokenId: true, summary: true,
    },
  })
  return {
    projectId,
    authorizations: rows,
    note:
      'Append-only. A later record does not replace an earlier one: it says the engagement ' +
      'continued under a new authority from that moment.',
  }
}

export { describeEngagement, type EngagementProjectRow, checkTighten }
