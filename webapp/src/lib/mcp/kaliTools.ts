/**
 * The MCP exec tools: kali_exec, kali_output, kali_cancel.
 *
 * These are the only tools on this surface that reach a live third-party target
 * outside a scan, so they carry containment the read tools do not need:
 *
 *  - FOUR independent switches, all of which must be on, each owned by a
 *    different decision-maker so no single compromise turns this on:
 *      1. MCP_KALI_EXEC_ENABLED  - the operator, once per deployment.
 *      2. the `kali:exec` scope  - the user, password-confirmed at mint time.
 *      3. project.mcpKaliExecEnabled - a human in the project form, per
 *         engagement. DENIED to update_recon_settings by name, so a token can
 *         never grant itself this.
 *      4. a configured target    - an unconfigured project refuses rather than
 *         running unchecked, because there is nothing to check against.
 *  - ADMISSION IS SERVER-SIDE, in the agent (kali_exec_guard.py). Nothing here
 *    inspects or rewrites the command, deliberately: a check in this file would
 *    be a second copy of the rules, and the copy that drifts is the one that
 *    lets something through.
 *  - THE COMMAND IS AUDITED VERBATIM, on refusal too. A refused command is the
 *    signal that someone is probing the boundary, and it is the only record of
 *    what they tried.
 *
 * Inside the product `kali_shell` is gated by a human clicking through the
 * DANGEROUS_TOOLS confirmation. An MCP caller has no human, which is why the
 * allowlist exists and why the default token cannot do this at all.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { kaliExec, kaliJobCancel, kaliJobStatus, type KaliJob } from '@/lib/mcp/kaliClient'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

/**
 * Default OFF, like MCP_SERVER_ENABLED and for the same reason: a surface that
 * reaches a target must be switched on deliberately, never inherited by
 * upgrading. Enabling the MCP server must not silently enable this too.
 */
export function kaliExecEnabled(): boolean {
  return process.env.MCP_KALI_EXEC_ENABLED === 'true' || process.env.MCP_KALI_EXEC_ENABLED === '1'
}

function assertEnabled(): void {
  if (!kaliExecEnabled()) {
    throw new McpToolError(
      'Sandbox commands are disabled on this RedAmon deployment. An operator enables them ' +
      'with MCP_KALI_EXEC_ENABLED=true.',
      'disabled'
    )
  }
}

/**
 * The per-project half of the switch, set by a human in the project form.
 *
 * `mcpKaliExecEnabled` is DENIED to update_recon_settings by name (reason
 * 'escalation'), so a token can never turn on its own ability to run commands.
 * That is the whole point of it being a column rather than another scope: the
 * deployment switch is one operator decision for the whole install, and this is
 * a per-engagement one.
 *
 * Fails CLOSED on a missing row: a project that cannot be read is not a project
 * that opted in.
 */
async function assertProjectOptedIn(projectId: string): Promise<void> {
  const row = await prisma.project.findUnique({
    where: { id: projectId },
    select: { mcpKaliExecEnabled: true },
  })
  if (!row?.mcpKaliExecEnabled) {
    throw new McpToolError(
      'Sandbox commands are not enabled for this project. Turn on "Allow MCP sandbox commands" ' +
      'in the project settings first. A token cannot enable it.',
      'project_opt_out'
    )
  }
}

const MAX_COMMAND_CHARS = 2000

/** Mirrors the agent's KALI_EXEC_MAX_WAIT so the advertised bound is the real one. */
const MAX_WAIT_SECONDS = 60

function auditExec(
  ctx: McpContext,
  projectId: string,
  action: string,
  after: Record<string, unknown>
): void {
  void writeAudit({
    actorId: ctx.token.userId,
    action,
    targetType: 'project',
    targetId: projectId,
    after: { tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix, ...after },
    source: 'mcp',
  })
}

/** The wire shape, with the note a caller needs to act on an unfinished job. */
function jobResult(projectId: string, job: KaliJob): Record<string, unknown> {
  const running = job.status === 'running'
  return {
    projectId,
    jobId: job.jobId,
    status: job.status,
    exitCode: job.exitCode,
    output: job.output,
    // Always returned, so resuming never depends on the caller counting bytes.
    nextCursor: job.nextCursor,
    ...(job.truncated ? { truncated: true } : {}),
    ...(job.command ? { command: job.command } : {}),
    note: running
      ? 'Still running. Call kali_output with this jobId and nextCursor for more, or ' +
        'kali_cancel to stop it.'
      : job.truncated
        ? 'Output continues. Call kali_output with this jobId and nextCursor for the rest.'
        : 'Finished. A non-zero exitCode is the TOOL failing, not RedAmon refusing.',
  }
}

export async function execCommand(
  ctx: McpContext,
  projectId: string,
  command: string,
  waitSeconds?: number
) {
  requireScope(ctx.token, 'kali:exec')
  assertEnabled()
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  await assertProjectOptedIn(projectId)

  const trimmed = typeof command === 'string' ? command.trim() : ''
  if (!trimmed) throw new McpToolError('A command is required.', 'bad_args')
  // Checked here as well as in the guard so an oversized body is refused before
  // it is written to an audit row.
  if (trimmed.length > MAX_COMMAND_CHARS) {
    throw new McpToolError(
      `The command is longer than ${MAX_COMMAND_CHARS} characters.`,
      'bad_args'
    )
  }
  if (waitSeconds !== undefined && (!Number.isFinite(waitSeconds) || waitSeconds < 0)) {
    throw new McpToolError('waitSeconds must be a positive number.', 'bad_args')
  }

  enforceRate(ctx, 'exec')

  let job: KaliJob
  try {
    job = await kaliExec(projectId, trimmed, waitSeconds)
  } catch (err) {
    // Audited BEFORE rethrowing: a refusal is the only record that someone
    // tried to reach outside their scope, and it is the more interesting half.
    auditExec(ctx, projectId, 'mcp.kali_exec.refused', {
      command: trimmed,
      reason: err instanceof McpToolError ? (err.code ?? 'error') : 'error',
    })
    throw err
  }

  auditExec(ctx, projectId, 'mcp.kali_exec', {
    // The admitted, re-quoted form: what actually ran, not what was typed.
    command: job.command ?? trimmed,
    jobId: job.jobId,
    status: job.status,
  })
  return jobResult(projectId, job)
}

export async function readCommandOutput(
  ctx: McpContext,
  projectId: string,
  jobId: string,
  cursor?: number
) {
  requireScope(ctx.token, 'kali:exec')
  assertEnabled()
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  await assertProjectOptedIn(projectId)
  if (!jobId) throw new McpToolError('A jobId is required.', 'bad_args')
  if (cursor !== undefined && (!Number.isInteger(cursor) || cursor < 0)) {
    throw new McpToolError('cursor must be a whole number of bytes, or omitted.', 'bad_args')
  }
  // The cheap bucket: polling a slow command must not consume the exec budget,
  // or watching one command would cost the same as starting another.
  enforceRate(ctx, 'read')

  return jobResult(projectId, await kaliJobStatus(projectId, jobId, cursor ?? 0))
}

export async function cancelCommand(ctx: McpContext, projectId: string, jobId: string) {
  requireScope(ctx.token, 'kali:exec')
  assertEnabled()
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  await assertProjectOptedIn(projectId)
  if (!jobId) throw new McpToolError('A jobId is required.', 'bad_args')
  enforceRate(ctx, 'write')

  const job = await kaliJobCancel(projectId, jobId)
  auditExec(ctx, projectId, 'mcp.kali_cancel', { jobId, status: job.status })
  return jobResult(projectId, job)
}

export { MAX_COMMAND_CHARS, MAX_WAIT_SECONDS }
