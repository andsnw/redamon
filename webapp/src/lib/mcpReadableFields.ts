/**
 * Which `Project` columns an MCP tool may RETURN.
 *
 * The write side has been a positive, frozen, fully-classified set since the
 * surface shipped. The read side had nothing: `get_recon_settings` returns the
 * WRITE allowlist, which quietly conflated "what you may change" with "what you
 * may see". That worked while the settings subset was the only project read.
 *
 * It stops working now, because the surface reads project-adjacent data in
 * several more places, and the 700-column problem is about to repeat in the
 * other direction: someone adds a column holding client information and a read
 * tool with a generous `select` starts returning it.
 *
 * The Rules of Engagement fields make that concrete rather than theoretical.
 * They are all denied for WRITE with the reason "the encoded engagement
 * agreement", and among them are `roeClientContactName`,
 * `roeClientContactEmail`, `roeClientContactPhone` and `roeEmergencyContact` -
 * third-party personal data - plus `roeDocumentData`, a binary blob, and
 * `roeRawText`. A read tool that selected "the RoE" without an explicit field
 * list would hand an external agent a client's phone number.
 *
 * So: readable is a positive set, everything else is unreadable, and a test
 * walks `Prisma.ProjectScalarFieldEnum` so a NEW column is unreadable until
 * someone classifies it. Same shape, same fail-closed cost, and the same
 * staleness that is a feature rather than a bug.
 */
import { RECON_SETTINGS_ALLOWLIST } from '@/lib/reconSettingsAllowlist.generated'

/**
 * Columns readable but NOT writable.
 *
 * Read and write genuinely differ here, which is the whole reason this file is
 * not just an alias for the write allowlist. `targetDomain` is denied for write
 * because changing it points the platform at a new victim; reading it is how a
 * caller knows which engagement it is looking at.
 */
export const READ_ONLY_PROJECT_FIELDS: Readonly<Record<string, string>> = Object.freeze({
  id: 'the project id the caller already holds',
  name: 'the operator\'s own label for the engagement',
  createdAt: 'row age; no engagement content',
  updatedAt: 'the optimistic-concurrency token update_recon_settings asks for',
  // Scope, readable so an agent knows what it is looking at and can refuse work
  // aimed anywhere else. Writable by nobody on this surface.
  targetDomain: 'the engagement target, so a caller can confirm what it is scanning',
  targetIps: 'the engagement target, same reason',
  ipMode: 'which of the two target fields is in use',
  domainBatchMode: 'whether this project scans one domain or many',
})

/**
 * Every `Project` column an MCP tool may return: the recon tuning it may also
 * write, plus the identity and scope fields above.
 */
export const MCP_READABLE_PROJECT_FIELDS: ReadonlySet<string> = Object.freeze(
  new Set<string>([
    ...Object.keys(RECON_SETTINGS_ALLOWLIST),
    ...Object.keys(READ_ONLY_PROJECT_FIELDS),
  ])
)

export function isReadableProjectField(key: string): boolean {
  return MCP_READABLE_PROJECT_FIELDS.has(key)
}

/**
 * Narrow a Prisma `select` to the readable set, naming anything refused.
 *
 * A tool builds its own `select`; this is the assertion that it did not reach
 * past the boundary, so the check lives beside the field list rather than in
 * each caller's head.
 */
export function assertReadableSelect(select: Record<string, unknown>, tool: string): void {
  const forbidden = Object.keys(select).filter(k => !isReadableProjectField(k))
  if (forbidden.length > 0) {
    throw new Error(
      `[mcp] ${tool} selects Project column(s) that are not MCP-readable: ` +
      `${forbidden.join(', ')}. Classify them in mcpReadableFields.ts first.`
    )
  }
}
