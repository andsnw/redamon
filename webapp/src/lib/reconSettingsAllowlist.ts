/**
 * Filtering and validation for the recon-settings allowlist.
 *
 * The allowlist and the full-column classification map live in
 * `reconSettingsAllowlist.generated.ts` beside this file; this module is the
 * logic that uses them. The split keeps a 700-line data table out of the way of
 * the rules that make it a control.
 *
 * Fail-closed in both directions: an unknown key rejects the whole call naming
 * the key, and an out-of-range value rejects it naming the bound. Nothing is
 * silently stripped or clamped, because a caller who believes a setting was
 * applied when it was not will act on a scan configured differently from the
 * one they asked for.
 */
import {
  RECON_SETTINGS_ALLOWLIST,
  RECON_SETTINGS_DENYLIST,
  DENY_REASON_DOC,
  type AllowedSetting,
  type DenyReason,
} from '@/lib/reconSettingsAllowlist.generated'

export {
  RECON_SETTINGS_ALLOWLIST,
  RECON_SETTINGS_DENYLIST,
  DENY_REASON_DOC,
  type AllowedSetting,
  type DenyReason,
}

/** Pipeline phases, mirroring ScanModulesSection's SCAN_MODULE_OPTIONS. */
export const SCAN_MODULE_VALUES = Object.freeze([
  'domain_discovery',
  'port_scan',
  'http_probe',
  'resource_enum',
  'vuln_scan',
  'js_recon',
])

/** Nuclei / takeover severity vocabulary. */
export const SEVERITY_VALUES = Object.freeze([
  'info', 'low', 'medium', 'high', 'critical', 'unknown',
])

const STATUS_CODE_FIELD = /(StatusCodes|MatchCodes|FilterCodes)$/

/**
 * The closed vocabulary a list field accepts, or `null` when its members are
 * free-form HTTP status codes rather than a fixed set.
 *
 * Shared by the validator below and by `describe_recon_settings`, so the values
 * a caller is TOLD it may use and the values it is actually allowed to write
 * cannot drift apart.
 */
export function settingValues(key: string, spec: AllowedSetting): readonly string[] | null {
  if (spec.kind === 'enum-list') return SCAN_MODULE_VALUES
  if (spec.kind === 'string-list') return STATUS_CODE_FIELD.test(key) ? null : SEVERITY_VALUES
  return null
}

export const ALLOWED_SETTING_KEYS: readonly string[] = Object.freeze(
  Object.keys(RECON_SETTINGS_ALLOWLIST).sort()
)

export function isAllowedSetting(key: string): boolean {
  return Object.prototype.hasOwnProperty.call(RECON_SETTINGS_ALLOWLIST, key)
}

export interface SettingsRejection {
  ok: false
  key: string
  error: string
}

export interface SettingsAccepted {
  ok: true
  /** Only the allowlisted, validated keys. Safe to spread into prisma.update. */
  data: Record<string, unknown>
}

export type SettingsValidation = SettingsAccepted | SettingsRejection

function explainDenied(key: string): string {
  const reason = RECON_SETTINGS_DENYLIST[key] as DenyReason | undefined
  if (reason) {
    return `'${key}' cannot be changed over MCP: ${DENY_REASON_DOC[reason]}.`
  }
  // Not in either table: a Prisma column added since this file was last
  // classified, or simply not a column at all. Both refuse.
  return `'${key}' is not a settable recon setting.`
}

function validateOne(key: string, spec: AllowedSetting, value: unknown): string | null {
  switch (spec.kind) {
    case 'boolean':
      return typeof value === 'boolean' ? null : `'${key}' must be true or false.`
    case 'number': {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        return `'${key}' must be a number.`
      }
      if (!Number.isInteger(value)) return `'${key}' must be a whole number.`
      if (value < spec.min || value > spec.max) {
        return `'${key}' must be between ${spec.min} and ${spec.max}.`
      }
      return null
    }
    case 'enum-list': {
      if (!Array.isArray(value)) return `'${key}' must be an array.`
      const allowed = settingValues(key, spec) ?? SCAN_MODULE_VALUES
      for (const v of value) {
        if (typeof v !== 'string' || !allowed.includes(v)) {
          return `'${key}' contains an unknown value. Allowed: ${allowed.join(', ')}.`
        }
      }
      return null
    }
    case 'string-list': {
      if (!Array.isArray(value)) return `'${key}' must be an array.`
      const vocabulary = settingValues(key, spec)
      for (const v of value) {
        if (typeof v !== 'string') return `'${key}' must contain only strings.`
        if (vocabulary && !vocabulary.includes(v)) {
          return `'${key}' contains an unknown value. Allowed: ${vocabulary.join(', ')}.`
        }
        // Status codes are free-form in the UI but must still be codes, not
        // arbitrary text destined for a command line.
        if (!vocabulary && !/^[0-9]{3}(-[0-9]{3})?$/.test(v)) {
          return `'${key}' must contain HTTP status codes such as "200" or "200-299".`
        }
      }
      return null
    }
  }
}

/**
 * Filter a caller-supplied settings object down to the allowlist, validating
 * every value. Returns the first rejection rather than a list: the whole call
 * is refused either way, and naming one offending key is clearer than a wall.
 */
export function filterReconSettings(input: unknown): SettingsValidation {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, key: '', error: 'settings must be an object.' }
  }
  const entries = Object.entries(input as Record<string, unknown>)
  if (entries.length === 0) {
    return { ok: false, key: '', error: 'settings must contain at least one field.' }
  }

  const data: Record<string, unknown> = {}
  for (const [key, value] of entries) {
    const spec = isAllowedSetting(key) ? RECON_SETTINGS_ALLOWLIST[key] : null
    if (!spec) return { ok: false, key, error: explainDenied(key) }
    const problem = validateOne(key, spec, value)
    if (problem) return { ok: false, key, error: problem }
    data[key] = value
  }
  return { ok: true, data }
}

/**
 * The allowlisted subset of a loaded project row, for `get_recon_settings`.
 * Built by projecting the allowlist over the row, so a credential-bearing field
 * can never appear in the result even if the caller loaded the whole project.
 */
export function projectReconSettings(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of ALLOWED_SETTING_KEYS) {
    if (Object.prototype.hasOwnProperty.call(row, key)) out[key] = row[key]
  }
  return out
}

/** Prisma `select` for loading exactly the allowlisted columns. */
export function reconSettingsSelect(): Record<string, true> {
  const select: Record<string, true> = {}
  for (const key of ALLOWED_SETTING_KEYS) select[key] = true
  return select
}
