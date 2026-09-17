/**
 * Registry-driven filtering for the recon-settings surface.
 *
 * This replaces a positive allowlist of 126 columns with four dispositions over
 * all 712, and the replacement is the whole point of the work: blocking a field
 * by name was a crude proxy for "this value could be dangerous", and it was
 * wrong in both directions at once.
 *
 *   settable      write any time
 *   create_only   write once at creation; refused afterwards, naming the tool
 *                 that can set it
 *   tighten_only  the Rules of Engagement: the safe direction only
 *   never         not a pipeline parameter at all; refused with its class
 *
 * Fail-closed in every direction, as before: an unknown key rejects the WHOLE
 * call naming the key, and an out-of-range value rejects it naming the bound.
 * Nothing is silently stripped or clamped, because a caller who believes a
 * setting applied when it did not will act on a scan configured differently
 * from the one it asked for.
 */
import {
  createOnlyFields,
  field,
  fieldsWhere,
  loadRegistry,
  neverFields,
  mcpReadableFields,
  settableFields,
  tightenOnlyFields,
  type RegistryField,
} from './registry'
import { validateValue } from './validators'

export type SettingsMode = 'update' | 'create'

export interface SettingsRejection {
  ok: false
  key: string
  error: string
}

export interface SettingsAccepted {
  ok: true
  /** Only the permitted, validated keys. Safe to spread into prisma.update. */
  data: Record<string, unknown>
}

export type SettingsValidation = SettingsAccepted | SettingsRejection

/** Why each closed class is closed, for the error message and the docs. */
export const DENY_REASON_DOC: Readonly<Record<string, string>> = Object.freeze({
  identity: 'row identity and audit columns, which configure nothing',
  internal: 'internal state written by the application, not a setting',
  escalation: 'would let a token grant itself a capability it was not issued',
  secret: 'a stored credential; reading or rewriting it is credential theft, not tuning',
  'upload-managed':
    'written only by the endpoint that also places the file on disk, so a second ' +
    'writer could name a file this project never uploaded',
})

/** Every key a caller may write in this mode. */
export function permittedKeys(mode: SettingsMode): string[] {
  if (mode === 'create') {
    return fieldsWhere(f => f.mcp !== 'never').map(f => f.key)
  }
  return settableFields().map(f => f.key)
}

export function settableFieldCount(): number {
  return settableFields().length
}

/**
 * Why this key cannot be written at all, ahead of any question about its value.
 *
 * Disposition before validation, deliberately: telling a caller that
 * `roeEnabled` "must be true or false" when it may not change it at all sends
 * it away to fix the wrong thing.
 */
function explainRefusal(
  key: string,
  spec: RegistryField,
  mode: SettingsMode,
  allowTighten: boolean
): string | null {
  if (spec.mcp === 'never') {
    const reason = spec.deny_reason ? DENY_REASON_DOC[spec.deny_reason] : undefined
    const written = spec.written_by ? ` It is written by ${spec.written_by}.` : ''
    return `'${key}' is not a pipeline parameter: ${reason ?? 'it configures nothing about a scan'}.${written}`
  }
  if (mode === 'create') return null
  if (spec.mcp === 'create_only') {
    return (
      `'${key}' is part of this project's engagement scope and is fixed at creation. ` +
      `Changing it on an existing project would re-point the platform at a different ` +
      `target, so it is refused here; use create_project to open a new engagement.`
    )
  }
  if (spec.mcp === 'tighten_only' && !allowTighten) {
    return (
      `'${key}' is part of this project's Rules of Engagement, which this permission ` +
      `does not change. Use tighten_engagement_roe, which may only move the engagement ` +
      `in the safe direction.`
    )
  }
  return null
}

/**
 * Is this a permitted move for a tighten-only field?
 *
 * The one direction rule that survives, and it is there to serve the goal
 * rather than to restrict it: the point is a pipeline that cannot exceed its
 * engagement, and an agent that can raise its own rate ceiling mid-run does not
 * have one. An agent that discovers a STRICTER rule applies it immediately; one
 * that wants more room asks a human.
 */
export function checkTighten(
  key: string,
  spec: RegistryField,
  current: unknown,
  next: unknown
): string | null {
  const direction = spec.tighten
  switch (direction) {
    case 'decrease': {
      if (typeof next !== 'number' || typeof current !== 'number') return null
      if (key === 'roeGlobalMaxRps' && current > 0 && next === 0) {
        return (
          `'${key}' may not go back to 0 once a ceiling has been set: 0 means NO ceiling, ` +
          `so that would remove the engagement's rate limit entirely.`
        )
      }
      // Setting a ceiling where there was none is a tightening, whatever the
      // arithmetic says: 0 means unlimited.
      if (current === 0) return null
      return next <= current
        ? null
        : `'${key}' may only decrease after creation (currently ${current}).`
    }
    case 'increase': {
      if (typeof next !== 'number' || typeof current !== 'number') return null
      return next >= current
        ? null
        : `'${key}' may only increase after creation (currently ${current}).`
    }
    case 'superset': {
      if (!Array.isArray(next) || !Array.isArray(current)) return null
      const have = new Set(next.map(String))
      const lost = current.map(String).filter(v => !have.has(v))
      return lost.length === 0
        ? null
        : `'${key}' may only grow after creation; this would remove ${lost.slice(0, 5).join(', ')}.`
    }
    case 'true_to_false':
      if (typeof next !== 'boolean' || typeof current !== 'boolean') return null
      return current === true && next === false
        ? null
        : current === next
          ? null
          : `'${key}' may only go from true to false after creation.`
    case 'false_to_true':
      if (typeof next !== 'boolean' || typeof current !== 'boolean') return null
      return current === false && next === true
        ? null
        : current === next
          ? null
          : `'${key}' may only go from false to true after creation.`
    case 'narrow':
      // A time window or a free-text field: no machine-checkable direction, so
      // the write is allowed and the audit row is what records it.
      return null
    default:
      return null
  }
}

/**
 * Filter a caller-supplied settings object, validating every value.
 *
 * Returns the FIRST rejection rather than a list: the whole call is refused
 * either way, and naming one offending key is clearer than a wall of them.
 *
 * `allowTighten` is off by default, and that is a permission boundary rather
 * than a convenience: `recon:settings` tunes a pipeline, and changing the
 * engagement agreement is a different act under a different permission. With it
 * on, `current` is required, because permitting a move whose direction could
 * not be checked is the one failure this layer cannot afford.
 */
/** The most fields one write may carry. See the check in `filterReconSettings`. */
export const MAX_KEYS_PER_CALL = 200

export function filterReconSettings(
  input: unknown,
  options: {
    mode?: SettingsMode
    current?: Record<string, unknown>
    allowTighten?: boolean
    /**
     * Whose project this write is for. The `project_file` validator needs it
     * because the upload directory is shared between projects; without it no
     * upload path is accepted.
     */
    projectId?: string
  } = {}
): SettingsValidation {
  const mode = options.mode ?? 'update'

  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, key: '', error: 'settings must be an object.' }
  }
  const entries = Object.entries(input as Record<string, unknown>)
  if (entries.length === 0) {
    return { ok: false, key: '', error: 'settings must contain at least one field.' }
  }
  // Per-value bounds do not bound a CALL. There are over 700 columns and the
  // free-text ones accept 20,000 characters each, so an unbounded key count is
  // a multi-megabyte row written by one request. No real caller writes more
  // than a handful of settings at once.
  if (entries.length > MAX_KEYS_PER_CALL) {
    return {
      ok: false,
      key: '',
      error:
        `${entries.length} fields in one call; at most ${MAX_KEYS_PER_CALL} may be written ` +
        'at a time. Split the batch.',
    }
  }

  const data: Record<string, unknown> = {}
  for (const [key, value] of entries) {
    const spec = field(key)
    if (!spec) {
      return {
        ok: false,
        key,
        error:
          `'${key}' is not a recon setting. Call describe_recon_settings for the ` +
          `fields this surface accepts and their bounds.`,
      }
    }

    const refusal = explainRefusal(key, spec, mode, options.allowTighten ?? false)
    if (refusal) return { ok: false, key, error: refusal }

    const problem = validateValue(key, spec, value, options.projectId)
    if (problem) return { ok: false, key, error: `'${key}' ${problem}` }

    if (spec.mcp === 'tighten_only' && mode === 'update') {
      if (!options.current) {
        return {
          ok: false,
          key,
          error:
            `'${key}' may only be tightened, and the direction cannot be checked ` +
            `without the project's current values.`,
        }
      }
      const direction = checkTighten(key, spec, options.current[key], value)
      if (direction) return { ok: false, key, error: direction }
    }

    data[key] = value
  }
  return { ok: true, data }
}

/**
 * The settings subset of a loaded project row, for `get_recon_settings`.
 *
 * Built by projecting the registry over the row, so a credential-bearing column
 * can never appear in the result even if the caller loaded the whole project.
 *
 * NARROWER than `readableKeys()` on purpose. `id`, `name`, `createdAt` and
 * `updatedAt` are readable and are returned as METADATA by the tools that need
 * them; putting them inside `settings` would make them look settable, and
 * `updatedAt` in particular is the optimistic-concurrency token a caller passes
 * back rather than a value it may write.
 */
export function settingsKeys(): string[] {
  return mcpReadableFields().filter(f => f.mcp !== 'never').map(f => f.key).sort()
}

export function projectReconSettings(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of settingsKeys()) {
    if (Object.prototype.hasOwnProperty.call(row, key)) out[key] = row[key]
  }
  return out
}

/**
 * Columns a caller may READ.
 *
 * Wider than what it may write in one direction and narrower in another. Scope
 * and most of the Rules of Engagement are readable, because an agent that
 * cannot see its own rate ceiling cannot verify that it is inside it. But the
 * RoE block also carries third-party personal data and the signed document
 * itself, and those are withheld from every read whatever their write
 * disposition is.
 */
export function readableKeys(): string[] {
  return mcpReadableFields().map(f => f.key).sort()
}

/** Prisma `select` for loading exactly the columns `get_recon_settings` returns. */
export function reconSettingsSelect(): Record<string, true> {
  const select: Record<string, true> = {}
  for (const key of settingsKeys()) select[key] = true
  return select
}

/** The four disposition sets, for the docs and the tests. */
export function dispositionSummary() {
  return {
    settable: settableFields().length,
    create_only: createOnlyFields().length,
    tighten_only: tightenOnlyFields().length,
    never: neverFields().length,
    total: Object.keys(loadRegistry().fields).length,
  }
}
