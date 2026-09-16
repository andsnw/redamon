/**
 * The named validators the registry points at.
 *
 * The recon-settings surface used to control risk by refusing 586 of 712
 * columns BY NAME. That was a crude proxy for "this value could be dangerous",
 * and wrong in both directions: it refused `nucleiTags`, which is a bug-class
 * filter, while permitting `takeoverRateLimit` to run at 500 rps past a 3 rps
 * engagement ceiling.
 *
 * So the allowlist stops being the control and validation at the point of use
 * becomes it. The precedent already shipped: `sanitize_image_settings()` lets
 * any value be written to a `*DockerImage` column and pins it to the shipped
 * default at scan start. The field is open; the VALUE is controlled.
 *
 * Two postures, and the difference is deliberate:
 *
 *   REJECT AT THE WRITE   for anything a caller could have got right. Rejecting
 *                         names the problem while the caller is still there to
 *                         fix it, and a silently rewritten value means the
 *                         caller believes a setting applied when it did not.
 *
 *   PIN AT SCAN START     for `docker_image` and `project_file`, where the
 *                         column is also written by the webapp, a project
 *                         import and a version restore. Those paths do not come
 *                         through here, so the check that has to hold is the one
 *                         in `recon/project_settings.py`. This layer rejects the
 *                         same values early as a courtesy, not as the control.
 */
import type { RegistryField } from './registry'

/** Pipeline phases, mirroring ScanModulesSection's SCAN_MODULE_OPTIONS. */
export const SCAN_MODULE_VALUES: readonly string[] = Object.freeze([
  'domain_discovery',
  'port_scan',
  'http_probe',
  'resource_enum',
  'vuln_scan',
  'js_recon',
])

/** Nuclei / takeover severity vocabulary. */
export const SEVERITY_VALUES: readonly string[] = Object.freeze([
  'info', 'low', 'medium', 'high', 'critical', 'unknown',
])

/**
 * Headers a caller may not set, whatever the field.
 *
 * Each would change WHERE the request goes or WHAT it carries rather than
 * annotating it: Host re-points a request at a different virtual host,
 * Authorization and Cookie attach a credential the engagement did not
 * authorise, and Proxy-* redirects the whole exchange.
 */
const FORBIDDEN_HEADERS = new Set(['host', 'authorization', 'cookie', 'proxy-authorization'])

/**
 * Directories a path-valued setting may resolve inside.
 *
 * Kept in step with `_PROJECT_FILE_ROOTS` in `recon/project_settings.py`, which
 * is the authoritative copy. This one exists to refuse early rather than to be
 * relied on.
 */
const PROJECT_FILE_ROOTS: readonly string[] = [
  '/app/recon/wordlists',
  '/app/custom_templates',
  '/custom-templates',
  '/usr/share/seclists',
  '/usr/share/wordlists',
  '/usr/share/dirb',
  '/usr/share/dirbuster',
]

/** Resolve `.` and `..` without touching the filesystem. */
function normalisePath(raw: string): string | null {
  if (raw.includes('\0')) return null
  if (!raw.startsWith('/')) return null
  const out: string[] = []
  for (const part of raw.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      if (out.length === 0) return null
      out.pop()
      continue
    }
    out.push(part)
  }
  return '/' + out.join('/')
}

export function isInsideProjectFileRoot(raw: unknown): boolean {
  if (typeof raw !== 'string' || raw.trim() === '') return false
  const resolved = normalisePath(raw.trim())
  if (resolved === null) return false
  return PROJECT_FILE_ROOTS.some(root => resolved === root || resolved.startsWith(root + '/'))
}

export function isSafeFileName(raw: unknown): boolean {
  if (typeof raw !== 'string') return false
  const name = raw.trim()
  if (name === '' || name.includes('\0')) return false
  if (name.includes('/') || name.includes('\\')) return false
  if (name === '.' || name === '..' || name.startsWith('.')) return false
  return true
}

/** One header line, as `Name: value`. */
export function checkHeader(raw: unknown): string | null {
  if (typeof raw !== 'string') return 'must be a string'
  if (/[\r\n]/.test(raw)) {
    // A CR or LF splits one header into two and lets the caller write the rest
    // of the request, which is request splitting rather than configuration.
    return 'must not contain a carriage return or newline'
  }
  if (raw.includes('\0')) return 'must not contain a NUL byte'
  const colon = raw.indexOf(':')
  if (colon <= 0) return "must be 'Name: value'"
  const name = raw.slice(0, colon).trim().toLowerCase()
  if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) return 'has an invalid header name'
  if (FORBIDDEN_HEADERS.has(name) || name.startsWith('proxy-')) {
    return `may not set the '${name}' header, which changes where the request goes or what it carries`
  }
  return null
}

const STATUS_CODE_RE = /^[0-9]{3}(-[0-9]{3})?$/

export interface ValidationContext {
  /** What the field is called, for the message. */
  key: string
  /** Its registry entry. */
  spec: RegistryField
}

/** Validate one scalar against a named validator. Returns a problem or null. */
function checkScalar(validator: string, value: unknown, ctx: ValidationContext): string | null {
  switch (validator) {
    case 'http_header':
      return checkHeader(value)
    case 'project_file':
      return isInsideProjectFileRoot(value) || value === ''
        ? null
        : 'must be an absolute path inside this project\'s wordlist or template directory'
    case 'project_file_name':
      return isSafeFileName(value) ? null : 'must be a plain filename with no directory part'
    case 'status_codes':
      return typeof value === 'string' && STATUS_CODE_RE.test(value)
        ? null
        : 'must be an HTTP status code such as "200" or "200-299"'
    case 'severity':
      return typeof value === 'string' && SEVERITY_VALUES.includes(value)
        ? null
        : `must be one of ${SEVERITY_VALUES.join(', ')}`
    case 'scan_modules':
      return typeof value === 'string' && SCAN_MODULE_VALUES.includes(value)
        ? null
        : `must be one of ${SCAN_MODULE_VALUES.join(', ')}`
    case 'docker_image':
      // Deliberately permissive: the runtime pins a non-allowlisted image to the
      // shipped default, and `get_recon_settings` will echo what was written
      // while the scan runs what was pinned. `preflight_scope_check` is where a
      // caller sees the RESOLVED value.
      return typeof value === 'string' && !/[\s\0]/.test(value)
        ? null
        : 'must be a container image reference with no whitespace'
    case 'json_object':
      return value !== null && typeof value === 'object' ? null : 'must be an object'
    case 'identifier':
      return typeof value === 'string' && /^[A-Za-z0-9._:-]{0,200}$/.test(value)
        ? null
        : 'must be a short identifier'
    case 'hostname':
      return typeof value === 'string' && /^[A-Za-z0-9.*_-]{0,253}$/.test(value)
        ? null
        : 'must be a hostname'
    case 'url':
      return typeof value === 'string' && (value === '' || /^https?:\/\/[^\s]+$/.test(value))
        ? null
        : 'must be an http or https URL'
    case 'port_spec':
      return typeof value === 'string' && /^[0-9,\s-]{0,2000}$/.test(value)
        ? null
        : 'must be a port list or range such as "80,443,8000-8100"'
    case 'free_text':
      if (typeof value !== 'string') return 'must be a string'
      if (value.includes('\0')) return 'must not contain a NUL byte'
      if (value.length > 20000) return 'is longer than 20000 characters'
      return null
    default:
      return `has an unknown validator '${validator}' (a registry bug, not a caller one)`
  }
}

/**
 * Validate one caller-supplied value against its registry entry.
 *
 * Returns a human-readable problem naming the bound or the rule, or null. The
 * message is written for the agent that will read it: an agent refused without
 * being told the bound learns it one call at a time, and because one bad key
 * refuses the whole call, a batch of guesses applies nothing at all.
 */
export function validateValue(key: string, spec: RegistryField, value: unknown): string | null {
  const ctx: ValidationContext = { key, spec }

  switch (spec.type) {
    case 'boolean':
      return typeof value === 'boolean' ? null : 'must be true or false'

    case 'int':
    case 'float': {
      if (typeof value !== 'number' || !Number.isFinite(value)) return 'must be a number'
      if (spec.type === 'int' && !Number.isInteger(value)) return 'must be a whole number'
      if (!spec.bounds) return 'has no bound in the registry (a registry bug, not a caller one)'
      if (value < spec.bounds.min || value > spec.bounds.max) {
        const zero =
          spec.zero_means === 'unlimited'
            ? ' Note that 0 means UNLIMITED here, so it is the most aggressive value, not the safest.'
            : ''
        return `must be between ${spec.bounds.min} and ${spec.bounds.max}.${zero}`
      }
      return null
    }

    case 'string': {
      if (spec.values) {
        return typeof value === 'string' && spec.values.includes(value)
          ? null
          : `must be one of ${spec.values.join(', ')}`
      }
      return checkScalar(spec.validator ?? 'free_text', value, ctx)
    }

    case 'string-list':
    case 'number-list': {
      if (!Array.isArray(value)) return 'must be an array'
      if (value.length > 5000) return 'has more than 5000 entries'
      for (const item of value) {
        if (spec.type === 'number-list') {
          if (typeof item !== 'number' || !Number.isInteger(item)) {
            return 'must contain only whole numbers'
          }
          continue
        }
        if (spec.values) {
          if (typeof item !== 'string' || !spec.values.includes(item)) {
            return `contains an unknown value. Allowed: ${spec.values.join(', ')}`
          }
          continue
        }
        const problem = checkScalar(spec.validator ?? 'free_text', item, ctx)
        if (problem) return `contains an entry that ${problem}`
      }
      return null
    }

    case 'json':
      return checkScalar(spec.validator ?? 'json_object', value, ctx)

    case 'datetime':
      // Not a pipeline parameter in practice; every datetime column is closed.
      return typeof value === 'string' && !Number.isNaN(Date.parse(value))
        ? null
        : 'must be an ISO 8601 timestamp'

    default:
      return `has an unhandled type '${spec.type}' (a registry bug, not a caller one)`
  }
}
