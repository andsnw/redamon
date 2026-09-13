/**
 * The two tools that explain the recon pipeline rather than reading a project.
 *
 * `update_recon_settings` is a 126-field API whose only reference manual was
 * `get_recon_settings`, which returns key names and current values: no meaning,
 * no type, no bounds, no enum domains, no grouping. An agent learned a bound by
 * being refused, one field at a time, and because one bad key refuses the WHOLE
 * call, a batch of guesses applied nothing at all.
 *
 * Both tools follow the `graph_schema` shape: no projectId, no database, no
 * tenant data. They are derived from constants in this build, so they still
 * answer when Neo4j and Postgres are down.
 *
 * Neither is new data. `RECON_SETTINGS_ALLOWLIST` already carries `kind`, `min`
 * and `max` for all 126 settable fields, and `RECON_PARAMETER_CATALOG` already
 * documents them in prose written for a model (it feeds the AI preset
 * generator). This is the join, filtered to what a token may actually set.
 */
import { RECON_PARAMETER_CATALOG } from '@/lib/recon-preset-schema'
import {
  ALLOWED_SETTING_KEYS,
  RECON_SETTINGS_ALLOWLIST,
  RECON_SETTINGS_DENYLIST,
  DENY_REASON_DOC,
  SCAN_MODULE_VALUES,
  SEVERITY_VALUES,
  settingValues,
  type DenyReason,
} from '@/lib/reconSettingsAllowlist'
import { RECON_PRESETS, getPresetById, type ReconPreset } from '@/lib/recon-presets'
import { requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

// --- the settings reference -----------------------------------------------------

export interface SettingDoc {
  key: string
  kind: string
  min?: number
  max?: number
  /** The closed set of values a list field accepts, when it has one. */
  values?: readonly string[]
  meaning?: string
}

export interface SettingGroup {
  group: string
  settings: SettingDoc[]
}

interface CatalogEntry {
  section: string
  meaning: string
}

/**
 * Parse `RECON_PARAMETER_CATALOG` into key -> {section, meaning}.
 *
 * The catalog is `## Section` headings over `- key: type - meaning` lines, with
 * the meaning genuinely optional (`- gauMaxUrls: integer`). Parsed rather than
 * re-authored because a second copy of 474 descriptions is a second copy to
 * drift.
 */
function parseCatalog(): Map<string, CatalogEntry> {
  const out = new Map<string, CatalogEntry>()
  let section = 'Other'
  for (const raw of RECON_PARAMETER_CATALOG.split('\n')) {
    const line = raw.trim()
    if (line.startsWith('## ')) {
      section = line.slice(3).trim()
      continue
    }
    const m = /^-\s+([A-Za-z0-9_]+):\s*[^-]*?(?:\s+-\s+(.*))?$/.exec(line)
    if (m) out.set(m[1], { section, meaning: (m[2] ?? '').trim() })
  }
  return out
}

let cachedGroups: SettingGroup[] | null = null

/** Every settable field, joined to its documentation, grouped by catalog section. */
export function settingGroups(): SettingGroup[] {
  if (cachedGroups) return cachedGroups
  const catalog = parseCatalog()
  const bySection = new Map<string, SettingDoc[]>()

  // Driven by the ALLOWLIST, never by the catalog. The catalog is a superset
  // covering 474 parameters, most of which this surface denies; returning those
  // would advertise settings the caller cannot set and hand it a map of the
  // denied surface at the same time.
  for (const key of ALLOWED_SETTING_KEYS) {
    const spec = RECON_SETTINGS_ALLOWLIST[key]
    const doc = catalog.get(key)
    const values = settingValues(key, spec)
    const entry: SettingDoc = {
      key,
      kind: spec.kind,
      ...(spec.kind === 'number' ? { min: spec.min, max: spec.max } : {}),
      ...(values ? { values } : {}),
      ...(doc?.meaning ? { meaning: doc.meaning } : {}),
    }
    const section = doc?.section ?? 'Other'
    const list = bySection.get(section)
    if (list) list.push(entry)
    else bySection.set(section, [entry])
  }

  cachedGroups = [...bySection.entries()].map(([group, settings]) => ({ group, settings }))
  return cachedGroups
}

/** Test seam: the parse is cached because the catalog is constant per build. */
export function __resetCatalogCache(): void {
  cachedGroups = null
}

const PHASE_NOTES: Record<string, string> = {
  domain_discovery: 'Subdomain enumeration and DNS. The phase every later one draws its hosts from.',
  port_scan: 'Port scanning (Naabu, Masscan) and service/banner identification.',
  http_probe: 'HTTP probing and technology fingerprinting of the hosts found so far.',
  resource_enum: 'Crawling, directory fuzzing, parameter and API discovery.',
  vuln_scan: 'Nuclei templates, takeover checks and the CVE / MITRE enrichment that hangs off them.',
  js_recon: 'JavaScript retrieval and analysis, including source maps and secret extraction.',
}

const NOTES = [
  'Configuration is TWO levels, and this is the mistake to avoid. `scanModules` decides which ' +
    'pipeline PHASES run at all; the per-tool `*Enabled` flags decide which tools run inside a ' +
    'phase. Setting one without the other is a silent no-op.',
  'Concretely: with "port_scan" in scanModules but naabuEnabled and masscanEnabled both false, ' +
    'the pipeline logs "skipping port scan phase" and continues. The scan runs, nothing is port ' +
    'scanned, and no result field says why. Enable the phase AND at least one tool in it.',
  'A phase that is not in scanModules does not run whatever its tools are set to.',
  'Sections listed as standalone scanners are not pipeline phases and are not gated by ' +
    'scanModules at all; they are separate jobs.',
  'These are the fields THIS surface may write. The product has many more settings; anything ' +
    'absent here is refused by name, never silently ignored.',
  'Settings apply to the NEXT scan. A scan already running read its settings when it started.',
]

/**
 * The shape of the recon configuration, with no values in it.
 *
 * Deliberately no current values: `get_recon_settings` answers that, and
 * duplicating it means two tools disagree the moment one is cached. This one
 * describes the shape, that one reports the state.
 */
export async function describeReconSettings(ctx: McpContext, args: { group?: string } = {}) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  const all = settingGroups()
  const wanted = args.group?.trim().toLowerCase()
  const groups = wanted
    ? all.filter(g => g.group.toLowerCase().includes(wanted))
    : all

  if (wanted && groups.length === 0) {
    throw new McpToolError(
      `No settings group matches '${args.group}'. Call this tool with no arguments to see the ` +
      `group names.`,
      'bad_args'
    )
  }

  return {
    phases: SCAN_MODULE_VALUES.map(module => ({ module, what: PHASE_NOTES[module] ?? '' })),
    enums: { scanModules: SCAN_MODULE_VALUES, severity: SEVERITY_VALUES },
    groups,
    settableFieldCount: ALLOWED_SETTING_KEYS.length,
    notes: NOTES,
  }
}

// --- the preset catalogue ---------------------------------------------------------

export interface PresetApplicability {
  /** Keys the preset sets that this surface could actually write. */
  appliedCount: number
  deniedCount: number
  deniedByReason: Record<string, number>
  /**
   * True when the denied set includes a field that makes the scan QUIETER.
   * Applying such a preset over MCP would be louder than the preset asked for,
   * while reporting success.
   */
  stealthCritical: boolean
  stealthCriticalFields: string[]
}

/**
 * Fields whose denial changes the engagement RISK of a preset rather than just
 * its thoroughness: the intrusiveness switches and the volume/rate caps.
 * `unbounded` covers the rate limits and max-* caps, `intrusive` the aggression
 * toggles.
 */
const STEALTH_REASONS: ReadonlySet<DenyReason> = new Set<DenyReason>(['intrusive', 'unbounded'])

export function presetApplicability(preset: ReconPreset): PresetApplicability {
  const keys = Object.keys(preset.parameters ?? {})
  let applied = 0
  const deniedByReason: Record<string, number> = {}
  const stealthCriticalFields: string[] = []

  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(RECON_SETTINGS_ALLOWLIST, key)) {
      applied += 1
      continue
    }
    const reason = (RECON_SETTINGS_DENYLIST[key] as DenyReason | undefined) ?? 'not-tuning'
    deniedByReason[reason] = (deniedByReason[reason] ?? 0) + 1
    if (STEALTH_REASONS.has(reason)) stealthCriticalFields.push(key)
  }

  return {
    appliedCount: applied,
    deniedCount: keys.length - applied,
    deniedByReason,
    stealthCritical: stealthCriticalFields.length > 0,
    stealthCriticalFields: stealthCriticalFields.sort().slice(0, 20),
  }
}

function presetRow(p: ReconPreset) {
  return {
    id: p.id,
    name: p.name,
    shortDescription: p.shortDescription,
    targetProfile: p.targetProfile,
    environment: p.environment,
    applicability: presetApplicability(p),
  }
}

/**
 * The 26 curated engagement presets, and how much of each this surface could
 * actually apply.
 *
 * `applicability` is the field that earns its place. A preset's `parameters` is
 * a partial over the WHOLE project form, so between a third and 60% of every
 * preset is denied by class here - and for the stealth presets the denied part
 * IS the stealth: the rate limits, the passive-mode switches, the brute-force
 * toggles. An intersection write would leave the caller louder than the preset
 * it asked for while reporting success, which is why this tool reads and does
 * not write.
 */
export async function listReconPresets(ctx: McpContext, args: { presetId?: string } = {}) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  const id = args.presetId?.trim()
  if (id) {
    const preset = getPresetById(id)
    if (!preset) {
      throw new McpToolError(
        `No preset with id '${id}'. Call this tool with no arguments to list them.`,
        'not_found'
      )
    }
    // The full description only for a named preset: they run to forty-plus
    // lines each, and twenty-six of them at once would dominate the caller's
    // context for no gain.
    return { preset: { ...presetRow(preset), fullDescription: preset.fullDescription } }
  }

  return {
    presets: RECON_PRESETS.map(presetRow),
    deniedReasons: DENY_REASON_DOC,
    notes: [
      'These cannot be applied from here, by design. A preset sets fields across the whole ' +
        'project form, and this surface may only write recon tuning, so applying one would ' +
        'produce a configuration that is neither the preset nor the prior state.',
      'Where stealthCritical is true the denied fields are the ones that make the scan quieter ' +
        '(rate limits, passive mode, brute-force and aggression toggles). Half-applying such a ' +
        'preset would be LOUDER than asking for it. Recommend it to the operator to apply in ' +
        'the UI instead.',
      'update_recon_settings can still set the applicable tuning fields individually; use ' +
        'describe_recon_settings for what those are.',
    ],
  }
}
