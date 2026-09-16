/**
 * The exhaustive settings reference, rendered from the registry.
 *
 * `Project-Settings-Reference.md` is 2,241 hand-written lines with screenshots
 * and a narrative, and it opened by claiming "245+ configurable parameters"
 * when the model has 714. That page keeps its editorial content; this one is the
 * complete table beside it, generated, so the exhaustive answer can never be
 * stale and the prose never has to be exhaustive.
 *
 * Determinism first, for the reason `apiReference.ts` already documents: no
 * dates, no version strings, stable ordering throughout. A generated diff that
 * changes on every run is one people learn to ignore, and this page is only
 * worth having if a diff on it means something.
 */
import {
  fieldsWhere,
  loadRegistry,
  type NamedField,
  type RegistryTool,
} from './registry'

export const SETTINGS_REFERENCE_PAGE = 'Project-Settings-Registry.md'

const CANONICAL_BANNER = [
  '<!-- canonical-banner -->',
  '> 📖 **Canonical version:** read this page on the official docs site — ' +
    '**[https://www.redamon.org/docs/project-settings-registry](https://www.redamon.org/docs/project-settings-registry)**. ' +
    'The GitHub wiki is a mirror.',
  '<!-- canonical-banner -->',
  '',
]

const DISPOSITION_LABEL: Record<string, string> = {
  settable: 'settable',
  create_only: 'create-only',
  tighten_only: 'tighten-only',
  never: 'closed',
}

/** One markdown table cell: pipes and newlines would break the row. */
function cell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ').trim()
}

function boundsCell(f: NamedField): string {
  if (f.bounds) {
    const unit = f.unit === 'none' ? '' : ` ${f.unit}`
    return `${f.bounds.min}–${f.bounds.max}${unit}`
  }
  if (f.values) return f.values.map(v => `\`${v}\``).join(', ')
  if (f.validator) return `\`${f.validator}\``
  if (f.type === 'boolean') return 'true / false'
  return '—'
}

function defaultCell(f: NamedField): string {
  if (!f.has_default) return '—'
  const d = f.default
  if (Array.isArray(d)) return d.length === 0 ? '(empty)' : `\`${JSON.stringify(d).slice(0, 80)}\``
  if (typeof d === 'string') return d === '' ? '(empty)' : `\`${d.slice(0, 80)}\``
  return `\`${String(d)}\``
}

function meaningCell(f: NamedField): string {
  const notes: string[] = []
  if (f.zero_means === 'unlimited') {
    notes.push('**0 means UNLIMITED here, so it is the fastest value and not the safest.**')
  }
  if (f.roe_capped) {
    notes.push('Capped to the engagement rate ceiling at scan start.')
  }
  if (f.fallback === 'falsy') {
    notes.push('An empty value is replaced by the default rather than honoured.')
  }
  if (f.mcp === 'create_only') {
    notes.push('Fixed at project creation; refused on an existing project.')
  }
  if (f.mcp === 'tighten_only') {
    notes.push('May only move in the safe direction after creation.')
  }
  if (f.readable === false) {
    notes.push('Withheld from every read on the MCP surface.')
  }
  return cell([f.meaning, ...notes].join(' '))
}

function toolHeading(id: string, tool: RegistryTool | undefined): string {
  const title = tool?.title ?? id
  const phase = tool?.phase === 'standalone' ? 'standalone' : `phase \`${tool?.phase}\``
  const traffic =
    tool?.traffic === 'none'
      ? 'sends no traffic'
      : tool?.traffic === 'passive'
        ? 'passive traffic'
        : 'active traffic at the target'
  return `### ${title}\n\n*${phase} · ${traffic}*\n`
}

export function renderSettingsReference(): string {
  const registry = loadRegistry()
  const all = fieldsWhere(() => true)
  const byTool = new Map<string, NamedField[]>()
  for (const f of all) {
    const list = byTool.get(f.tool)
    if (list) list.push(f)
    else byTool.set(f.tool, [f])
  }

  const counts = {
    total: all.length,
    settable: all.filter(f => f.mcp === 'settable').length,
    createOnly: all.filter(f => f.mcp === 'create_only').length,
    tightenOnly: all.filter(f => f.mcp === 'tighten_only').length,
    never: all.filter(f => f.mcp === 'never').length,
  }

  const out: string[] = [...CANONICAL_BANNER]
  out.push('# Project Settings Registry')
  out.push('')
  out.push(
    'Every configurable parameter of a RedAmon project, with what it means, what it accepts ' +
    'and whether an external agent may write it. **GENERATED** from ' +
    '`recon_settings/registry.yaml`; a test fails the build when this page and the registry ' +
    'disagree, so it cannot go stale.'
  )
  out.push('')
  out.push(
    `There are **${counts.total}** parameters. ${counts.settable} are settable over the MCP ` +
    `surface at any time, ${counts.createOnly} are fixed when a project is created, ` +
    `${counts.tightenOnly} (the Rules of Engagement) may only be tightened afterwards, and ` +
    `${counts.never} are not pipeline parameters at all.`
  )
  out.push('')
  out.push('For the narrative version with screenshots, see [Project Settings Reference](Project-Settings-Reference).')
  out.push('')
  out.push('## How to read this')
  out.push('')
  out.push(
    '- **Accepts** is the ENFORCED bound, not a suggestion. A value outside it is refused ' +
    'by name rather than clamped, and one bad key refuses a whole batch.'
  )
  out.push(
    '- **Written vs resolved.** Several values are corrected at scan start rather than ' +
    'refused: a rate above the engagement ceiling comes down to the ceiling, a container ' +
    'image outside the shipped set is pinned back to the default, and a wordlist path ' +
    'outside the project directory is dropped. Each is logged with a `[guardrail]` line.'
  )
  out.push(
    '- **Zero is not always the slowest value.** Several rate fields treat `0` as ' +
    'UNLIMITED, which makes it the most aggressive setting available. Those say so.'
  )
  out.push(
    '- **Two levels.** `scanModules` decides which PHASES run; a per-tool `*Enabled` flag ' +
    'decides which tools run inside a phase. Setting one without the other is a silent no-op.'
  )
  out.push('')

  const toolIds = [...byTool.keys()].sort((a, b) => {
    const at = registry.tools[a]?.title ?? a
    const bt = registry.tools[b]?.title ?? b
    return at.localeCompare(bt)
  })

  out.push('## Contents')
  out.push('')
  for (const id of toolIds) {
    const title = registry.tools[id]?.title ?? id
    const anchor = title.toLowerCase().replace(/[^a-z0-9 -]/g, '').replace(/ /g, '-')
    out.push(`- [${title}](#${anchor}) (${byTool.get(id)!.length})`)
  }
  out.push('')
  out.push('---')
  out.push('')

  for (const id of toolIds) {
    out.push(toolHeading(id, registry.tools[id]))
    out.push('| Field | Accepts | Default | MCP | Meaning |')
    out.push('| --- | --- | --- | --- | --- |')
    for (const f of byTool.get(id)!.sort((a, b) => a.key.localeCompare(b.key))) {
      out.push(
        `| \`${f.key}\` | ${boundsCell(f)} | ${defaultCell(f)} | ` +
        `${DISPOSITION_LABEL[f.mcp]} | ${meaningCell(f)} |`
      )
    }
    out.push('')
  }

  return out.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n'
}

/** The parameter count the narrative page must agree with. */
export function parameterCount(): number {
  return fieldsWhere(() => true).length
}
