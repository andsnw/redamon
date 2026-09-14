/**
 * The operator-facing wording for each token scope.
 *
 * Shared by the token-minting UI and the generated MCP API reference, so the
 * checkbox a person ticks and the page that documents it cannot describe the
 * same permission two different ways.
 *
 * `blurb` is doing two jobs, so the fields are split by AUDIENCE:
 *
 *  - `blurb` is the shared, table-safe text. It becomes ONE MARKDOWN TABLE CELL
 *    in the generated API reference, so it stays to a sentence or two. Changing
 *    it changes `redamon.wiki/MCP-API-Reference.md`, which means `npm run
 *    docs:mcp` has to run in the same change or apiReference.test.ts goes red.
 *  - `detail` and `learnMore` are UI-only. The renderer never prints them, so
 *    adding or editing either needs no regeneration.
 */
import type { McpScope } from '@/lib/mcpAuth'

export interface ScopeCopy {
  label: string
  /** Table-safe. Printed by the generated API reference. Keep it short. */
  blurb: string
  /** The longer UI paragraph, for a permission that needs a real explanation. */
  detail?: string
  /** A wiki deep link, UI-only. */
  learnMore?: { text: string; href: string }[]
  danger?: boolean
}

const WIKI = 'https://github.com/samugit83/redamon/wiki'

/** Each write scope states its consequence, so a tick is an informed one. */
export const MCP_SCOPE_COPY: Record<McpScope, ScopeCopy> = {
  'recon:read': {
    label: 'Read recon + graph',
    blurb: 'List projects, read scan status and settings, and query the attack-surface graph in natural language.',
  },
  'recon:scan': {
    label: 'Start and stop scans',
    blurb: 'Start a full recon pipeline (keeping the current graph as a saved version) and stop the scan running on a project.',
  },
  'recon:overwrite': {
    label: 'Discard the current graph on start',
    blurb: 'Permits starting a scan in overwrite mode, which DISCARDS the current graph instead of saving it as a version. This is the only irreversible action on this surface.',
    danger: true,
  },
  'recon:settings': {
    label: 'Change recon tuning settings',
    blurb: 'Change a narrow allowlist of recon tuning values. It can never change the target, scope, Rules of Engagement or any credential.',
  },
  'triage:read': {
    label: 'Read suppressed findings and remediations',
    blurb: 'Read the findings a person muted as noise, including who muted them and why, and the remediation write-ups (their solutions, evidence summaries and PR status). Muted findings are hidden from every other permission on this surface, so this is the only way an agent can tell "nothing was found" apart from "someone suppressed it". Separate from Read recon + graph on purpose: these are not reachable any other way.',
  },
  'recon:queue': {
    label: 'Queue scans to run later',
    blurb: 'Queue a full recon to start when the machine has room, instead of being refused while the project is busy, and cancel a job it queued. A queued job DISPATCHES LATER and is not cancelled when you revoke this token - use the Activity view or the agent\'s own cancel to stop it. It also appears in your queue attributed to you, with nothing marking it as an agent\'s.',
    danger: true,
  },
  'triage:write': {
    label: 'Record a verdict on a finding',
    blurb: 'Let an agent mark a finding confirmed, likely noise, or back to unreviewed, as if you had clicked it yourself. The verdict is DURABLE: it survives re-scans and stops later AI triage runs from overruling it, and the node records that it arrived over MCP. It cannot mute or unmute anything, and nothing on this surface can undo a verdict except another verdict.',
    danger: true,
  },
  'graph:cypher': {
    label: 'Run raw Cypher',
    blurb: 'Send read-only Cypher directly instead of a natural-language question. Still tenant-scoped and still read-only.',
  },
  'kali:exec': {
    label: 'Run sandbox commands at the target',
    blurb: 'Run single commands from a fixed allowlist of read-only tools (curl, dig, nikto, testssl and similar) in the Kali sandbox. Every command is checked against the project\'s own scope and its excluded-hosts list before it runs, and it is not a shell: pipelines, redirection and any tool that can load or run code are refused. This is the only permission that reaches a live target outside a scan.',
    // Leads with the decision the operator is actually making, because "does my
    // agent bring its own tools or borrow RedAmon's" is the real question and
    // everything else follows from it.
    //
    // It deliberately does NOT enumerate the permitted programs. The allowlist
    // is maintained in agentic/kali_exec_guard.py and grows; a list copied into
    // this string would be wrong within a release, and a copy that overstates it
    // is wrong in the dangerous direction. The wiki link below is generated from
    // the guard itself.
    detail:
      'Does your agent already have security tools installed where it runs, or should it borrow ' +
      'RedAmon\'s? With this on, your agent runs commands inside RedAmon\'s Kali sandbox instead of ' +
      'on its own machine, so it needs nothing installed locally. It is a fixed allowlist of ' +
      'read-only tools, not the sandbox\'s whole toolset and not a shell: anything that can load or ' +
      'run code is refused by name. Every command is checked against this project\'s scope and its ' +
      'excluded hosts before it runs. This is the only permission that reaches a live target ' +
      'outside a scan, and ticking it is not sufficient on its own: the deployment must also enable ' +
      'the feature, and a server-side guard admits or refuses each command.',
    learnMore: [
      { text: 'What the sandbox carries', href: `${WIKI}/MCP-Server#kali_toolbox-what-is-installed-not-what-is-permitted` },
      { text: 'What this can actually run', href: `${WIKI}/MCP-Server#kali_exec-one-command-at-your-target-from-a-fixed-list` },
    ],
    danger: true,
  },
}

/**
 * How the checkboxes are GROUPED in the token form.
 *
 * `MCP_SCOPES` is not reordered to achieve this, and must not be: that array is
 * the enforcement list, its per-scope comments carry the security rationale, and
 * its order also drives the generated API reference's permission table. This is
 * a presentation structure beside the copy.
 *
 * With a profile now ticking boxes on the operator's behalf, the list has to be
 * readable at a glance: a flat list of nine, where reading, scanning and writing
 * interleave and the one permission that reaches a live target looks like the
 * eight above it, is not.
 *
 * `tone` drives the visual treatment. `exec` is its own tier rather than more
 * red, because red is already spent on the `danger` scopes inside groups 2 and 3.
 */
export interface ScopeGroup {
  id: string
  label: string
  /** One line saying what the whole group is, so a profile's ticks read as a shape. */
  hint: string
  tone: 'neutral' | 'action' | 'exec'
  scopes: McpScope[]
}

export const SCOPE_GROUPS: ScopeGroup[] = [
  {
    id: 'read',
    label: 'Read and query',
    hint: 'Nothing here changes any state.',
    tone: 'neutral',
    scopes: ['recon:read', 'triage:read', 'graph:cypher'],
  },
  {
    id: 'scan',
    label: 'Run scans',
    hint: 'Start work that writes the attack-surface graph.',
    tone: 'action',
    scopes: ['recon:scan', 'recon:queue', 'recon:overwrite'],
  },
  {
    id: 'write',
    label: 'Change settings and findings',
    hint: 'Writes that are not scans.',
    tone: 'action',
    scopes: ['recon:settings', 'triage:write'],
  },
  {
    id: 'exec',
    label: 'Run commands at the target',
    hint: 'The only permission that reaches a live target outside a scan.',
    tone: 'exec',
    scopes: ['kali:exec'],
  },
]
