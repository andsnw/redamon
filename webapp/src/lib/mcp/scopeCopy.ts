/**
 * The operator-facing wording for each token scope.
 *
 * Shared by the token-minting UI and the generated MCP API reference, so the
 * checkbox a person ticks and the page that documents it cannot describe the
 * same permission two different ways.
 */
import type { McpScope } from '@/lib/mcpAuth'

/** Each write scope states its consequence, so a tick is an informed one. */
export const MCP_SCOPE_COPY: Record<McpScope, { label: string; blurb: string; danger?: boolean }> = {
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
    danger: true,
  },
}
