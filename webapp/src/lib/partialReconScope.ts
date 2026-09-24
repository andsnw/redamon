/**
 * Partial recon: which project roots a partial run is offered.
 *
 * A Domain-batch project keeps one Domain node per root. The orchestrator is the
 * authority on scope: partial_project_roots() in recon_orchestrator/batch_scope.py
 * re-derives the roots from the project row and refuses anything else. This is a
 * mirror of it, used only to decide what the modal shows and sends.
 */

const ROOT_CHARSET = /^[a-z0-9.-]+$/

export type PartialScopeMode = 'ip' | 'batch' | 'single'

export interface ProjectTargetFields {
  ipMode?: boolean | null
  targetDomain?: string | null
  domainBatchMode?: boolean | null
  domainBatchGroups?: unknown
}

export interface ProjectRoots {
  mode: PartialScopeMode
  /** Every root the project scans, in project order. */
  roots: string[]
  /** Batch roots whose group enumerates (a '*' prefix). Empty outside batch mode. */
  wildcardRoots: string[]
}

/** The name recon/main.py mints for IP mode's synthetic Domain node. */
export function ipModeRoot(projectId: string): string {
  return `ip-targets.${projectId}`
}

function usableRoot(root: string): boolean {
  // Checked lowercased but kept as stored: a single-domain target is saved
  // trimmed, not lowercased, and its Domain node carries exactly that name.
  const low = root.trim().toLowerCase()
  return low.length > 0 && ROOT_CHARSET.test(low) && !low.includes('..')
}

export function resolveProjectRoots(project: ProjectTargetFields, projectId: string): ProjectRoots {
  if (project.ipMode) {
    const root = ipModeRoot(projectId)
    return { mode: 'ip', roots: usableRoot(root) ? [root] : [], wildcardRoots: [] }
  }
  if (project.domainBatchMode) {
    const roots: string[] = []
    const wildcardRoots: string[] = []
    const groups = Array.isArray(project.domainBatchGroups) ? project.domainBatchGroups : []
    for (const group of groups) {
      if (!group || typeof group !== 'object') continue
      const { rootDomain, prefixes } = group as { rootDomain?: unknown; prefixes?: unknown }
      const root = String(rootDomain ?? '').trim().toLowerCase()
      if (!usableRoot(root)) continue
      if (!roots.includes(root)) roots.push(root)
      if (Array.isArray(prefixes) && prefixes.includes('*') && !wildcardRoots.includes(root)) {
        wildcardRoots.push(root)
      }
    }
    return { mode: 'batch', roots, wildcardRoots }
  }
  const target = String(project.targetDomain ?? '').trim()
  return { mode: 'single', roots: usableRoot(target) ? [target] : [], wildcardRoots: [] }
}

export interface GraphDomainRow {
  name: string
  /** The Domain has at least one Subdomain or resolves to an IP. */
  hasData: boolean
}

export interface PartialScopeFields {
  domain: string | null
  domains: string[]
  stale_domains: string[]
  empty_domains: string[]
}

const byName = (a: string, b: string) => a.localeCompare(b)

/**
 * The scope part of a graph-inputs response.
 *
 * `graph` is the project's Domain nodes, or null when Neo4j could not be read;
 * the roots are then offered as they are, and the orchestrator still decides.
 * A tool not yet able to cover several roots is offered only the first.
 */
export function partialScopeFields(
  scope: ProjectRoots,
  graph: GraphDomainRow[] | null,
): PartialScopeFields {
  const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase()
  const inGraph = (root: string) => (graph ?? []).some(row => same(row.name, root))

  let current = [...scope.roots]
  // IP mode's root exists only once a full recon has minted it. A domain root
  // is offered even without its node: partial discovery creates it.
  if (scope.mode === 'ip' && graph) current = current.filter(inGraph)
  current.sort(byName)

  const domains = current
  const stale = (graph ?? [])
    .map(row => row.name)
    .filter(name => !scope.roots.some(root => same(root, name)))
    .sort(byName)
  const withData = new Set((graph ?? []).filter(row => row.hasData).map(row => row.name.toLowerCase()))
  const empty = graph ? domains.filter(root => !withData.has(root.toLowerCase())) : []

  return { domain: domains[0] ?? null, domains, stale_domains: stale, empty_domains: empty }
}

/** The roots a SubdomainDiscovery run may enumerate: in a batch, only a
 *  wildcard group enumerates (group_discovery_enabled in recon). */
export function discoveryDomains(scope: ProjectRoots, domains: string[]): string[] {
  if (scope.mode !== 'batch') return [...domains]
  return domains.filter(root => scope.wildcardRoots.includes(root.toLowerCase()))
}

/** True when `host` is one of the roots or sits under one (label boundary). */
export function underAnyRoot(host: string, roots: readonly string[]): boolean {
  const h = host.toLowerCase()
  return roots.some(r => {
    const root = r.toLowerCase()
    return h === root || h.endsWith('.' + root)
  })
}
