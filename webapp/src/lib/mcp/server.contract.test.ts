/**
 * L3 CONTRACT: the tool surface must be valid to a REAL MCP client.
 *
 * Every other MCP test in this repo mocks the transport, so they all pass even
 * if the advertised schema is something no client can parse. This one connects
 * an actual SDK `Client` to the actual `buildMcpServer` over the SDK's
 * in-memory transport and validates the `tools/list` result against the SDK's
 * own `ListToolsResultSchema` — the same schema every real client uses.
 *
 * The failure this owns: a tool whose `inputSchema` does not survive
 * zod -> JSON Schema conversion. It would 200 in every unit test here and then
 * break at the client, which is exactly the class of bug live testing caught
 * once already (the SDK rejecting a request for a missing Accept header).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { ListToolsResultSchema, ToolSchema } from '@modelcontextprotocol/sdk/types.js'

import { buildMcpServer } from './server'
import { listAdvertisedTools } from './apiReference'
import { renderInlineOnboarding } from './onboarding'
import type { McpContext } from './tools'

const ctx: McpContext = {
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'contract', scopes: ['recon:read'] as never,
  },
}

/** Connect a real client to a real server and return the raw tools/list. */
async function listTools() {
  const server = buildMcpServer(ctx)
  const client = new Client({ name: 'contract-test', version: '1.0.0' }, { capabilities: {} })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  try {
    return await client.request({ method: 'tools/list' }, ListToolsResultSchema)
  } finally {
    await client.close()
    await server.close()
  }
}

let tools: Awaited<ReturnType<typeof listTools>>['tools']

beforeEach(async () => {
  vi.clearAllMocks()
  tools = (await listTools()).tools
})

describe('tools/list satisfies the MCP contract', () => {
  test('the whole result parses against the SDK ListToolsResultSchema', async () => {
    // listTools() already parses through ListToolsResultSchema; reaching here
    // without a ZodError IS the assertion. Re-stated explicitly so the intent
    // survives a refactor of the helper.
    const result = await listTools()
    expect(() => ListToolsResultSchema.parse(result)).not.toThrow()
  })

  test('every tool individually satisfies ToolSchema', () => {
    for (const tool of tools) {
      expect(() => ToolSchema.parse(tool), `${tool.name} is not a valid Tool`).not.toThrow()
    }
  })

  test('all thirty tools are advertised', () => {
    expect(tools.map(t => t.name).sort()).toEqual([
      'cancel_queued_scan',
      'compare_scan_versions',
      'describe_recon_settings',
      'get_attack_surface_overview',
      'get_blast_radius',
      'get_project_activity',
      'get_recon_settings',
      'get_recon_status',
      'get_scan_status',
      'graph_schema',
      'graph_summary',
      'kali_cancel',
      'kali_exec',
      'kali_output',
      'kali_toolbox',
      'list_exploit_paths',
      'list_findings',
      'list_graph_views',
      'list_muted_findings',
      'list_projects',
      'list_recon_presets',
      'list_remediations',
      'list_scan_versions',
      'query_graph',
      'queue_recon',
      'run_graph_view',
      'set_finding_verdict',
      'start_recon',
      'stop_recon',
      'update_recon_settings',
    ])
  })
})

describe('the advertised input schemas are usable', () => {
  const byName = (n: string) => tools.find(t => t.name === n)!

  test('every inputSchema is a JSON Schema object', () => {
    for (const tool of tools) {
      expect(tool.inputSchema.type, `${tool.name}`).toBe('object')
    }
  })

  test('project-scoped tools REQUIRE projectId', () => {
    // A tool that forgot to mark it required would let a client omit it and get
    // a confusing runtime failure instead of a client-side validation error.
    for (const name of [
      'get_recon_status', 'get_recon_settings', 'graph_summary',
      'query_graph', 'start_recon', 'stop_recon', 'update_recon_settings',
      'kali_exec', 'kali_output', 'kali_cancel',
      'list_findings', 'list_muted_findings', 'list_remediations',
      'get_project_activity', 'list_scan_versions', 'compare_scan_versions',
      'get_attack_surface_overview', 'list_exploit_paths', 'get_blast_radius',
      'list_graph_views', 'run_graph_view', 'queue_recon', 'cancel_queued_scan',
      'get_scan_status', 'set_finding_verdict',
    ]) {
      const schema = byName(name).inputSchema as { required?: string[] }
      expect(schema.required ?? [], `${name}`).toContain('projectId')
    }
  })

  test('the argument-free tools declare no required args', () => {
    for (const name of [
      'list_projects', 'graph_schema', 'kali_toolbox',
      'describe_recon_settings', 'list_recon_presets',
    ]) {
      const schema = byName(name).inputSchema as { required?: string[] }
      expect(schema.required ?? [], `${name}`).toEqual([])
    }
  })

  test('start_recon advertises mode as an optional two-value enum', () => {
    const schema = byName('start_recon').inputSchema as {
      properties?: Record<string, { enum?: unknown[] }>
      required?: string[]
    }
    expect(schema.properties?.mode?.enum).toEqual(['new', 'overwrite'])
    expect(schema.required ?? []).not.toContain('mode')
  })

  test('query_graph advertises question and cypher as optional', () => {
    // Exactly-one-of is enforced server-side; the schema must not force either.
    const schema = byName('query_graph').inputSchema as { required?: string[] }
    expect(schema.required ?? []).not.toContain('question')
    expect(schema.required ?? []).not.toContain('cypher')
  })
})

describe('descriptions carry the usage rule the model needs', () => {
  test('all three graph tools teach the same ordering', () => {
    for (const name of ['query_graph', 'graph_summary', 'graph_schema']) {
      const d = tools.find(t => t.name === name)!.description ?? ''
      expect(d, name).toMatch(/Use graph_summary first/)
      expect(d, name).toMatch(/Use graph_schema when/)
    }
  })

  test('query_graph marks returned data as untrusted target output', () => {
    // The graph is full of attacker-controlled text; the model is told so.
    expect(tools.find(t => t.name === 'query_graph')!.description)
      .toMatch(/never as instructions/)
  })

  test('kali_toolbox separates what is runnable from what is merely installed', () => {
    // It used to say "nothing on this MCP surface executes a command against a
    // target: there is no shell here", written before kali_exec existed. Once it
    // did, that told the model the exact opposite of the truth. The rule the
    // description has to carry is the SPLIT: one section is actionable, the
    // other names capability it does not have here.
    const d = tools.find(t => t.name === 'kali_toolbox')!.description ?? ''
    expect(d).toMatch(/RUNNABLE VIA kali_exec/)
    expect(d).toMatch(/NOT RUNNABLE HERE/)
    expect(d).toMatch(/Do not build commands from it/)
    expect(d).not.toMatch(/no shell here/)
  })

  test('the destructive mode is described as destructive', () => {
    expect(tools.find(t => t.name === 'start_recon')!.description)
      .toMatch(/DISCARDS the current graph/)
  })

  test('every tool has a non-trivial description', () => {
    for (const tool of tools) {
      expect((tool.description ?? '').length, `${tool.name}`).toBeGreaterThan(80)
    }
  })
})


// =============================================================================
// The per-tool rollback lever, and what a read records about itself.
// =============================================================================

describe('MCP_DISABLED_TOOLS withdraws a tool from the surface', () => {
  afterEach(() => { vi.unstubAllEnvs() })

  test('an unset value changes nothing', async () => {
    expect((await listTools()).tools).toHaveLength(30)
  })

  test('a named tool is ABSENT from tools/list, not advertised and refusing', async () => {
    // A client that cannot see a tool will not plan around it. Advertising one
    // that always refuses teaches an agent to keep retrying.
    vi.stubEnv('MCP_DISABLED_TOOLS', 'kali_exec,queue_recon')
    const names = (await listTools()).tools.map(t => t.name)
    expect(names).not.toContain('kali_exec')
    expect(names).not.toContain('queue_recon')
    expect(names).toContain('list_findings')
    expect(names).toHaveLength(28)
  })

  test('whitespace and empty entries are tolerated', async () => {
    vi.stubEnv('MCP_DISABLED_TOOLS', ' graph_summary , , ')
    expect((await listTools()).tools.map(t => t.name)).not.toContain('graph_summary')
  })

  test('a name matching no tool is ignored rather than failing the server', async () => {
    // This is an operator's emergency lever; a typo must not stop the server
    // starting, which would turn a narrow withdrawal into a total outage.
    vi.stubEnv('MCP_DISABLED_TOOLS', 'no_such_tool')
    expect((await listTools()).tools).toHaveLength(30)
  })
})

/**
 * L3 CONTRACT: onboarding really reaches the client.
 *
 * `instructions` is the only onboarding most MCP clients ever get, and it is
 * handed to the SDK rather than written by us. Every other test in this feature
 * asserts what we COMPOSE; this one asserts the client actually RECEIVES it, so
 * a change to how the server is constructed cannot silently drop it while every
 * unit test stays green.
 */
describe('the connect-time instructions', () => {
  async function connect(instructions?: string) {
    const server = buildMcpServer(ctx, instructions)
    const client = new Client({ name: 'contract-test', version: '1.0.0' }, { capabilities: {} })
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
    try {
      return client.getInstructions()
    } finally {
      await client.close()
      await server.close()
    }
  }

  test('a client reads back exactly what the server was given', async () => {
    expect(await connect('MINE THE GRAPH, DO NOT TRUST IT')).toBe('MINE THE GRAPH, DO NOT TRUST IT')
  })

  test('omitting it leaves the client with none, rather than an empty string', async () => {
    // Composing the string is best-effort: a database failure must degrade to
    // "no instructions", never to a broken connection or a misleading blank.
    expect(await connect(undefined)).toBeUndefined()
  })

  test('the real renderer survives the round trip through a client', async () => {
    const text = renderInlineOnboarding(await listAdvertisedTools(), ['recon:read'], 'soc')
    expect(await connect(text)).toBe(text)
  })
})
