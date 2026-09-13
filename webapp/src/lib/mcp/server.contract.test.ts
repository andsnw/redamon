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
import { describe, test, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { ListToolsResultSchema, ToolSchema } from '@modelcontextprotocol/sdk/types.js'

import { buildMcpServer } from './server'
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

  test('all twenty-eight tools are advertised', () => {
    expect(tools.map(t => t.name).sort()).toEqual([
      'cancel_queued_scan',
      'compare_scan_versions',
      'describe_recon_settings',
      'get_attack_surface_overview',
      'get_blast_radius',
      'get_project_activity',
      'get_recon_settings',
      'get_recon_status',
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

  test('kali_toolbox tells the model it cannot run any of what it lists', () => {
    // The catalogue names sqlmap, hashcat, msfvenom and the rest. Without this
    // line a model reads that list as an offer and burns calls hunting for the
    // tool that executes it; there is none on this surface.
    const d = tools.find(t => t.name === 'kali_toolbox')!.description ?? ''
    expect(d).toMatch(/does not run anything/)
    expect(d).toMatch(/no shell here/)
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
