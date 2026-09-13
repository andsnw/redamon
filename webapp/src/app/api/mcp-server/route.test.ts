/**
 * The inbound MCP route's transport guards.
 *
 * Everything here is about what reaches the tools at all. The route is BEARER
 * ONLY, and the two credentials it must refuse are the interesting cases:
 *
 *  - the session cookie, because honouring it would make this
 *    middleware-exempt, state-changing POST CSRF-reachable from a logged-in
 *    operator's browser
 *  - X-Scanner-Key, because every spawned scan container holds one and that is
 *    the least-trusted tier; accepting it would invert the trust model
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  resolve: vi.fn(),
  audit: vi.fn(),
  build: vi.fn(),
  connect: vi.fn(),
  close: vi.fn(),
  handleRequest: vi.fn(),
  transportOptions: vi.fn(),
}))

vi.mock('@/lib/mcpAuth', () => ({
  resolveMcpUser: (...a: unknown[]) => h.resolve(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/mcp/server', () => ({
  buildMcpServer: (...a: unknown[]) => {
    h.build(...a)
    return { connect: h.connect, close: h.close }
  },
}))
vi.mock('@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js', () => ({
  WebStandardStreamableHTTPServerTransport: class {
    constructor(opts: unknown) { h.transportOptions(opts) }
    handleRequest(...a: unknown[]) { return h.handleRequest(...a) }
  },
}))

import { POST, GET, DELETE, mcpServerEnabled } from './route'

const TOKEN = {
  tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
  name: 'agent', scopes: ['recon:read'],
}

const rpc = { jsonrpc: '2.0', method: 'tools/list', id: 1 }

function req(opts: {
  body?: unknown
  raw?: string
  headers?: Record<string, string>
  url?: string
} = {}) {
  const headers = new Headers({
    'content-type': 'application/json',
    authorization: 'Bearer rdmn_mcp_' + 'a'.repeat(48),
    ...(opts.headers ?? {}),
  })
  const body = opts.raw ?? JSON.stringify(opts.body ?? rpc)
  return new Request(opts.url ?? 'https://redamon.example/api/mcp-server', {
    method: 'POST', headers, body,
  }) as never
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
  vi.stubEnv('MCP_SERVER_ENABLED', 'true')
  h.resolve.mockResolvedValue({ ok: true, token: TOKEN, prefix: TOKEN.tokenPrefix })
  h.connect.mockResolvedValue(undefined)
  h.close.mockResolvedValue(undefined)
  h.handleRequest.mockResolvedValue(
    new Response(JSON.stringify({ jsonrpc: '2.0', result: { tools: [] }, id: 1 }), {
      status: 200, headers: { 'content-type': 'application/json' },
    })
  )
  h.audit.mockResolvedValue(undefined)
})

// --- the feature flag ------------------------------------------------------------

describe('MCP_SERVER_ENABLED defaults off', () => {
  test('unset means disabled', () => {
    vi.stubEnv('MCP_SERVER_ENABLED', '')
    expect(mcpServerEnabled()).toBe(false)
  })

  test.each(['false', '0', 'yes', 'TRUE', 'on'])('%s does not enable it', v => {
    vi.stubEnv('MCP_SERVER_ENABLED', v)
    expect(mcpServerEnabled()).toBe(false)
  })

  test.each(['true', '1'])('%s enables it', v => {
    vi.stubEnv('MCP_SERVER_ENABLED', v)
    expect(mcpServerEnabled()).toBe(true)
  })

  test('a disabled deployment answers 404 and does no auth work', async () => {
    vi.stubEnv('MCP_SERVER_ENABLED', 'false')
    const res = await POST(req())
    expect(res.status).toBe(404)
    // It must not reveal whether a token is valid.
    expect(h.resolve).not.toHaveBeenCalled()
  })
})

// --- bearer only -------------------------------------------------------------------

describe('the route is bearer-only', () => {
  test('a valid bearer builds the server with the resolved token', async () => {
    const res = await POST(req())
    expect(res.status).toBe(200)
    expect(h.build).toHaveBeenCalledWith({ token: TOKEN })
  })

  test('a missing bearer is rejected', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({ headers: { authorization: '' } }))
    expect(res.status).toBe(401)
    expect(h.build).not.toHaveBeenCalled()
  })

  test('a session COOKIE alone authenticates nothing (CSRF)', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({
      headers: { authorization: '', cookie: 'redamon-auth=a.valid.jwt' },
    }))
    expect(res.status).toBe(401)
  })

  test('X-Scanner-Key alone authenticates nothing (trust inversion)', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({
      headers: { authorization: '', 'x-scanner-key': 'scan-tok' },
    }))
    expect(res.status).toBe(401)
  })

  test('X-Internal-Key alone authenticates nothing', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'missing' })
    const res = await POST(req({
      headers: { authorization: '', 'x-internal-key': 'master-key' },
    }))
    expect(res.status).toBe(401)
  })

  test.each(['revoked', 'expired', 'invalid', 'bad_scopes'])(
    'a %s token is rejected with the same stable message',
    async failure => {
      h.resolve.mockResolvedValue({ ok: false, failure, prefix: 'rdmn_mcp_aaaaaaaa' })
      const res = await POST(req())
      expect(res.status).toBe(401)
      const body = await res.json()
      // The reason goes to the log, not the caller.
      expect(body.error.message).toBe('Unauthorized')
    }
  )

  test('an auth failure is audited by PREFIX, never by token', async () => {
    h.resolve.mockResolvedValue({ ok: false, failure: 'revoked', prefix: 'rdmn_mcp_aaaaaaaa' })
    await POST(req())
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'mcp.auth.denied',
      targetId: 'rdmn_mcp_aaaaaaaa',
    }))
    expect(JSON.stringify(h.audit.mock.calls[0][0])).not.toContain('a'.repeat(48))
  })
})

// --- request shape guards -------------------------------------------------------------

describe('request shape', () => {
  test('a non-JSON content type is refused', async () => {
    // A plain HTML form post cannot set application/json, so it cannot drive
    // this endpoint.
    const res = await POST(req({ headers: { 'content-type': 'application/x-www-form-urlencoded' } }))
    expect(res.status).toBe(415)
    expect(h.resolve).not.toHaveBeenCalled()
  })

  test('a JSON content type with a charset is accepted', async () => {
    const res = await POST(req({ headers: { 'content-type': 'application/json; charset=utf-8' } }))
    expect(res.status).toBe(200)
  })

  test('a JSON-RPC BATCH array is refused', async () => {
    // A batch would let one authenticated call fan out past every per-call
    // budget the tools enforce.
    const res = await POST(req({ body: [rpc, rpc] }))
    expect(res.status).toBe(400)
    expect(h.build).not.toHaveBeenCalled()
  })

  test('an over-large body is refused before parsing', async () => {
    const res = await POST(req({ raw: JSON.stringify({ x: 'y'.repeat(70_000) }) }))
    expect(res.status).toBe(413)
    expect(h.resolve).not.toHaveBeenCalled()
  })

  test('unparseable JSON is a 400, not a 500', async () => {
    const res = await POST(req({ raw: '{not json' }))
    expect(res.status).toBe(400)
  })
})

describe('Origin handling (DNS rebinding / browser-driven abuse)', () => {
  test('a foreign Origin is refused', async () => {
    const res = await POST(req({ headers: { origin: 'https://evil.example' } }))
    expect(res.status).toBe(403)
    expect(h.resolve).not.toHaveBeenCalled()
  })

  test('our own Origin is allowed', async () => {
    const res = await POST(req({ headers: { origin: 'https://redamon.example' } }))
    expect(res.status).toBe(200)
  })

  test('an ABSENT Origin is allowed: MCP clients are not browsers', async () => {
    const res = await POST(req())
    expect(res.status).toBe(200)
  })

  test('a malformed Origin is refused', async () => {
    const res = await POST(req({ headers: { origin: 'not-a-url' } }))
    expect(res.status).toBe(403)
  })
})

// --- transport mode -----------------------------------------------------------------

describe('stateless JSON mode', () => {
  test('no session id generator is configured', async () => {
    await POST(req())
    const opts = h.transportOptions.mock.calls[0][0]
    expect(opts.sessionIdGenerator).toBeUndefined()
    expect(opts.enableJsonResponse).toBe(true)
  })

  test('the server is closed after every request', async () => {
    await POST(req())
    expect(h.close).toHaveBeenCalled()
  })

  test('the server is closed even when handling throws', async () => {
    h.handleRequest.mockRejectedValue(new Error('boom'))
    const res = await POST(req())
    expect(res.status).toBe(500)
    expect(h.close).toHaveBeenCalled()
  })

  test('a handling failure does not leak the error to the caller', async () => {
    h.handleRequest.mockRejectedValue(new Error('ECONNREFUSED 10.0.0.5:7687'))
    const body = await (await POST(req())).json()
    expect(JSON.stringify(body)).not.toMatch(/ECONNREFUSED|10\.0\.0\.5/)
  })

  test.each([
    ['GET', GET],
    ['DELETE', DELETE],
  ])('%s answers 405: there is no stream to manage', async (_m, fn) => {
    expect((await fn()).status).toBe(405)
  })
})

describe('caching', () => {
  test('every response is no-store, not relying on the edge', async () => {
    // A plain `docker compose up` has no nginx, so the header is set here.
    expect((await POST(req())).headers.get('Cache-Control')).toBe('no-store')
    vi.stubEnv('MCP_SERVER_ENABLED', 'false')
    expect((await POST(req())).headers.get('Cache-Control')).toBe('no-store')
  })
})
