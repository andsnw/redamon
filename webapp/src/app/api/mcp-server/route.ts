/**
 * The inbound MCP server.
 *
 * RedAmon is the SERVER here: an external agent connects in and acts as one
 * RedAmon user. That single fact drives every guard below.
 *
 * The path is `/api/mcp-server`, never `/api/mcp`. `/api/mcp/` is already the
 * OUTBOUND MCP-plugin admin namespace, and the middleware matches public paths
 * as `pathname === p || pathname.startsWith(p + '/')`, so a PUBLIC_PATHS entry
 * of `/api/mcp` would expose all three of those routes unauthenticated.
 *
 * BEARER ONLY. Being in PUBLIC_PATHS also skips the middleware's
 * X-Internal-Key / X-Scanner-Key handling, so this route authenticates solely
 * by `Authorization: Bearer` and explicitly ignores everything else:
 *
 *  - honouring the session cookie would make a middleware-exempt,
 *    state-changing POST CSRF-reachable from a logged-in operator's browser.
 *    sameSite: 'lax' blocks a cross-site POST today, but SameSite must not be
 *    the only control.
 *  - honouring X-Scanner-Key would let a leaked scanner token - held by every
 *    spawned scan container, the least-trusted tier - authenticate to the
 *    control plane. That inverts the trust model.
 *
 * Stateless JSON mode: no server-held session, so the route never depends on
 * SSE buffering behaviour at the edge, and GET/DELETE have no stream to manage.
 */
import { NextRequest, NextResponse } from 'next/server'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'

import { writeAudit } from '@/lib/audit'
import { resolveMcpUser, type McpAuthFailure } from '@/lib/mcpAuth'
import { buildMcpServer } from '@/lib/mcp/server'

export const runtime = 'nodejs'
/** The tools read live data; a cached MCP response would be actively wrong. */
export const dynamic = 'force-dynamic'

/** 64 KiB. A tool call is a small JSON-RPC envelope; anything larger is abuse. */
const MAX_BODY_BYTES = 64 * 1024

export function mcpServerEnabled(): boolean {
  // Default OFF. A new authenticated inbound surface must be switched on
  // deliberately, not inherited by upgrading.
  return process.env.MCP_SERVER_ENABLED === 'true' || process.env.MCP_SERVER_ENABLED === '1'
}

function jsonRpcError(code: number, message: string, status: number): NextResponse {
  return NextResponse.json(
    { jsonrpc: '2.0', error: { code, message }, id: null },
    { status, headers: { 'Cache-Control': 'no-store' } }
  )
}

/** 401-equivalent. The reason is logged; the caller gets one stable line. */
function unauthorized(failure: McpAuthFailure, prefix?: string): NextResponse {
  console.warn(`[mcp] auth rejected: ${failure}${prefix ? ` prefix=${prefix}` : ''}`)
  return jsonRpcError(-32001, 'Unauthorized', 401)
}

/**
 * Reject a request whose Origin is present and is not our own.
 *
 * A browser always sends Origin on a cross-site fetch, so this blocks
 * browser-driven abuse and DNS rebinding. A non-browser client sends none,
 * which is why an ABSENT origin is allowed: MCP clients are not browsers.
 */
function originAllowed(request: NextRequest): boolean {
  const origin = request.headers.get('origin')
  if (!origin) return true
  try {
    const self = new URL(request.url)
    return new URL(origin).host === self.host
  } catch {
    return false
  }
}

export async function POST(request: NextRequest) {
  // The flag is checked before anything else, so a disabled deployment does no
  // database work and reveals nothing about whether a token is valid.
  if (!mcpServerEnabled()) {
    return jsonRpcError(-32601, 'Not found', 404)
  }

  const contentType = request.headers.get('content-type') || ''
  if (!contentType.toLowerCase().includes('application/json')) {
    // A plain HTML form cannot set this, so it cannot drive the endpoint.
    return jsonRpcError(-32700, 'Content-Type must be application/json', 415)
  }
  if (!originAllowed(request)) {
    console.warn(`[mcp] rejected cross-origin request from ${request.headers.get('origin')}`)
    return jsonRpcError(-32001, 'Forbidden', 403)
  }

  const raw = await request.text()
  if (raw.length > MAX_BODY_BYTES) {
    return jsonRpcError(-32700, 'Request body too large', 413)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return jsonRpcError(-32700, 'Parse error', 400)
  }
  if (Array.isArray(parsed)) {
    // Stateless mode answers one request per call; a batch would let one
    // authenticated call fan out past every per-call budget below.
    return jsonRpcError(-32600, 'Batch requests are not supported', 400)
  }

  const auth = await resolveMcpUser(request)
  if (!auth.ok || !auth.token) {
    void writeAudit({
      actorId: null,
      action: 'mcp.auth.denied',
      targetType: 'mcpAccessToken',
      targetId: auth.prefix ?? null,
      after: { failure: auth.failure, tokenPrefix: auth.prefix ?? null },
      source: 'mcp',
    })
    return unauthorized(auth.failure ?? 'invalid', auth.prefix)
  }

  const server = buildMcpServer({ token: auth.token })
  const transport = new WebStandardStreamableHTTPServerTransport({
    // Stateless: no session id, so nothing is held between requests and the
    // token is re-verified on every call.
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  })

  try {
    await server.connect(transport)
    const response = await transport.handleRequest(request, { parsedBody: parsed })
    const headers = new Headers(response.headers)
    headers.set('Cache-Control', 'no-store')
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    })
  } catch (err) {
    console.error('[mcp] request handling failed:', err)
    return jsonRpcError(-32603, 'Internal error', 500)
  } finally {
    // Stateless mode: the server and transport live for exactly this request.
    await server.close().catch(() => undefined)
  }
}

/** Stateless mode has no stream to resume and no session to delete. */
export async function GET() {
  return jsonRpcError(-32601, 'Method not allowed', 405)
}

export async function DELETE() {
  return jsonRpcError(-32601, 'Method not allowed', 405)
}
