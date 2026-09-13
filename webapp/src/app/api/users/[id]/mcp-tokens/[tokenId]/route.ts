/**
 * MCP personal access tokens: edit and revoke.
 *
 * PATCH changes a token's name, scopes and expiry. The hash and the owner are
 * never mutable, and a revoked token keeps its capability frozen (it can only
 * be renamed): restoring access means minting a new token.
 *
 * The rule an edit is judged by is DIRECTION, not field:
 *  - a change that NARROWS the token (drop a scope, earlier expiry, "expire
 *    now", rename) keeps the admin bypass, exactly like revoke. Taking power
 *    away is a safe privilege during an incident.
 *  - a change that WIDENS it (add a scope, later or no expiry, reviving an
 *    expired token) gets the mint's step-up: self-only on the REAL identity,
 *    password re-confirmed, same limiter. Otherwise a stolen session cookie
 *    could upgrade an existing token into the credential it cannot mint.
 *
 * Scopes and expiry are re-read on every MCP call, so an edit takes effect on
 * the agent's next call.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { verifyPassword } from '@/lib/auth'
import { getSession, requireUserAccess } from '@/lib/session'
import { checkLockout, recordFailure, clearAttempts } from '@/lib/loginThrottle'
import { writeAudit } from '@/lib/audit'
import {
  isTokenWidening,
  resolveExpiryChange,
  sanitizeTokenName,
  validateScopes,
  type McpScope,
} from '@/lib/mcpAuth'

interface RouteParams {
  params: Promise<{ id: string; tokenId: string }>
}

const SELECT = {
  id: true,
  name: true,
  tokenPrefix: true,
  scopes: true,
  lastUsedAt: true,
  expiresAt: true,
  revokedAt: true,
  createdAt: true,
} as const

/** Load the token, 404ing unless it belongs to the user in the path. */
async function loadOwned(userId: string, tokenId: string) {
  const token = await prisma.mcpAccessToken.findUnique({
    where: { id: tokenId },
    select: { ...SELECT, userId: true },
  })
  if (!token || token.userId !== userId) return null
  return token
}

const sameScopes = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every(s => b.includes(s))

const sameExpiry = (a: Date | null, b: Date | null) =>
  (a === null && b === null) || (a !== null && b !== null && a.getTime() === b.getTime())

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const { id, tokenId } = await params
  const denied = await requireUserAccess(request, id)
  if (denied) return denied

  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const existing = await loadOwned(id, tokenId)
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const data: { name?: string; scopes?: McpScope[]; expiresAt?: Date | null } = {}

  if ('name' in body) {
    const name = sanitizeTokenName(body.name)
    if (!name) return NextResponse.json({ error: 'A token name is required' }, { status: 400 })
    if (name !== existing.name) data.name = name
  }
  if ('scopes' in body) {
    const scopeResult = validateScopes(body.scopes)
    if ('error' in scopeResult) {
      return NextResponse.json({ error: scopeResult.error }, { status: 400 })
    }
    if (!sameScopes(scopeResult.scopes, existing.scopes)) data.scopes = scopeResult.scopes
  }
  if ('expiry' in body) {
    const expiryResult = resolveExpiryChange(body.expiry)
    if ('error' in expiryResult) {
      return NextResponse.json({ error: expiryResult.error }, { status: 400 })
    }
    if (!sameExpiry(expiryResult.expiresAt, existing.expiresAt)) data.expiresAt = expiryResult.expiresAt
  }

  if (!('name' in body) && !('scopes' in body) && !('expiry' in body)) {
    return NextResponse.json({ error: 'Nothing to change' }, { status: 400 })
  }
  if (Object.keys(data).length === 0) {
    const token = Object.fromEntries(
      Object.keys(SELECT).map(k => [k, existing[k as keyof typeof SELECT]])
    )
    return NextResponse.json({ token })
  }

  const changesCapability = 'scopes' in data || 'expiresAt' in data
  if (changesCapability && existing.revokedAt) {
    return NextResponse.json(
      { error: 'A revoked token can only be renamed. Create a new token to restore access.' },
      { status: 409 }
    )
  }

  const after = {
    scopes: data.scopes ?? existing.scopes,
    expiresAt: 'expiresAt' in data ? data.expiresAt ?? null : existing.expiresAt,
  }
  const widened = changesCapability && isTokenWidening(existing, after)
  const session = await getSession()

  if (widened) {
    // Judged on the REAL identity, like minting: requireUserAccess above
    // carries the admin bypass, which must not extend to adding power.
    if (!session || session.userId !== id) {
      return NextResponse.json(
        {
          error:
            'Only the token owner, signed in as themselves, can add a permission or extend the ' +
            'expiry. You can still remove permissions, shorten the expiry or revoke it.',
        },
        { status: 403 }
      )
    }
    const throttleIp = request.headers?.get('x-forwarded-for')?.split(',')[0]?.trim() ?? null
    // The mint's key, on purpose: both verify the same password, so they share
    // one attempt budget instead of doubling the guesses a stolen cookie gets.
    const throttleKey = `mcp-token-mint:${id}`
    const lock = checkLockout(throttleKey, throttleIp)
    if (lock.locked) {
      return NextResponse.json(
        { error: `Too many incorrect passwords. Try again in ${lock.retryAfterSeconds}s.` },
        { status: 429 }
      )
    }
    const password = typeof body.password === 'string' ? body.password : ''
    if (!password) {
      return NextResponse.json(
        {
          error: 'Adding a permission or extending the expiry needs your password.',
          passwordRequired: true,
        },
        { status: 401 }
      )
    }
    const user = await prisma.user.findUnique({ where: { id }, select: { password: true } })
    if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    if (!(await verifyPassword(password, user.password))) {
      recordFailure(throttleKey, throttleIp)
      return NextResponse.json(
        { error: 'Password is incorrect', passwordRequired: true },
        { status: 401 }
      )
    }
    clearAttempts(throttleKey, throttleIp)
  }

  try {
    const updated = await prisma.mcpAccessToken.update({
      where: { id: tokenId },
      data,
      select: SELECT,
    })

    const renameOnly = !changesCapability
    await writeAudit({
      actorId: session?.userId ?? null,
      action: renameOnly ? 'mcp-token.rename' : 'mcp-token.update',
      targetType: 'mcpAccessToken',
      targetId: tokenId,
      before: renameOnly
        ? { name: existing.name, tokenPrefix: existing.tokenPrefix }
        : {
            name: existing.name, tokenPrefix: existing.tokenPrefix,
            scopes: existing.scopes, expiresAt: existing.expiresAt,
          },
      after: renameOnly
        ? { name: updated.name, tokenPrefix: existing.tokenPrefix }
        : {
            name: updated.name, tokenPrefix: existing.tokenPrefix,
            scopes: updated.scopes, expiresAt: updated.expiresAt,
            widened, ownerId: id,
          },
      source: 'ui',
    })
    return NextResponse.json({ token: updated })
  } catch (error) {
    console.error('[mcp-tokens] update failed:', error)
    return NextResponse.json({ error: 'Could not update the token' }, { status: 500 })
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  const { id, tokenId } = await params
  const denied = await requireUserAccess(request, id)
  if (denied) return denied

  const existing = await loadOwned(id, tokenId)
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  // Revoke, never delete: the row stays visible so the operator can see why
  // their agent stopped working. Pruning is a separate, time-based job.
  if (existing.revokedAt) return NextResponse.json({ token: existing })

  try {
    const updated = await prisma.mcpAccessToken.update({
      where: { id: tokenId },
      data: { revokedAt: new Date() },
      select: SELECT,
    })
    const session = await getSession()
    await writeAudit({
      actorId: session?.userId ?? null,
      action: 'mcp-token.revoke',
      targetType: 'mcpAccessToken',
      targetId: tokenId,
      after: { tokenPrefix: existing.tokenPrefix, name: existing.name, ownerId: id },
      source: 'ui',
    })
    return NextResponse.json({ token: updated })
  } catch (error) {
    console.error('[mcp-tokens] revoke failed:', error)
    return NextResponse.json({ error: 'Could not revoke the token' }, { status: 500 })
  }
}
