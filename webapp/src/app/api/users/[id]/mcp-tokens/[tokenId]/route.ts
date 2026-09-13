/**
 * MCP personal access tokens: rename and revoke.
 *
 * PATCH changes `name` only. Nothing else about a token is mutable: not the
 * hash, the user, the scopes or the expiry. Rotating means minting a new token
 * and revoking the old one, which keeps a token's capability fixed for its whole
 * life and makes the audit trail mean something.
 *
 * Both keep the admin bypass (requireUserAccess): an admin must be able to audit
 * and kill tokens during an incident. Revoking is a safe privilege; minting,
 * which lives in the parent route, is not.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, requireUserAccess } from '@/lib/session'
import { writeAudit } from '@/lib/audit'
import { sanitizeTokenName } from '@/lib/mcpAuth'

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

  const name = sanitizeTokenName(body.name)
  if (!name) return NextResponse.json({ error: 'A token name is required' }, { status: 400 })

  const existing = await loadOwned(id, tokenId)
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  try {
    const updated = await prisma.mcpAccessToken.update({
      where: { id: tokenId },
      data: { name },
      select: SELECT,
    })
    const session = await getSession()
    await writeAudit({
      actorId: session?.userId ?? null,
      action: 'mcp-token.rename',
      targetType: 'mcpAccessToken',
      targetId: tokenId,
      before: { name: existing.name, tokenPrefix: existing.tokenPrefix },
      after: { name, tokenPrefix: existing.tokenPrefix },
      source: 'ui',
    })
    return NextResponse.json({ token: updated })
  } catch (error) {
    console.error('[mcp-tokens] rename failed:', error)
    return NextResponse.json({ error: 'Could not rename the token' }, { status: 500 })
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
