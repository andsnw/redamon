import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { readJsonBody } from '@/lib/jsonBody'
import { requireProjectOwner, graphTriage, realActorUserId } from '@/lib/triageClient'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'

/**
 * POST /api/triage/unmute - restore suppressed findings.
 *
 * Body: { projectId, keys: string[] }, or the single-finding form { projectId, nodeId }.
 *
 * Lossless: each finding keeps every relationship and property it had. The triage
 * VERDICT is deliberately left in place -- unmuting means "show me this again",
 * not "forget the analysis".
 *
 * Every unmuted finding also gets a NodeFilterExemption, whether a person or a
 * rule had muted it, so an operator's unmute sticks: no filter rule mutes that
 * node again until the exemption is cleared from the Node Filters page. The
 * exemption is a Postgres row rather than a graph property because the prune,
 * the recon asset clear, version activation and import would each delete a
 * property.
 */
const MAX_KEYS = 500

export async function POST(request: NextRequest) {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, keys } = parsed.body as {
    projectId?: string; nodeId?: unknown; keys?: unknown
  }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller

  const wanted = Array.isArray(keys)
    ? keys.filter((k): k is string => typeof k === 'string' && k.length > 0 && k.length <= 300)
    : typeof nodeId === 'string' && nodeId ? [nodeId] : []
  if (wanted.length === 0) {
    return NextResponse.json({ error: 'keys (or nodeId) is required' }, { status: 400 })
  }
  if (wanted.length > MAX_KEYS) {
    return NextResponse.json({ error: `at most ${MAX_KEYS} keys per request` }, { status: 400 })
  }

  // A running apply read the exemptions when it started, so a finding unmuted
  // now would be muted again when its page comes up. Refused until it ends.
  const applying = await describeNodeFilterWriter(caller.projectId)
  if (applying) {
    return NextResponse.json(
      { error: `Cannot unmute while ${applying}. Try again when it finishes.` },
      { status: 409 },
    )
  }

  const result = await graphTriage('unmute_many', caller, { keys: [...new Set(wanted)] })
  if (result.status !== 200) return NextResponse.json(result.body, { status: result.status })

  const items = (Array.isArray(result.body.items) ? result.body.items : []) as {
    key: string; label: string; muted_by: string
  }[]
  const realActor = await realActorUserId()

  let exempted = 0
  let exemptionError: string | null = null
  try {
    for (const item of items) {
      if (!item?.key || !item?.label) continue
      await prisma.nodeFilterExemption.upsert({
        where: {
          projectId_label_nodeKey: {
            projectId: caller.projectId, label: item.label, nodeKey: item.key,
          },
        },
        create: {
          projectId: caller.projectId, label: item.label, nodeKey: item.key,
          createdBy: caller.userId, realActorUserId: realActor,
        },
        update: {},
      })
      exempted += 1
    }
  } catch (e) {
    // The graph unmute already happened and is not rolled back: the finding is
    // visible, which is what the operator asked for. What is lost is only the
    // guarantee that a rule will not mute it again, so the caller is told.
    console.error('[unmute] could not record node-filter exemptions:', e)
    exemptionError = 'Unmuted, but the filter exemption was not saved: a filter rule may mute it again.'
  }

  if (items.length > 0) {
    await writeAudit({
      actorId: caller.userId,
      action: 'muted_nodes.unmuted',
      targetType: 'project',
      targetId: caller.projectId,
      after: {
        realActorUserId: realActor,
        count: items.length,
        exempted,
        // Keys and what had muted each: rule ids and user ids, never finding text.
        items: items.slice(0, 100).map(i => ({ key: i.key, label: i.label, mutedBy: i.muted_by })),
      },
      source: 'ui',
    })
  }

  return NextResponse.json({
    unmuted: items.length,
    items,
    exempted,
    ...(exemptionError ? { exemptionError } : {}),
  })
}
