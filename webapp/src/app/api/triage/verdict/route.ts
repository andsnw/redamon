import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'
import { readJsonBody } from '@/lib/jsonBody'

// `needs_verification` is gone: the old classifier answered it for almost
// everything, so it meant nothing. The review's `unclear` replaced it, and that
// is an AI verdict rather than a status a person sets.
const VALID = ['confirmed', 'likely_noise', 'unreviewed']

/**
 * POST /api/triage/verdict - record the operator's own judgement on a finding.
 *
 * Body: { projectId, nodeId, status, reason? }
 *
 * Stamps `triage_source = 'human'`, which is what makes a later AI triage run
 * skip the row instead of overwriting the decision.
 */
export async function POST(request: NextRequest) {
  // A plain HTML form cannot send JSON, so a cross-site page cannot drive this.
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, status, reason } = parsed.body as {
    projectId?: string; nodeId?: unknown; status?: string; reason?: unknown
  }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (!nodeId || typeof nodeId !== 'string') {
    return NextResponse.json({ error: 'nodeId is required' }, { status: 400 })
  }
  if (typeof status !== 'string' || !VALID.includes(status)) {
    return NextResponse.json(
      { error: `status must be one of ${VALID.join(', ')}` },
      { status: 400 },
    )
  }

  return callGraphTriage('human_verdict', caller, {
    node_id: nodeId,
    status,
    reason: typeof reason === 'string' ? reason.slice(0, 500) : '',
  })
}
