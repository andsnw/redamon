/**
 * What has to be true before a scan may reach somebody else's estate.
 *
 * Two defects this closes, and they compound.
 *
 * The first: `roeEnabled` defaults false and `roeGlobalMaxRps` defaults 0, so a
 * project created without deliberately switching the Rules of Engagement on has
 * NO rate ceiling at all. That was survivable while 126 columns were settable
 * and three of the fifteen rate fields were reachable. Once every rate is
 * reachable the RoE layer is the main control for all of them, which makes an
 * inert-by-default ceiling load-bearing in a way it was not before.
 *
 * The second: a project carried no link to the document that permitted it. With
 * an agent able to create projects and reach every pipeline parameter, "who said
 * you could scan this" needs an answer that survives the token that made the
 * claim.
 *
 * `engagementKind` is what ties them together. An `internal` project is our own
 * estate and nothing changes for it. A `third_party` project must carry a
 * non-zero ceiling AND an authorization record, and `start_recon` refuses it
 * otherwise - refuses, rather than silently downgrading, because a scan that
 * quietly ran without its ceiling is the exact failure this exists to prevent.
 *
 * Every project that predates the column reads as `internal`, which keeps the
 * estate working and means the defect is closed for NEW projects only. The
 * existing ones are FLAGGED instead: `describeEngagement` reports the absence of
 * a ceiling prominently so an operator converts deliberately rather than
 * discovering it during an incident.
 */
import { createHash } from 'crypto'

import prisma from '@/lib/prisma'

export type EngagementKind = 'internal' | 'third_party'

export const ENGAGEMENT_KINDS: readonly EngagementKind[] = ['internal', 'third_party']

export const DOCUMENT_KINDS = [
  'hackerone_program',
  'bugcrowd_program',
  'roe_document',
  'internal_ticket',
  'other',
] as const
export type DocumentKind = (typeof DOCUMENT_KINDS)[number]

export function isEngagementKind(value: unknown): value is EngagementKind {
  return typeof value === 'string' && (ENGAGEMENT_KINDS as readonly string[]).includes(value)
}

export function isDocumentKind(value: unknown): value is DocumentKind {
  return typeof value === 'string' && (DOCUMENT_KINDS as readonly string[]).includes(value)
}

const SHA256_RE = /^[0-9a-f]{64}$/

export function isSha256(value: unknown): value is string {
  return typeof value === 'string' && SHA256_RE.test(value)
}

/** The digest of a scope document, for a caller that has the text rather than the hash. */
export function digestScopeDocument(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

export interface EngagementProjectRow {
  id: string
  engagementKind: string
  roeEnabled: boolean
  roeGlobalMaxRps: number
  targetDomain?: string
  engagementIdentityHeader?: string
}

export interface EngagementStatus {
  kind: EngagementKind
  /** The effective request-rate ceiling, or null when there is none. */
  ceilingRps: number | null
  /** True when a ceiling is configured AND the RoE switch that applies it is on. */
  ceilingEffective: boolean
  hasAuthorization: boolean
  /** Empty when the engagement is startable. Otherwise, why it is not. */
  blockers: string[]
  /** Not blocking, but an operator should see it. */
  warnings: string[]
}

/**
 * A ceiling is only real when BOTH switches agree.
 *
 * `roeGlobalMaxRps` alone caps nothing: the capper is gated on `roeEnabled`, so
 * a project with a 3 written and the switch off runs unlimited. Reporting the
 * number without the switch is how an operator believes in a ceiling that is not
 * applied.
 */
export function effectiveCeiling(project: EngagementProjectRow): number | null {
  if (!project.roeEnabled) return null
  return project.roeGlobalMaxRps > 0 ? project.roeGlobalMaxRps : null
}

export function describeEngagement(
  project: EngagementProjectRow,
  authorizationCount: number
): EngagementStatus {
  const kind: EngagementKind = isEngagementKind(project.engagementKind)
    ? project.engagementKind
    : 'internal'
  const ceiling = effectiveCeiling(project)
  const blockers: string[] = []
  const warnings: string[] = []

  if (kind === 'third_party') {
    if (!project.roeEnabled) {
      blockers.push(
        'Rules of Engagement are switched off, so no rate ceiling is applied. A third-party ' +
        'engagement must run under one.'
      )
    } else if (!(project.roeGlobalMaxRps > 0)) {
      blockers.push(
        'roeGlobalMaxRps is 0, which means NO ceiling rather than a slow one. A third-party ' +
        'engagement must declare a request-rate ceiling.'
      )
    }
    if (authorizationCount === 0) {
      blockers.push(
        'No authorization record. A third-party engagement must record the scope document ' +
        'that permits it before a scan starts; use attach_engagement_authorization.'
      )
    }
  } else if (ceiling === null) {
    // The whole existing estate lands here after the backfill. Loud, and not
    // blocking: turning it into a blocker would break every project at once.
    warnings.push(
      'This project has NO request-rate ceiling: every tool runs at whatever rate its own ' +
      'setting says. That is the default for a project created before engagement kinds ' +
      'existed. If the target is not your own estate, set engagementKind to third_party on a ' +
      'new project, or switch the Rules of Engagement on with a ceiling.'
    )
  }

  if (kind === 'third_party' && !project.engagementIdentityHeader) {
    warnings.push(
      'No engagement identity header is set, so the target\'s operators cannot attribute this ' +
      'traffic to you. Many programs require one.'
    )
  }

  return {
    kind,
    ceilingRps: ceiling,
    ceilingEffective: ceiling !== null,
    hasAuthorization: authorizationCount > 0,
    blockers,
    warnings,
  }
}

const ENGAGEMENT_SELECT = {
  id: true,
  engagementKind: true,
  engagementIdentityHeader: true,
  roeEnabled: true,
  roeGlobalMaxRps: true,
  targetDomain: true,
} as const

/**
 * Load a project's engagement status.
 *
 * FAILS CLOSED for a third_party project: an unreadable project or an
 * uncountable authorization set is reported as blocking, never as fine. This
 * runs on the path that decides whether a scan reaches somebody else's estate,
 * and "we could not check" is not the same as "it is allowed".
 */
export async function loadEngagement(projectId: string): Promise<EngagementStatus> {
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: ENGAGEMENT_SELECT,
  })
  if (!project) {
    return {
      kind: 'third_party',
      ceilingRps: null,
      ceilingEffective: false,
      hasAuthorization: false,
      blockers: ['Project not found.'],
      warnings: [],
    }
  }
  const count = await prisma.engagementAuthorization.count({ where: { projectId } })
  return describeEngagement(project as EngagementProjectRow, count)
}

/**
 * The project's current authorization, or null.
 *
 * The most recent record, because the model is append-only: when a program
 * re-issues its scope a new row records that the engagement continued under a
 * new authority from that moment, and the latest one is what a run today is
 * covered by.
 */
export async function currentAuthorization(projectId: string) {
  return prisma.engagementAuthorization.findFirst({
    where: { projectId },
    orderBy: { recordedAt: 'desc' },
    select: {
      id: true,
      documentSha256: true,
      documentKind: true,
      sourceUrl: true,
      programHandle: true,
      issuedAt: true,
      recordedAt: true,
      recordedVia: true,
      summary: true,
    },
  })
}
