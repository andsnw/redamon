/**
 * The engagement gate: what has to be true before a scan reaches somebody
 * else's estate.
 *
 * The rule these tests pin is narrow and load-bearing. `roeEnabled` defaults
 * false and `roeGlobalMaxRps` defaults 0, so a project has NO rate ceiling
 * unless someone deliberately switched one on. That was survivable while three
 * of fifteen rate fields were reachable over MCP; with every rate reachable, the
 * RoE layer is the main control for all of them.
 *
 * Two failures the assertions below exist to prevent, both of which read as fine
 * from a distance:
 *
 *  - a ceiling written with the switch off, which caps nothing. The number is
 *    there, an operator believes in it, and the capper never runs.
 *  - a ceiling of 0, which is NO ceiling rather than a slow one, and which is
 *    also the shipped default.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import {
  DOCUMENT_KINDS,
  describeEngagement,
  digestScopeDocument,
  effectiveCeiling,
  isDocumentKind,
  isEngagementKind,
  isSha256,
  type EngagementProjectRow,
} from './engagement'

const project = (over: Partial<EngagementProjectRow> = {}): EngagementProjectRow => ({
  id: 'p1',
  engagementKind: 'internal',
  roeEnabled: false,
  roeGlobalMaxRps: 0,
  ...over,
})

describe('a ceiling is only real when both switches agree', () => {
  test('a number with the switch off is not a ceiling', () => {
    expect(effectiveCeiling(project({ roeEnabled: false, roeGlobalMaxRps: 3 }))).toBeNull()
  })

  test('a switch with no number is not a ceiling either', () => {
    expect(effectiveCeiling(project({ roeEnabled: true, roeGlobalMaxRps: 0 }))).toBeNull()
  })

  test('both together is a ceiling', () => {
    expect(effectiveCeiling(project({ roeEnabled: true, roeGlobalMaxRps: 3 }))).toBe(3)
  })
})

describe('a third-party engagement is blocked until both exist', () => {
  const third = (over: Partial<EngagementProjectRow> = {}) =>
    project({ engagementKind: 'third_party', roeEnabled: true, roeGlobalMaxRps: 3, ...over })

  test('a ceiling and a record together make it startable', () => {
    const status = describeEngagement(third(), 1)
    expect(status.blockers).toEqual([])
    expect(status.ceilingRps).toBe(3)
    expect(status.hasAuthorization).toBe(true)
  })

  test('no authorization blocks it, naming the tool that fixes it', () => {
    const status = describeEngagement(third(), 0)
    expect(status.blockers).toHaveLength(1)
    expect(status.blockers[0]).toMatch(/attach_engagement_authorization/)
  })

  test('a zero ceiling blocks it, saying what zero means', () => {
    const status = describeEngagement(third({ roeGlobalMaxRps: 0 }), 1)
    expect(status.blockers[0]).toMatch(/NO ceiling/)
  })

  test('the switch off blocks it even with a number written', () => {
    const status = describeEngagement(third({ roeEnabled: false, roeGlobalMaxRps: 3 }), 1)
    expect(status.blockers[0]).toMatch(/switched off/)
  })

  test('two missing things produce two blockers, not one', () => {
    // An operator who fixes the first and retries should not discover the
    // second one call later.
    const status = describeEngagement(third({ roeEnabled: false }), 0)
    expect(status.blockers).toHaveLength(2)
  })

  test('a missing identity header warns without blocking', () => {
    // Many programs require one, and none of them are enforced by us.
    const status = describeEngagement(third(), 1)
    expect(status.blockers).toEqual([])
    expect(status.warnings.join(' ')).toMatch(/identity header/)
  })
})

describe('the existing estate is flagged, not broken', () => {
  test('an internal project with no ceiling still starts, loudly', () => {
    // Every project created before engagement kinds existed reads as internal
    // with no ceiling. Blocking them would turn the whole estate red at once,
    // which is not a fix.
    const status = describeEngagement(project(), 0)
    expect(status.blockers).toEqual([])
    expect(status.warnings.join(' ')).toMatch(/NO request-rate ceiling/)
  })

  test('an internal project WITH a ceiling gets no warning', () => {
    const status = describeEngagement(
      project({ roeEnabled: true, roeGlobalMaxRps: 10 }),
      0
    )
    expect(status.warnings).toEqual([])
  })

  test('an unrecognised engagementKind reads as internal rather than throwing', () => {
    // A value written before the enum was constrained, or by a future version.
    // Reading it as internal keeps the project working; reading it as
    // third_party would block a project nobody converted.
    const status = describeEngagement(project({ engagementKind: 'something_else' }), 0)
    expect(status.kind).toBe('internal')
  })
})

describe('the authorization record is a digest, never the document', () => {
  test('the digest of a document is its sha256', () => {
    const digest = digestScopeDocument('in scope: *.example.com\nout: admin.example.com\n')
    expect(digest).toMatch(/^[0-9a-f]{64}$/)
    expect(digestScopeDocument('different')).not.toBe(digest)
  })

  test('the same document always digests the same', () => {
    const text = 'a scope document'
    expect(digestScopeDocument(text)).toBe(digestScopeDocument(text))
  })

  test('only 64 lower-case hex is a digest', () => {
    expect(isSha256('a'.repeat(64))).toBe(true)
    expect(isSha256('A'.repeat(64))).toBe(false)
    expect(isSha256('a'.repeat(63))).toBe(false)
    expect(isSha256('')).toBe(false)
    expect(isSha256(null)).toBe(false)
  })

  test('the document kinds cover the formats a scope actually arrives in', () => {
    // The point of storing only a digest is that the model works the same for
    // any of them and parses none of them.
    for (const kind of ['hackerone_program', 'bugcrowd_program', 'roe_document', 'internal_ticket']) {
      expect(isDocumentKind(kind), kind).toBe(true)
    }
    expect(isDocumentKind('made_up')).toBe(false)
    expect(DOCUMENT_KINDS).toContain('other')
  })

  test('only the two engagement kinds are engagement kinds', () => {
    expect(isEngagementKind('internal')).toBe(true)
    expect(isEngagementKind('third_party')).toBe(true)
    expect(isEngagementKind('thirdparty')).toBe(false)
    expect(isEngagementKind(undefined)).toBe(false)
  })
})
