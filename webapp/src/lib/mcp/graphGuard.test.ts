/**
 * Result post-validation.
 *
 * This is defence in depth, not the primary control: `scope_query` scopes the
 * query server-side. It exists because that filter HAS failed once - an
 * unlabelled `MATCH (n)` used to bypass it entirely and return another
 * project's data - and on an internet-reachable surface the same regression
 * would be a remote cross-tenant breach rather than a sandbox-local one.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { assertTenantScoped, TenantViolation, GLOBAL_REFERENCE_LABELS } from './graphGuard'

const node = (labels: string[], props: Record<string, unknown>) => ({
  _kind: 'node',
  labels,
  properties: props,
})

const rel = (type: string, props: Record<string, unknown> = {}) => ({
  _kind: 'relationship',
  type,
  properties: props,
})

const OWN = { user_id: 'u1', project_id: 'p1' }

describe('own-tenant data passes', () => {
  test('a node carrying the right tenant key is allowed', () => {
    expect(() => assertTenantScoped([{ n: node(['IP'], { ...OWN, address: '10.0.0.1' }) }], 'u1', 'p1'))
      .not.toThrow()
  })

  test('an empty result is allowed', () => {
    expect(() => assertTenantScoped([], 'u1', 'p1')).not.toThrow()
  })

  test('scalar projections pass (they carry no keys to check)', () => {
    // The accepted, documented residual: `RETURN i.address` has nothing to
    // validate, so scope_query alone bounds it.
    expect(() => assertTenantScoped([{ 'i.address': '10.0.0.1' }], 'u1', 'p1')).not.toThrow()
  })

  test('deeply nested own-tenant nodes pass', () => {
    const records = [{ path: { hops: [node(['Host'], OWN), node(['Service'], OWN)] } }]
    expect(() => assertTenantScoped(records, 'u1', 'p1')).not.toThrow()
  })
})

describe('cross-tenant data is caught', () => {
  test("another user's node throws", () => {
    expect(() =>
      assertTenantScoped([{ n: node(['IP'], { user_id: 'mallory', project_id: 'p1' }) }], 'u1', 'p1')
    ).toThrow(TenantViolation)
  })

  test("another PROJECT of the same user throws", () => {
    // user_id alone is not the tenant key: project_id is half of it.
    expect(() =>
      assertTenantScoped([{ n: node(['IP'], { user_id: 'u1', project_id: 'p2' }) }], 'u1', 'p1')
    ).toThrow(TenantViolation)
  })

  test('a node with NO tenant keys throws', () => {
    // Every entity node is written with the tenant key, so a missing one means
    // the filter did not apply - exactly the historical bypass.
    expect(() => assertTenantScoped([{ n: node(['IP'], { address: '10.0.0.1' }) }], 'u1', 'p1'))
      .toThrow(TenantViolation)
  })

  test('one bad node in a large good result still throws', () => {
    const records = [
      ...Array.from({ length: 50 }, () => ({ n: node(['IP'], OWN) })),
      { n: node(['IP'], { user_id: 'mallory', project_id: 'pX' }) },
    ]
    expect(() => assertTenantScoped(records, 'u1', 'p1')).toThrow(TenantViolation)
  })

  test('a nested foreign node is caught, not just a top-level one', () => {
    const records = [{ wrapper: { deep: [{ n: node(['Host'], { user_id: 'x', project_id: 'y' }) }] } }]
    expect(() => assertTenantScoped(records, 'u1', 'p1')).toThrow(TenantViolation)
  })

  test('the violation records what was seen, for the audit line', () => {
    try {
      assertTenantScoped([{ n: node(['Secret'], { user_id: 'x', project_id: 'y' }) }], 'u1', 'p1')
      throw new Error('unreachable')
    } catch (e) {
      expect(e).toBeInstanceOf(TenantViolation)
      const v = e as TenantViolation
      expect(v.detail.labels).toEqual(['Secret'])
      expect(v.detail.sawUserId).toBe('x')
    }
  })
})

describe('global reference nodes are untenanted by design', () => {
  test.each([...GLOBAL_REFERENCE_LABELS])('a bare %s node passes without tenant keys', label => {
    expect(() => assertTenantScoped([{ c: node([label], { id: 'CVE-2021-1' }) }], 'u1', 'p1'))
      .not.toThrow()
  })

  test('a node mixing a reference label with a tenanted one is NOT exempt', () => {
    // Otherwise a foreign node could be smuggled out by adding :CVE to it.
    expect(() =>
      assertTenantScoped([{ n: node(['CVE', 'Vulnerability'], { user_id: 'x', project_id: 'y' }) }], 'u1', 'p1')
    ).toThrow(TenantViolation)
  })

  test('an unknown label is not treated as a reference label', () => {
    expect(() => assertTenantScoped([{ n: node(['SomethingNew'], {}) }], 'u1', 'p1'))
      .toThrow(TenantViolation)
  })
})

describe('relationships', () => {
  test('a relationship with no keys of its own is allowed', () => {
    // Its endpoints are validated; the edge itself need carry nothing.
    expect(() => assertTenantScoped([{ r: rel('RESOLVES_TO') }], 'u1', 'p1')).not.toThrow()
  })

  test('a relationship carrying the WRONG tenant key throws', () => {
    expect(() =>
      assertTenantScoped([{ r: rel('RESOLVES_TO', { user_id: 'x', project_id: 'y' }) }], 'u1', 'p1')
    ).toThrow(TenantViolation)
  })

  test('a relationship carrying the right key passes', () => {
    expect(() => assertTenantScoped([{ r: rel('RESOLVES_TO', OWN) }], 'u1', 'p1')).not.toThrow()
  })
})
