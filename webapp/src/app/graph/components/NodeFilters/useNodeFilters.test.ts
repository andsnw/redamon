/**
 * useNodeFilters across a project switch.
 *
 * The page keeps the Mute Rules view mounted when the project changes, so a
 * slow answer for the previous project can arrive after the new one's. Landing
 * it would show project A's rules under project B, and Save would then write
 * A's rules into B.
 *
 * Run: npx vitest run src/app/graph/components/NodeFilters/useNodeFilters.test.ts
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useNodeFilters } from './useNodeFilters'

const doc = (name: string) => ({ version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [
  { id: 'k3f9a2', name, enabled: true, all: [{ field: 'severity', op: 'in', value: ['info'] }] },
] } } })
const state = (revision: number, name: string) => ({
  mode: 'denylist', applyToScans: false, rules: doc(name), revision, exists: true,
  exemptionCounts: {}, activeVersion: null, lastRun: null, lastCompleted: null, liveRunId: null,
})
const reply = (body: unknown) => ({ ok: true, status: 200, json: () => Promise.resolve(body) })

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('useNodeFilters', () => {
  test('late_load_crosses_projects: a slow answer for the previous project never lands under the new one', async () => {
    let releaseA: () => void = () => {}
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url.includes('/projects/pA/')) {
        return new Promise(resolve => { releaseA = () => resolve(reply(state(11, 'Rules of A'))) })
      }
      return Promise.resolve(reply(state(22, 'Rules of B')))
    }))

    const { result, rerender } = renderHook(({ pid }) => useNodeFilters(pid), { initialProps: { pid: 'pA' } })
    rerender({ pid: 'pB' })
    await waitFor(() => expect(result.current.saved?.revision).toBe(22))

    await act(async () => { releaseA() })
    expect(result.current.saved?.revision).toBe(22)
    expect(result.current.draft.kinds['vuln.nuclei'].rules[0].name).toBe('Rules of B')
    expect(result.current.dirty).toBe(false)
  })
})
