/**
 * The Apply modal: when "current graph" is offered, and what it applies.
 *
 * Run: npx vitest run src/app/graph/components/NodeFilters/ApplyModal.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

vi.mock('@/components/ui', () => ({
  Modal: ({ isOpen, children, footer, title }: { isOpen: boolean; children: ReactNode; footer: ReactNode; title: string }) =>
    isOpen ? <div role="dialog" aria-label={title}>{children}{footer}</div> : null,
}))

import { ApplyModal, currentGraphBlocker } from './ApplyModal'
import { NODE_FILTER_CATALOG } from '@/lib/nodeFilters/catalog'

const RULES = { version: 1 as const, kinds: {} }
const PREVIEW = {
  ok: true, partial: false,
  totals: { scanned: 100, to_mute: 60, to_unmute: 2 },
  kinds: { 'vuln.nuclei': { scanned: 100, would_mute: 60 } },
  relatedRemediations: 3,
}

function reply(body: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })
}

let fetchMock: ReturnType<typeof vi.fn>

function wire({ busy = null as string | null, preview = PREVIEW as unknown, previewStatus = 200 } = {}) {
  fetchMock.mockImplementation((url: string) =>
    url.endsWith('/node-filters/apply')
      ? reply({ busy, activeVersion: { id: 'v7', label: 'Scan 7' } })
      : reply(preview, previewStatus))
}

function open(props: Partial<Parameters<typeof ApplyModal>[0]> = {}) {
  const onConfirm = vi.fn().mockResolvedValue(undefined)
  render(
    <ApplyModal
      isOpen onClose={vi.fn()} projectId="p1" catalog={NODE_FILTER_CATALOG} mode="denylist"
      rules={RULES} ruleCount={2} dirty={false} isViewingPastVersion={false} onConfirm={onConfirm}
      {...props}
    />,
  )
  return onConfirm
}

beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ApplyModal', () => {
  test('on a free graph it offers all three, defaulting to both, with the counts', async () => {
    wire()
    const onConfirm = open()
    expect(await screen.findByText(/Mutes 60 nodes now and unmutes 2/)).toBeInTheDocument()
    expect(screen.getByText('Current graph: Scan 7')).toBeInTheDocument()
    expect((screen.getByDisplayValue('both') as HTMLInputElement).checked).toBe(true)
    expect(screen.getByText(/More than half of Nuclei would be muted/)).toBeInTheDocument()
    expect(screen.getByText(/3 open CypherFix remediations may/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Apply'))
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith('both'))
    // The preview asked for the remediation count.
    const previewCall = fetchMock.mock.calls.find(c => String(c[0]).endsWith('/preview'))!
    expect(JSON.parse(previewCall[1].body).withRemediations).toBe(true)
  })

  test('a past version allows New scans only, and says why', async () => {
    wire()
    const onConfirm = open({ isViewingPastVersion: true, viewedVersionLabel: 'Scan 3' })
    expect((await screen.findAllByText(/You are viewing Scan 3/)).length).toBeGreaterThan(0)
    await waitFor(() => expect((screen.getByDisplayValue('scans') as HTMLInputElement).checked).toBe(true))
    expect((screen.getByDisplayValue('current') as HTMLInputElement).disabled).toBe(true)
    expect((screen.getByDisplayValue('both') as HTMLInputElement).disabled).toBe(true)
    fireEvent.click(screen.getByText('Apply'))
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith('scans'))
  })

  test('a running scan blocks the current graph', async () => {
    wire({ busy: 'a full recon scan is running' })
    open()
    expect((await screen.findAllByText(/A full recon scan is running; apply to the current graph when it finishes/)).length)
      .toBeGreaterThan(0)
  })

  test('an unreachable agent blocks the current graph', async () => {
    wire({ preview: { error: 'down' }, previewStatus: 503 })
    open()
    expect((await screen.findAllByText(/Cannot reach the agent/)).length).toBeGreaterThan(0)
  })

  test('says it will save first when there are unsaved changes', async () => {
    wire()
    open({ dirty: true })
    expect(await screen.findByText(/Saves the rules \(denylist, 2 rules\)/)).toBeInTheDocument()
  })
})

describe('currentGraphBlocker', () => {
  const base = { isViewingPastVersion: false, readiness: { busy: null, activeVersion: null },
                 preview: null, previewFailed: false }
  test('an empty graph has nothing to apply to', () => {
    expect(currentGraphBlocker({ ...base, preview: { ok: true, partial: false, kinds: {}, totals: { scanned: 0 } } }))
      .toMatch(/none of these findings/)
  })
  test('free', () => {
    expect(currentGraphBlocker(base)).toBeNull()
  })
})
