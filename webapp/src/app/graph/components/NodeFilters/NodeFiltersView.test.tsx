/**
 * The Node Filters page: its states, the armed status, saving (and a save that
 * lost a race), and the live preview.
 *
 * Run: npx vitest run src/app/graph/components/NodeFilters/NodeFiltersView.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

const confirm = vi.fn()
const alertError = vi.fn()
const toast = { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ confirm, alertError }),
  useToast: () => toast,
  WikiInfoButton: () => null,
  Toggle: ({ checked, onChange, disabled, 'aria-label': label }: {
    checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; 'aria-label'?: string
  }) => (
    <input type="checkbox" aria-label={label} checked={checked} disabled={disabled}
      onChange={e => onChange(e.target.checked)} />
  ),
  Modal: ({ isOpen, children, footer }: { isOpen: boolean; children: ReactNode; footer?: ReactNode }) =>
    (isOpen ? <div>{children}{footer}</div> : null),
}))

import { NodeFiltersView } from './NodeFiltersView'

const RULE = { id: 'k3f9a2', name: 'Informational templates', enabled: true,
               all: [{ field: 'severity', op: 'in', value: ['info'] }] }
const STATE = {
  mode: 'denylist', applyToScans: true, revision: 3, exists: true,
  rules: { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [RULE] } } },
  exemptionCounts: { Vulnerability: 2 }, activeVersion: { id: 'v7', label: 'Scan 7' },
  lastRun: null, lastCompleted: null, liveRunId: null,
}
const PREVIEW = {
  ok: true, partial: false, totals: { scanned: 1930, to_mute: 412, to_unmute: 0 },
  kinds: { 'vuln.nuclei': { active: true, scanned: 1930, would_mute: 412, to_mute: 412, to_unmute: 0,
    to_restamp: 0, guarded: 14, exempt: 2, operator_muted: 0, missing: {},
    rules: { k3f9a2: { name: 'Informational templates', matched: 398,
      samples: [{ key: 'v1', name: 'tech-detect:nginx', host: 'api.example.com', guards: [] }] } } } },
}

function reply(body: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })
}

let fetchMock: ReturnType<typeof vi.fn>
let putStatus = 200

beforeEach(() => {
  putStatus = 200
  fetchMock = vi.fn((url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url.endsWith('/node-filters') && method === 'GET') return reply(STATE)
    if (url.endsWith('/node-filters') && method === 'PUT') {
      return putStatus === 200 ? reply({ ok: true, revision: 4 }) : reply({ error: 'changed', currentRevision: 5 }, putStatus)
    }
    if (url.endsWith('/preview')) return reply(PREVIEW)
    if (url.endsWith('/disarm')) return reply({ armed: false })
    if (url.endsWith('/apply') && method === 'GET') return reply({ busy: null, activeVersion: STATE.activeVersion })
    if (url.endsWith('/apply') && method === 'POST') return reply({ runId: 'run1', armed: true }, 202)
    if (url.includes('/runs/')) return reply({ id: 'run1', status: 'running', stats: null })
    return reply({}, 404)
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

const view = (props: Partial<Parameters<typeof NodeFiltersView>[0]> = {}) =>
  render(<NodeFiltersView projectId="p1" isViewingPastVersion={false} {...props} />)

describe('NodeFiltersView', () => {
  test('a project the caller does not own shows nothing to edit', async () => {
    fetchMock.mockImplementation(() => reply({ error: 'Not found' }, 404))
    view()
    expect(await screen.findByText('Node filters are not available for this project.')).toBeInTheDocument()
  })

  test('shows the armed state and turns it off', async () => {
    const onStatusChange = vi.fn()
    view({ onStatusChange })
    expect(await screen.findByText(/Active on new scans · 1 rule in 1 kind · denylist/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Turn off'))
    await waitFor(() => expect(onStatusChange).toHaveBeenCalled())
    const disarm = fetchMock.mock.calls.find(c => String(c[0]).endsWith('/disarm'))!
    expect(disarm[1].headers).toEqual({ 'Content-Type': 'application/json' })
  })

  test('the preview counts, per kind and per rule, with examples', async () => {
    view()
    expect(await screen.findByText('412', {}, { timeout: 3000 })).toBeInTheDocument()
    expect(screen.getByText(/14 kept by guards/)).toBeInTheDocument()
    expect(screen.getByText('· 2 exempt')).toBeInTheDocument()
    expect(screen.getByText('398')).toBeInTheDocument()
    expect(screen.getByText('tech-detect:nginx')).toBeInTheDocument()
    expect(screen.getByText('Clear 2 exemptions')).toBeInTheDocument()
  })

  test('Save is only possible with unsaved changes, and sends the loaded revision', async () => {
    view()
    const save = await screen.findByText('Save')
    expect((save as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByLabelText('Filter Nuclei'))
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Rules saved.', 'Node filters'))
    const put = fetchMock.mock.calls.find(c => c[1]?.method === 'PUT')!
    const body = JSON.parse(put[1].body)
    expect(body.revision).toBe(3)
    expect(body.rules.kinds['vuln.nuclei'].enabled).toBe(false)
  })

  test('a save that lost a race offers Overwrite, which forces it', async () => {
    putStatus = 409
    confirm.mockResolvedValue(true)
    view()
    await screen.findByText('Save')
    fireEvent.click(screen.getByLabelText('Filter Nuclei'))
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(confirm).toHaveBeenCalled())
    await waitFor(() => {
      const puts = fetchMock.mock.calls.filter(c => c[1]?.method === 'PUT')
      expect(JSON.parse(puts.at(-1)![1].body).force).toBe(true)
    })
  })

  test('conflict_dialog_dismiss_discards_edits: closing the conflict dialog keeps the edits', async () => {
    // Escape, the X and Cancel all resolve the dialog as "no". That used to mean
    // "reload theirs", so dismissing it threw every unsaved edit away.
    putStatus = 409
    confirm.mockResolvedValue(false)
    view()
    await screen.findByText('Save')
    fireEvent.click(screen.getByLabelText('Filter Nuclei'))
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(confirm).toHaveBeenCalled())
    await waitFor(() => expect(fetchMock.mock.calls.filter(c => (c[1]?.method ?? 'GET') === 'GET'
      && String(c[0]).endsWith('/node-filters')).length).toBe(2))
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
    expect((screen.getByLabelText('Filter Nuclei') as HTMLInputElement).checked).toBe(false)
  })

  test('an invalid rule blocks Save and Apply and is marked', async () => {
    view()
    const name = await screen.findByDisplayValue('Informational templates')
    fireEvent.change(name, { target: { value: '<b>bad</b>' } })
    expect(await screen.findByText(/rule names are 1-80 letters/)).toBeInTheDocument()
    expect((screen.getByText('Save') as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByText('Apply…') as HTMLButtonElement).disabled).toBe(true)
  })

  test('an inactive kind says nothing is filtered, not "0 of 0"', async () => {
    view({ focus: { kind: 'secret' } })
    expect(await screen.findByText('Nothing is filtered.')).toBeInTheDocument()
  })

  test('a link from Muted Nodes opens the rule\'s kind', async () => {
    view({ focus: { kind: 'secret' } })
    expect(await screen.findByRole('heading', { name: 'Secrets' })).toBeInTheDocument()
  })

  test('apply targets the version on screen, not the one the server calls active', async () => {
    // The page shows v5 while the server has since moved to v7 (another tab
    // activated it). Sending v7 would let the server's "only the active
    // version" check pass and apply to a graph the operator is not looking at.
    view({ viewedVersionId: 'v5' })
    fireEvent.click(await screen.findByText('Apply…'))
    const confirmApply = await screen.findByRole('button', { name: 'Apply' })
    await waitFor(() => expect((confirmApply as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(confirmApply)
    await waitFor(() => expect(fetchMock.mock.calls.some(c => c[1]?.method === 'POST' && String(c[0]).endsWith('/apply'))).toBe(true))
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST' && String(c[0]).endsWith('/apply'))!
    expect(JSON.parse(post[1].body)).toMatchObject({ versionId: 'v5', revision: 3 })
  })

  test('switching to allowlist while armed asks first', async () => {
    confirm.mockResolvedValue(false)
    view()
    fireEvent.click(await screen.findByText('Allowlist: keep only what matches'))
    await waitFor(() => expect(confirm).toHaveBeenCalled())
    expect(screen.queryByText('Unsaved changes')).toBeNull()
  })
})
