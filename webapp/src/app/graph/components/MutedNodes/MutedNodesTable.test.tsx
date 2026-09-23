/**
 * Muted Nodes: its states, unmuting, and the link from a rule mute to its rule.
 *
 * Run: npx vitest run src/app/graph/components/MutedNodes/MutedNodesTable.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const toast = { success: vi.fn(), warning: vi.fn(), error: vi.fn(), info: vi.fn() }
const alertError = vi.fn()

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError }),
  useToast: () => toast,
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

import { MutedNodesTable } from './MutedNodesTable'

const row = (over: Record<string, unknown> = {}) => ({
  id: 'v1', label: 'Vulnerability', name: 'tech-detect:nginx', severity: 'info', source: 'nuclei',
  host: 'api.example.com', muted_at: '2026-09-23T10:00:00Z', muted_by: 'rule:vuln.nuclei/k3f9a2',
  muted_via: 'rule', muted_reason: 'Filter rule: Informational templates', stale_since: null,
  triage_status: 'unreviewed', triage_reason: null, rule_kind: 'vuln.nuclei', rule_id: 'k3f9a2',
  rule_name: 'Informational templates', rule_deleted: false, ...over,
})

function reply(body: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('MutedNodesTable', () => {
  test('lists rule and person mutes, and says which', async () => {
    fetchMock.mockReturnValue(reply({
      total: 3,
      findings: [
        row(),
        row({ id: 'v2', name: 'aws key', label: 'Secret', source: 'jsluice', muted_by: 'u1', muted_via: 'person',
              rule_kind: null, rule_id: null, rule_name: null }),
        row({ id: 'v3', name: 'GHSA on lodash', muted_by: 'rule:vuln.osv/gone01', rule_name: null, rule_deleted: true,
              muted_reason: 'Filter rule: Old advisories', stale_since: '2026-09-22T00:00:00Z' }),
      ],
      facets: { total: 3, by_person: 1, labels: { Vulnerability: 2, Secret: 1 }, rules: [] },
    }))
    const onOpenRule = vi.fn()
    render(<MutedNodesTable projectId="p1" onOpenRule={onOpenRule} />)
    expect(await screen.findByText('tech-detect:nginx')).toBeInTheDocument()
    expect(screen.getByText('you')).toBeInTheDocument()
    expect(screen.getByText('Rule (deleted): Filter rule: Old advisories')).toBeInTheDocument()
    expect(screen.getByText('resolved: no longer reported')).toBeInTheDocument()
    // A live rule links to it; a deleted one cannot.
    fireEvent.click(screen.getByText('Rule: Informational templates'))
    expect(onOpenRule).toHaveBeenCalledWith('vuln.nuclei', 'k3f9a2')
    const first = String(fetchMock.mock.calls[0][0])
    expect(first).toContain('/api/triage/muted?projectId=p1&offset=0&limit=50')
    expect(first).toContain('facets=1')
  })

  test('nothing muted at all', async () => {
    fetchMock.mockReturnValue(reply({ total: 0, findings: [], facets: { total: 0, by_person: 0, labels: {}, rules: [] } }))
    render(<MutedNodesTable projectId="p1" />)
    expect(await screen.findByText('Nothing is muted in this project.')).toBeInTheDocument()
  })

  test('nothing matching the filters offers to clear them', async () => {
    fetchMock.mockReturnValue(reply({ total: 0, findings: [] }))
    render(<MutedNodesTable projectId="p1" />)
    await screen.findByText('Nothing is muted in this project.')
    fireEvent.change(screen.getByLabelText('Muted by'), { target: { value: 'rule' } })
    expect(await screen.findByText('No muted nodes match these filters.')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Clear filters'))
    await screen.findByText('Nothing is muted in this project.')
    expect(String(fetchMock.mock.calls.at(-1)![0])).not.toContain('mutedVia')
  })

  test('a failed load offers a retry', async () => {
    fetchMock.mockReturnValueOnce(reply({ error: 'agent down' }, 503))
    render(<MutedNodesTable projectId="p1" />)
    expect(await screen.findByText('agent down')).toBeInTheDocument()
    fetchMock.mockReturnValue(reply({ total: 1, findings: [row()] }))
    fireEvent.click(screen.getByText('Retry'))
    expect(await screen.findByText('tech-detect:nginx')).toBeInTheDocument()
  })

  test('Unmute sends the key as JSON and reloads', async () => {
    fetchMock.mockImplementation((url: string, init?: RequestInit) =>
      init?.method === 'POST'
        ? reply({ unmuted: 1, items: [{ key: 'v1' }], exempted: 1 })
        : reply({ total: 1, findings: [row()] }))
    render(<MutedNodesTable projectId="p1" />)
    fireEvent.click((await screen.findAllByText('Unmute'))[0])
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')!
    expect(post[0]).toBe('/api/triage/unmute')
    expect(post[1].headers).toEqual({ 'Content-Type': 'application/json' })
    expect(JSON.parse(post[1].body)).toEqual({ projectId: 'p1', keys: ['v1'] })
  })

  test('a selection is unmuted in one request', async () => {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) =>
      init?.method === 'POST'
        ? reply({ unmuted: 2, items: [{ key: 'v1' }, { key: 'v2' }], exempted: 2 })
        : reply({ total: 2, findings: [row(), row({ id: 'v2', name: 'other' })] }))
    render(<MutedNodesTable projectId="p1" />)
    await screen.findByText('other')
    fireEvent.click(screen.getByLabelText('Select all on this page'))
    fireEvent.click(screen.getByText(/Unmute selected \(2\)/))
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Unmuted 2 findings.'))
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')!
    expect(JSON.parse(post[1].body).keys).toEqual(['v1', 'v2'])
  })

  test('an unmute whose exemption was not saved warns', async () => {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) =>
      init?.method === 'POST'
        ? reply({ unmuted: 1, items: [{ key: 'v1' }], exempted: 0, exemptionError: 'a filter rule may mute it again' })
        : reply({ total: 1, findings: [row()] }))
    render(<MutedNodesTable projectId="p1" />)
    fireEvent.click((await screen.findAllByText('Unmute'))[0])
    await waitFor(() => expect(toast.warning).toHaveBeenCalledWith('a filter rule may mute it again'))
  })

  test('pages forward', async () => {
    fetchMock.mockReturnValue(reply({ total: 120, findings: [row()] }))
    render(<MutedNodesTable projectId="p1" />)
    expect(await screen.findByText(/1 of 3/)).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('Next page'))
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('offset=50'))
  })
})
