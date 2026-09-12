/**
 * @vitest-environment jsdom
 *
 * Strategy row 6 (L2): the Tlsx partial-recon modal must offer IP and Port inputs.
 *
 * SECTION_INPUT_MAP only declares WHICH node types a tool reads. Whether the
 * operator actually gets a control is decided by the hasUserInputs / hasIpInput /
 * hasPortInput chains in this component. A tool missing from those chains renders
 * a modal that looks correctly wired -- title, description, node badges -- with no
 * way to supply a target. No unit test covers those chains, which is exactly why
 * this row exists.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tlsx.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

function mockFetch(ipCount: number, portCount: number) {
  return vi.fn((url: string) => {
    if (url.includes('/graph-inputs/')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({
          domain: 'acme.test', existing_subdomains: [], existing_subdomains_count: 0,
          existing_ips_count: ipCount, existing_ports_count: portCount, source: 'graph',
        }),
      } as Response)
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response)
  })
}

function renderModal(toolId: string) {
  return render(
    <PartialReconModal
      isOpen
      toolId={toolId}
      onClose={vi.fn()}
      onConfirm={vi.fn()}
      projectId="p1"
      targetDomain="acme.test"
      userId="u1"
    />,
  )
}

afterEach(cleanup)
beforeEach(() => { vi.stubGlobal('fetch', mockFetch(3, 7)) })

describe('PartialReconModal — Tlsx inputs', () => {
  test('offers the Custom IPs control', async () => {
    renderModal('Tlsx')
    expect((await screen.findAllByText(/Custom IPs/i)).length).toBeGreaterThan(0)
  })

  test('offers the Custom ports control (tlsx grabs certs per open port)', async () => {
    renderModal('Tlsx')
    expect((await screen.findAllByText(/Custom ports/i)).length).toBeGreaterThan(0)
  })

  test('renders a Tlsx-specific description, not the generic fallback', async () => {
    renderModal('Tlsx')
    const generic = /Runs this pipeline phase independently and merges results/i
    expect((await screen.findAllByText(/TLS certificate/i)).length).toBeGreaterThan(0)
    expect(screen.queryAllByText(generic).length).toBe(0)
  })

  test('the run button is reachable when the graph has IPs and ports', async () => {
    renderModal('Tlsx')
    const btn = await screen.findByRole('button', { name: /Run Partial Recon/i })
    expect((btn as HTMLButtonElement).disabled).toBe(false)
  })

  test('control: a tool with no IP input does not show the IPs control', async () => {
    // Proves the assertions above are driven by the Tlsx wiring, not by the
    // control being present for every tool.
    renderModal('Katana')
    expect(await screen.findByRole('button', { name: /Run Partial Recon/i })).toBeDefined()
    expect(screen.queryAllByText(/Custom IPs/i).length).toBe(0)
  })
})
