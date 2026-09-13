/**
 * The MCP Access Tokens tab.
 *
 * The states pinned here are the ones that, when missed, cause a real support
 * problem rather than a cosmetic one:
 *
 *  - a loading SKELETON, never a flash of the empty state (which reads as "you
 *    have no tokens" and prompts a duplicate mint)
 *  - a fetch error shown INLINE with a retry, never a silent empty list
 *  - create-in-flight disables submit, so a double-click cannot mint two tokens
 *  - permission-denied renders the form DISABLED WITH A REASON, rather than a
 *    button that 403s on click
 *  - the one-time reveal says plainly that it will not be shown again
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

const h = vi.hoisted(() => ({ dangerConfirm: vi.fn(), alertError: vi.fn() }))

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ dangerConfirm: h.dangerConfirm, alertError: h.alertError }),
}))
vi.mock('@/hooks/useUnsavedChangesGuard', () => ({
  useUnsavedChangesGuard: () => ({ guardedNavigate: vi.fn() }),
}))

import McpTokensTab from './McpTokensTab'

const TOKEN = {
  id: 't1',
  name: 'ci agent',
  tokenPrefix: 'rdmn_mcp_a3f9c21e',
  scopes: ['recon:read'],
  lastUsedAt: null,
  expiresAt: null,
  revokedAt: null,
  createdAt: '2026-09-01T10:00:00.000Z',
}

/** Route fetch by URL so the component's two parallel loads both resolve. */
function mockFetch(handlers: {
  me?: unknown
  meStatus?: number
  tokens?: unknown
  tokensStatus?: number
  create?: unknown
  createStatus?: number
  onCreate?: () => void
}) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    if (String(url).includes('/api/auth/me')) {
      return {
        ok: (handlers.meStatus ?? 200) < 400,
        status: handlers.meStatus ?? 200,
        json: async () => handlers.me ?? { id: 'owner', role: 'standard' },
      }
    }
    if (init?.method === 'POST') {
      handlers.onCreate?.()
      return {
        ok: (handlers.createStatus ?? 201) < 400,
        status: handlers.createStatus ?? 201,
        json: async () => handlers.create ?? { plaintext: 'rdmn_mcp_' + 'a'.repeat(48), token: TOKEN },
      }
    }
    return {
      ok: (handlers.tokensStatus ?? 200) < 400,
      status: handlers.tokensStatus ?? 200,
      json: async () => handlers.tokens ?? { tokens: [] },
    }
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(cleanup)

describe('loading and error states', () => {
  test('shows a skeleton while loading, never the empty state', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<McpTokensTab userId="owner" />)

    expect(screen.getByLabelText('Loading tokens')).toBeTruthy()
    expect(screen.queryByText(/No MCP access tokens yet/)).toBeNull()
  })

  test('a fetch failure is shown inline with a retry, not as an empty list', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokensStatus: 500 }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/request failed \(500\)/)).toBeTruthy())
    expect(screen.getByText('Retry')).toBeTruthy()
    expect(screen.queryByText(/No MCP access tokens yet/)).toBeNull()
  })

  test('an empty list explains what a token is for', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/No MCP access tokens yet/)).toBeTruthy())
  })
})

describe('the list', () => {
  test('renders a token by its masked prefix, never a full token', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [TOKEN] } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    expect(screen.getByText(/rdmn_mcp_a3f9c21e…/)).toBeTruthy()
  })

  test('"Never" and "Never used" are shown rather than blanks', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [TOKEN] } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('Never')).toBeTruthy())
    expect(screen.getByText('Never used')).toBeTruthy()
  })

  test('a revoked token is flagged rather than hidden', async () => {
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [{ ...TOKEN, revokedAt: '2026-09-02T00:00:00.000Z' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('revoked')).toBeTruthy())
  })

  test('an expired token is flagged rather than hidden', async () => {
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [{ ...TOKEN, expiresAt: '2020-01-01T00:00:00.000Z' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('expired')).toBeTruthy())
  })

  test('a revoked token offers no Revoke button', async () => {
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [{ ...TOKEN, revokedAt: '2026-09-02T00:00:00.000Z' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('revoked')).toBeTruthy())
    expect(screen.queryByTitle('Revoke')).toBeNull()
  })
})

describe('permission denied renders a reason, not a button that 403s', () => {
  test('an admin viewing another user cannot open the create form', async () => {
    vi.stubGlobal('fetch', mockFetch({ me: { id: 'admin1', role: 'admin' } }))
    render(<McpTokensTab userId="victim" />)

    await waitFor(() => expect(screen.getByText(/can only be created by its own user/)).toBeTruthy())
    expect(screen.getByText('New token').closest('button')).toBeDisabled()
  })

  test('the owner can open the create form', async () => {
    vi.stubGlobal('fetch', mockFetch({ me: { id: 'owner', role: 'standard' } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    expect(screen.queryByText(/can only be created by its own user/)).toBeNull()
  })

  test('an unresolved session leaves minting disabled (the safe direction)', async () => {
    vi.stubGlobal('fetch', mockFetch({ meStatus: 401 }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/No MCP access tokens yet/)).toBeTruthy())
    expect(screen.getByText('New token').closest('button')).toBeDisabled()
  })
})

describe('the create form', () => {
  const openForm = async () => {
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.click(screen.getByText('New token'))
  }

  test('only recon:read is ticked by default', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    const read = screen.getByText('recon:read').closest('label')!.querySelector('input')!
    const scan = screen.getByText('recon:scan').closest('label')!.querySelector('input')!
    expect(read).toBeChecked()
    expect(scan).not.toBeChecked()
  })

  test('recon:overwrite says plainly that it discards the graph', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    expect(screen.getByText(/DISCARDS the current graph/)).toBeTruthy()
  })

  test('the default expiry is 90 days', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    expect((screen.getByLabelText('Expires') as HTMLSelectElement).value).toBe('90')
  })

  test('it asks for the password as a step-up', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    expect((screen.getByLabelText('Confirm your password') as HTMLInputElement).type).toBe('password')
  })

  test('a create failure keeps the form populated so nothing is retyped', async () => {
    vi.stubGlobal('fetch', mockFetch({ createStatus: 401, create: { error: 'Password is incorrect' } }))
    await openForm()

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci agent' } })
    fireEvent.click(screen.getByText('Create token'))

    await waitFor(() => expect(screen.getByText('Password is incorrect')).toBeTruthy())
    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('ci agent')
  })

  test('a double-click cannot mint two tokens', async () => {
    let creates = 0
    let release: (() => void) | undefined
    const gate = new Promise<void>(r => { release = r })
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ id: 'owner', role: 'standard' }) }
      }
      if (init?.method === 'POST') {
        creates++
        await gate
        return { ok: true, status: 201, json: async () => ({ plaintext: 'rdmn_mcp_x', token: TOKEN }) }
      }
      return { ok: true, status: 200, json: async () => ({ tokens: [] }) }
    }))
    await openForm()

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci' } })
    const submit = screen.getByText('Create token').closest('button')!
    fireEvent.click(submit)
    await waitFor(() => expect(submit).toBeDisabled())
    fireEvent.click(submit)

    release!()
    await waitFor(() => expect(creates).toBe(1))
  })
})

describe('the one-time reveal', () => {
  test('warns that the token will not be shown again, and shows a client snippet', async () => {
    const plaintext = 'rdmn_mcp_' + 'b'.repeat(48)
    vi.stubGlobal('fetch', mockFetch({ create: { plaintext, token: TOKEN } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.click(screen.getByText('New token'))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci' } })
    fireEvent.click(screen.getByText('Create token'))

    await waitFor(() => expect(screen.getByText(/will not be able to see it again/)).toBeTruthy())
    expect(screen.getByText(plaintext)).toBeTruthy()
    // The ready-to-paste config, so no hand editing is needed.
    expect(screen.getByText(/"mcpServers"/)).toBeTruthy()
  })
})

describe('revoking asks first, through the modal (never window.confirm)', () => {
  test('a declined confirm revokes nothing', async () => {
    h.dangerConfirm.mockResolvedValue(false)
    const fetchMock = mockFetch({ tokens: { tokens: [TOKEN] } })
    vi.stubGlobal('fetch', fetchMock)
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    fireEvent.click(screen.getByTitle('Revoke'))

    await waitFor(() => expect(h.dangerConfirm).toHaveBeenCalled())
    expect(fetchMock.mock.calls.some(c => c[1]?.method === 'DELETE')).toBe(false)
  })

  test('a confirmed revoke calls DELETE', async () => {
    h.dangerConfirm.mockResolvedValue(true)
    const fetchMock = mockFetch({ tokens: { tokens: [TOKEN] } })
    vi.stubGlobal('fetch', fetchMock)
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    fireEvent.click(screen.getByTitle('Revoke'))

    await waitFor(() =>
      expect(fetchMock.mock.calls.some(c => c[1]?.method === 'DELETE')).toBe(true)
    )
  })
})

describe('the two MCP tabs are distinguishable', () => {
  test('the subtitle names this one as INBOUND and the other as outbound', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/Inbound:/)).toBeTruthy())
    expect(screen.getByText(/MCP Tool Plugins/)).toBeTruthy()
  })
})
