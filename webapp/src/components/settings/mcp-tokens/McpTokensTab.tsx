'use client'

/**
 * MCP Access Tokens - the INBOUND direction.
 *
 * The sibling "MCP Tool Plugins" tab is OUTBOUND (RedAmon connecting out to
 * servers the operator registers). This one mints credentials that let other
 * agents connect IN. Two tabs, opposite directions, so the subtitle says so
 * explicitly rather than relying on the reader to infer it from the name.
 */
import { useState, useEffect, useCallback } from 'react'
import {
  KeyRound, Plus, Loader2, Copy, Check, Trash2, Pencil,
  AlertTriangle, RefreshCw, ShieldAlert,
} from 'lucide-react'
import { useAlertModal } from '@/components/ui'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import {
  MCP_SCOPES,
  MCP_DEFAULT_EXPIRY_DAYS,
  DEFAULT_MCP_SCOPES,
  type McpScope,
} from '@/lib/mcpAuth'
import styles from './McpTokensTab.module.css'

interface Props {
  userId: string
  onDirtyChange?: (dirty: boolean) => void
}

interface TokenRow {
  id: string
  name: string
  tokenPrefix: string
  scopes: string[]
  lastUsedAt: string | null
  expiresAt: string | null
  revokedAt: string | null
  createdAt: string
}

/** Each write scope states its consequence, so a tick is an informed one. */
const SCOPE_COPY: Record<McpScope, { label: string; blurb: string; danger?: boolean }> = {
  'recon:read': {
    label: 'Read recon + graph',
    blurb: 'List projects, read scan status and settings, and query the attack-surface graph in natural language.',
  },
  'recon:scan': {
    label: 'Start and stop scans',
    blurb: 'Start a full recon pipeline (keeping the current graph as a saved version) and stop one it started.',
  },
  'recon:overwrite': {
    label: 'Discard the current graph on start',
    blurb: 'Permits starting a scan in overwrite mode, which DISCARDS the current graph instead of saving it as a version. This is the only irreversible action on this surface.',
    danger: true,
  },
  'recon:settings': {
    label: 'Change recon tuning settings',
    blurb: 'Change a narrow allowlist of recon tuning values. It can never change the target, scope, Rules of Engagement or any credential.',
  },
  'graph:cypher': {
    label: 'Run raw Cypher',
    blurb: 'Send read-only Cypher directly instead of a natural-language question. Still tenant-scoped and still read-only.',
  },
}

const EXPIRY_OPTIONS: { value: number | 'never'; label: string }[] = [
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: 90, label: '90 days' },
  { value: 365, label: '1 year' },
  { value: 'never', label: 'No expiry' },
]

const fmtDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : null

function tokenState(t: TokenRow): 'active' | 'revoked' | 'expired' {
  if (t.revokedAt) return 'revoked'
  if (t.expiresAt && new Date(t.expiresAt).getTime() <= Date.now()) return 'expired'
  return 'active'
}

function clientSnippet(token: string): string {
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://<redamon-host>'
  return JSON.stringify(
    { mcpServers: { redamon: { url: `${origin}/api/mcp-server`, headers: { Authorization: `Bearer ${token}` } } } },
    null,
    2
  )
}

export default function McpTokensTab({ userId, onDirtyChange }: Props) {
  const { dangerConfirm, alertError } = useAlertModal()

  const [tokens, setTokens] = useState<TokenRow[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  // The real session user. Minting is self-only on the REAL identity, so when
  // an admin is viewing someone else's settings the form is disabled WITH A
  // REASON rather than being a button that 403s on click.
  const [sessionUserId, setSessionUserId] = useState<string | null>(null)

  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState<McpScope[]>([...DEFAULT_MCP_SCOPES])
  const [expiresInDays, setExpiresInDays] = useState<number | 'never'>(MCP_DEFAULT_EXPIRY_DAYS)
  const [password, setPassword] = useState('')
  const [creating, setCreating] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [minted, setMinted] = useState<string | null>(null)
  const [copied, setCopied] = useState<'token' | 'snippet' | null>(null)

  // Renaming happens inline: the design system has no prompt modal, and
  // window.prompt is not allowed in this UI.
  const [renamingId, setRenamingId] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')

  const draft = { name, scopes, expiresInDays, password }
  const { isDirty, setBaseline } = useDirtyState(draft)
  const dirty = showForm && isDirty
  useUnsavedChangesGuard(dirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(dirty) }, [dirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const canMint = sessionUserId !== null && sessionUserId === userId

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const r = await fetch(`/api/users/${userId}/mcp-tokens`)
      if (!r.ok) throw new Error(`request failed (${r.status})`)
      const data = await r.json()
      setTokens(Array.isArray(data.tokens) ? data.tokens : [])
    } catch (e) {
      // Never a silent empty list: that reads as "you have no tokens" and
      // prompts a duplicate mint.
      setLoadError(e instanceof Error ? e.message : 'Could not load tokens')
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => { void load() }, [load])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        // /api/auth/me resolves getSession(), i.e. the REAL login identity, not
        // the act-as target. That is exactly the identity minting is judged on.
        const r = await fetch('/api/auth/me')
        if (!r.ok) return
        const data = await r.json()
        if (!cancelled) setSessionUserId(typeof data?.id === 'string' ? data.id : null)
      } catch {
        // Leaving it null keeps the form disabled, which is the safe direction.
      }
    })()
    return () => { cancelled = true }
  }, [])

  const resetForm = useCallback(() => {
    setName('')
    setScopes([...DEFAULT_MCP_SCOPES])
    setExpiresInDays(MCP_DEFAULT_EXPIRY_DAYS)
    setPassword('')
    setFormError(null)
    setBaseline({ name: '', scopes: [...DEFAULT_MCP_SCOPES], expiresInDays: MCP_DEFAULT_EXPIRY_DAYS, password: '' })
  }, [setBaseline])

  const toggleScope = (s: McpScope) => {
    setScopes(prev => (prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]))
  }

  const create = async () => {
    if (creating) return // a double-submit must not mint two tokens
    setCreating(true)
    setFormError(null)
    try {
      const r = await fetch(`/api/users/${userId}/mcp-tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, scopes, expiresInDays, password }),
      })
      const data = await r.json().catch(() => ({}))
      if (!r.ok) {
        // Keep the form populated so the operator does not retype everything.
        setFormError(data.error || `Could not create the token (${r.status})`)
        return
      }
      setMinted(data.plaintext)
      setShowForm(false)
      resetForm()
      await load()
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Could not create the token')
    } finally {
      setCreating(false)
    }
  }

  const revoke = async (t: TokenRow) => {
    const confirmed = await dangerConfirm(
      `Revoke '${t.name}' (${t.tokenPrefix}…)? Any agent using it stops working immediately. This cannot be undone.`,
      'Revoke MCP Access Token',
    )
    if (!confirmed) return
    try {
      const r = await fetch(`/api/users/${userId}/mcp-tokens/${t.id}`, { method: 'DELETE' })
      if (!r.ok) {
        const data = await r.json().catch(() => ({}))
        await alertError(data.error || `Revoke failed (${r.status})`, 'Revoke MCP Access Token')
        return
      }
      await load()
    } catch (e) {
      await alertError(e instanceof Error ? e.message : 'Revoke failed', 'Revoke MCP Access Token')
    }
  }

  const commitRename = async (t: TokenRow) => {
    const next = renameValue.trim()
    setRenamingId(null)
    if (!next || next === t.name) return
    try {
      const r = await fetch(`/api/users/${userId}/mcp-tokens/${t.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: next }),
      })
      if (!r.ok) {
        const data = await r.json().catch(() => ({}))
        await alertError(data.error || `Rename failed (${r.status})`, 'Rename MCP Access Token')
        return
      }
      await load()
    } catch (e) {
      await alertError(e instanceof Error ? e.message : 'Rename failed', 'Rename MCP Access Token')
    }
  }

  const copy = async (text: string, which: 'token' | 'snippet') => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(which)
      setTimeout(() => setCopied(null), 2000)
    } catch {
      await alertError('Could not copy to the clipboard. Select the text and copy it manually.', 'Copy')
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <div>
          <h3 className={styles.sectionTitle}>
            <KeyRound size={16} /> MCP Access Tokens
          </h3>
          <p className={styles.sectionDescription}>
            <strong>Inbound:</strong> let an external AI agent connect to RedAmon and act as you,
            within your own projects. (The <em>MCP Tool Plugins</em> tab is the opposite
            direction: RedAmon connecting out to other servers.)
          </p>
        </div>
        <div className={styles.headerActions}>
          <button className={styles.secondaryBtn} onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button
            className={styles.primaryBtn}
            onClick={() => { setShowForm(true); resetForm() }}
            disabled={!canMint || showForm}
          >
            <Plus size={14} /> New token
          </button>
        </div>
      </div>

      {sessionUserId !== null && !canMint && (
        <div className={styles.noticeBanner}>
          <ShieldAlert size={14} />
          <span>
            You are viewing another user&apos;s settings. A token can only be created by its own
            user, signed in as themselves. You can still review and revoke their tokens here.
          </span>
        </div>
      )}

      {minted && (
        <div className={styles.revealPanel}>
          <div className={styles.revealHeader}>
            <AlertTriangle size={15} />
            <strong>Copy this token now. You will not be able to see it again.</strong>
          </div>
          <div className={styles.revealRow}>
            <code className={styles.revealToken}>{minted}</code>
            <button className={styles.secondaryBtn} onClick={() => void copy(minted, 'token')}>
              {copied === 'token' ? <Check size={14} /> : <Copy size={14} />} Copy
            </button>
          </div>
          <p className={styles.muted}>Paste this into your MCP client&apos;s config:</p>
          <div className={styles.revealRow}>
            <pre className={styles.snippet}>{clientSnippet(minted)}</pre>
            <button className={styles.secondaryBtn} onClick={() => void copy(clientSnippet(minted), 'snippet')}>
              {copied === 'snippet' ? <Check size={14} /> : <Copy size={14} />} Copy
            </button>
          </div>
          <button className={styles.linkBtn} onClick={() => setMinted(null)}>I have saved it - dismiss</button>
        </div>
      )}

      {showForm && (
        <div className={styles.formBlock}>
          {formError && <div className={styles.errorBanner}>{formError}</div>}

          <div className={styles.field}>
            <label htmlFor="mcpTokenName">Name</label>
            <input
              id="mcpTokenName"
              value={name}
              maxLength={64}
              placeholder="e.g. CI agent"
              onChange={e => setName(e.target.value)}
            />
          </div>

          <div className={styles.field}>
            <label htmlFor="mcpTokenExpiry">Expires</label>
            <select
              id="mcpTokenExpiry"
              value={String(expiresInDays)}
              onChange={e => setExpiresInDays(e.target.value === 'never' ? 'never' : Number(e.target.value))}
            >
              {EXPIRY_OPTIONS.map(o => (
                <option key={String(o.value)} value={String(o.value)}>{o.label}</option>
              ))}
            </select>
          </div>

          <fieldset className={styles.scopes}>
            <legend>Permissions</legend>
            {MCP_SCOPES.map(s => (
              <label
                key={s}
                className={`${styles.scopeRow} ${SCOPE_COPY[s].danger ? styles.scopeDanger : ''}`}
              >
                <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} />
                <span>
                  <strong>{SCOPE_COPY[s].label}</strong>
                  <code className={styles.scopeCode}>{s}</code>
                  <span className={styles.scopeBlurb}>{SCOPE_COPY[s].blurb}</span>
                </span>
              </label>
            ))}
          </fieldset>

          <div className={styles.field}>
            <label htmlFor="mcpTokenPassword">Confirm your password</label>
            <input
              id="mcpTokenPassword"
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={e => setPassword(e.target.value)}
            />
            <span className={styles.muted}>
              Creating a long-lived credential asks for your password again.
            </span>
          </div>

          <div className={styles.formActions}>
            <button className={styles.primaryBtn} onClick={() => void create()} disabled={creating}>
              {creating ? <Loader2 className={styles.spin} size={14} /> : <Plus size={14} />} Create token
            </button>
            <button
              className={styles.secondaryBtn}
              onClick={() => { setShowForm(false); resetForm() }}
              disabled={creating}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {loading && (
        <div className={styles.skeleton} aria-busy="true" aria-label="Loading tokens">
          <div className={styles.skeletonRow} />
          <div className={styles.skeletonRow} />
        </div>
      )}

      {!loading && loadError && (
        <div className={styles.errorBanner}>
          <AlertTriangle size={14} /> {loadError}
          <button className={styles.linkBtn} onClick={() => void load()}>Retry</button>
        </div>
      )}

      {!loading && !loadError && tokens.length === 0 && (
        <div className={styles.empty}>
          <p>No MCP access tokens yet.</p>
          <p className={styles.muted}>
            A token lets an external AI agent start recon scans, read your attack-surface graph and
            adjust recon tuning, scoped to your own projects and to the permissions you tick.
          </p>
        </div>
      )}

      {!loading && !loadError && tokens.length > 0 && (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Name</th>
                <th>Token</th>
                <th>Permissions</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map(t => {
                const state = tokenState(t)
                return (
                  <tr key={t.id} className={state === 'active' ? '' : styles.deadRow}>
                    <td>
                      {renamingId === t.id ? (
                        <input
                          className={styles.renameInput}
                          value={renameValue}
                          maxLength={64}
                          autoFocus
                          aria-label={`New name for ${t.name}`}
                          onChange={e => setRenameValue(e.target.value)}
                          onBlur={() => void commitRename(t)}
                          onKeyDown={e => {
                            if (e.key === 'Enter') void commitRename(t)
                            if (e.key === 'Escape') setRenamingId(null)
                          }}
                        />
                      ) : (
                        <span className={styles.cellTitle}>{t.name}</span>
                      )}
                      {state !== 'active' && (
                        <span className={styles.deadTag}>{state}</span>
                      )}
                    </td>
                    <td><code className={styles.prefix}>{t.tokenPrefix}…</code></td>
                    <td>
                      {t.scopes.map(s => (
                        <span key={s} className={styles.tag}>{s}</span>
                      ))}
                    </td>
                    <td>{fmtDate(t.createdAt)}</td>
                    <td>{fmtDate(t.expiresAt) ?? <span className={styles.muted}>Never</span>}</td>
                    <td>{fmtDate(t.lastUsedAt) ?? <span className={styles.muted}>Never used</span>}</td>
                    <td className={styles.rowActions}>
                      <button
                        className={styles.iconBtn}
                        title="Rename"
                        onClick={() => { setRenamingId(t.id); setRenameValue(t.name) }}
                      >
                        <Pencil size={14} />
                      </button>
                      {state === 'active' && (
                        <button className={styles.iconBtn} title="Revoke" onClick={() => void revoke(t)}>
                          <Trash2 size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
