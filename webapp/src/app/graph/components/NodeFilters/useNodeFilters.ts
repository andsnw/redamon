'use client'

/**
 * Load, edit and save a project's node-filter rules.
 *
 * The draft is local until Save. A save sends the revision it was loaded at,
 * and a 409 means someone saved in between: the caller offers Overwrite (a
 * save with `force`) or keeps the draft over a refreshed saved copy.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { EMPTY_NODE_FILTER_DOC, type NodeFilterDoc, type NodeFilterMode } from '@/lib/nodeFilters/model'
import { allErrors, validateNodeFilters, type NodeFilterValidation } from '@/lib/nodeFilters/validate'
import { sameDoc } from './draft'

export interface NodeFilterRunSummary {
  id: string
  status: string
  target: string
  versionId: string
  revision: number
  mode: string
  stats: {
    totals?: Record<string, number>
    progress?: { scanned?: number }
    partial?: boolean
  } | null
  error: string | null
  startedAt: string
  heartbeatAt: string
  finishedAt: string | null
}

export interface NodeFiltersState {
  mode: NodeFilterMode
  applyToScans: boolean
  rules: NodeFilterDoc
  revision: number
  exists: boolean
  exemptionCounts: Record<string, number>
  activeVersion: { id: string; label: string } | null
  lastRun: NodeFilterRunSummary | null
  lastCompleted: NodeFilterRunSummary | null
  liveRunId: string | null
}

export type SaveResult =
  | { ok: true; revision: number }
  | { ok: false; conflict: true; currentRevision?: number }
  | { ok: false; conflict: false; error: string; errors?: string[] }

export function useNodeFilters(projectId: string | null) {
  const [saved, setSaved] = useState<NodeFiltersState | null>(null)
  const [draftMode, setDraftMode] = useState<NodeFilterMode>('denylist')
  const [draft, setDraft] = useState<NodeFilterDoc>(EMPTY_NODE_FILTER_DOC)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<{ status: number; message: string } | null>(null)
  const [saving, setSaving] = useState(false)
  // The view stays mounted across a project switch, so an answer is applied
  // only if it is the latest load AND still for the project on screen.
  const loadSeq = useRef(0)
  const currentProject = useRef(projectId)
  currentProject.current = projectId

  const load = useCallback(async (keepDraft = false) => {
    if (!projectId) return
    const seq = ++loadSeq.current
    const stale = () => seq !== loadSeq.current || currentProject.current !== projectId
    setLoading(true)
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters`)
      const body = await res.json().catch(() => ({}))
      if (stale()) return
      if (!res.ok) {
        setError({ status: res.status, message: body.error || `Node filters: ${res.status}` })
        return
      }
      setError(null)
      setSaved(body)
      if (!keepDraft) {
        setDraftMode(body.mode)
        setDraft(body.rules ?? EMPTY_NODE_FILTER_DOC)
      }
    } catch (e) {
      if (!stale()) setError({ status: 0, message: e instanceof Error ? e.message : 'Could not load the node filters' })
    } finally {
      if (!stale()) setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    // Never show the previous project's rules while this one loads.
    setSaved(null)
    setDraftMode('denylist')
    setDraft(EMPTY_NODE_FILTER_DOC)
    void load()
  }, [load])

  const dirty = useMemo(
    () => !!saved && (saved.mode !== draftMode || !sameDoc(saved.rules, draft)),
    [saved, draftMode, draft],
  )

  const validation: NodeFilterValidation = useMemo(
    () => validateNodeFilters(draftMode, draft), [draftMode, draft])
  const errors = useMemo(() => allErrors(validation), [validation])

  const save = useCallback(async (force = false): Promise<SaveResult> => {
    if (!projectId || !saved) return { ok: false, conflict: false, error: 'Nothing loaded' }
    setSaving(true)
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: draftMode, rules: draft, revision: saved.revision, ...(force ? { force: true } : {}) }),
      })
      const body = await res.json().catch(() => ({}))
      if (res.status === 409) return { ok: false, conflict: true, currentRevision: body.currentRevision }
      if (!res.ok) return { ok: false, conflict: false, error: body.error || `Save failed: ${res.status}`, errors: body.errors }
      // Saved, but the operator has moved to another project meanwhile.
      if (currentProject.current !== projectId) return { ok: true, revision: body.revision }
      await load(true)
      setSaved(prev => (prev ? { ...prev, mode: draftMode, rules: draft, revision: body.revision, exists: true } : prev))
      return { ok: true, revision: body.revision }
    } finally {
      setSaving(false)
    }
  }, [projectId, saved, draftMode, draft, load])

  const discard = useCallback(() => {
    if (!saved) return
    setDraftMode(saved.mode)
    setDraft(saved.rules)
  }, [saved])

  return {
    saved, draft, setDraft, draftMode, setDraftMode, loading, error, saving, dirty,
    validation, errors, load, save, discard,
  }
}
