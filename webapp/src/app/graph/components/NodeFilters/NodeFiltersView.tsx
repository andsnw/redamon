'use client'

/**
 * Node Filters: rules, per node kind, that mute findings project-wide.
 *
 * Muting here is the existing `:Muted` label, so a filtered finding disappears
 * from the graph, the agent, analytics and reports exactly as a hand-muted one
 * does, and reappears when its rule is disabled and applied again. Every rule
 * shows, live, what it would do to the active version.
 *
 * The rules are edited as a draft and saved explicitly; Apply saves them and
 * then applies to the current graph, arms them for new scans, or both.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Loader2, RotateCcw, SlidersHorizontal } from 'lucide-react'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { NODE_FILTER_CATALOG, enabledKinds } from '@/lib/nodeFilters/catalog'
import type { NodeFilterMode } from '@/lib/nodeFilters/model'
import { countActiveRules } from '@/lib/nodeFilters/validate'
import { ApplyModal } from './ApplyModal'
import { ArmedStatus } from './ArmedStatus'
import { KindPanel } from './KindPanel'
import { KindRail, LOCKED_ID } from './KindRail'
import { ModeToggle } from './ModeToggle'
import { useApplyRun, type ApplyTarget } from './useApplyRun'
import { useNodeFilters, type NodeFilterRunSummary } from './useNodeFilters'
import { usePreview } from './usePreview'
import styles from './NodeFilters.module.css'

interface NodeFiltersViewProps {
  projectId: string | null
  isViewingPastVersion: boolean
  viewedVersionLabel?: string
  /**
   * The version on screen. Apply sends it, and the server refuses a
   * current-graph apply unless it is the active one, so a stale page viewing
   * an old snapshot cannot change the live graph.
   */
  viewedVersionId?: string | null
  focus?: { kind: string; ruleId?: string } | null
  /** The armed badge on the header tab has to be refreshed. */
  onStatusChange?: () => void
  /** An apply changed mute state: the graph and the tables should refetch. */
  onGraphChanged?: () => void
}

function fmtWhen(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString(undefined, {
    day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
  })
}

export function NodeFiltersView({
  projectId, isViewingPastVersion, viewedVersionLabel, viewedVersionId, focus, onStatusChange, onGraphChanged,
}: NodeFiltersViewProps) {
  const catalog = NODE_FILTER_CATALOG
  const kinds = useMemo(() => enabledKinds(catalog), [catalog])
  const nf = useNodeFilters(projectId)
  const { confirm, alertError } = useAlertModal()
  const toast = useToast()
  const [selected, setSelected] = useState<string>(focus?.kind ?? kinds[0]?.id ?? LOCKED_ID)
  const [applyOpen, setApplyOpen] = useState(false)
  const [busyAction, setBusyAction] = useState(false)

  useEffect(() => {
    if (focus?.kind && catalog.kinds[focus.kind]) setSelected(focus.kind)
  }, [focus, catalog])

  const preview = usePreview(projectId, nf.draftMode, nf.draft, !!nf.saved)

  const onFinished = useCallback((run: NodeFilterRunSummary) => {
    const totals = run.stats?.totals ?? {}
    if (run.status === 'completed') {
      toast.success(
        `Filters applied: muted ${(totals.muted ?? 0).toLocaleString()}, ` +
        `unmuted ${(totals.unmuted ?? 0).toLocaleString()}.`,
        'Node filters',
      )
    } else {
      toast.error(`The apply ${run.status}${run.error ? `: ${run.error}` : '.'}`, 'Node filters')
    }
    void nf.load(true)
    preview.retry()
    onStatusChange?.()
    onGraphChanged?.()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toast, onStatusChange, onGraphChanged])

  const run = useApplyRun(projectId, nf.saved?.liveRunId ?? null, onFinished)

  const saved = nf.saved
  const armedCounts = useMemo(
    () => (saved ? countActiveRules(saved.mode, saved.rules) : { rules: 0, kinds: 0 }), [saved])
  const draftCounts = useMemo(() => countActiveRules(nf.draftMode, nf.draft), [nf.draftMode, nf.draft])

  const handleSaveResult = useCallback(async (result: Awaited<ReturnType<typeof nf.save>>): Promise<number | null> => {
    if (result.ok) return result.revision
    if (result.conflict) {
      const overwrite = await confirm(
        'Someone saved these rules since you opened them. Overwrite their version with yours, or keep editing: '
          + 'your changes stay on screen, and Discard replaces them with theirs.',
        'The rules changed elsewhere',
        { confirmLabel: 'Overwrite', cancelLabel: 'Keep editing' },
      )
      if (overwrite) {
        const forced = await nf.save(true)
        return forced.ok ? forced.revision : null
      }
      // Escape and the close button land here too, so this must never lose the
      // edits: only the saved copy underneath is refreshed.
      await nf.load(true)
      return null
    }
    await alertError([result.error, ...(result.errors ?? [])].join('\n'), 'Save failed')
    return null
  }, [nf, confirm, alertError])

  const save = useCallback(async () => {
    const revision = await handleSaveResult(await nf.save())
    if (revision !== null) {
      toast.success('Rules saved.', 'Node filters')
      onStatusChange?.()
    }
  }, [nf, handleSaveResult, toast, onStatusChange])

  const changeMode = useCallback(async (mode: NodeFilterMode) => {
    if (mode === 'allowlist' && saved?.applyToScans) {
      const ok = await confirm(
        'In allowlist mode every finding of an active kind that NO rule keeps is muted. ' +
        'These filters are active on new scans, so once you save, the next scan mutes by the new mode.',
        'Switch to allowlist?',
        { confirmLabel: 'Switch' },
      )
      if (!ok) return
    }
    nf.setDraftMode(mode)
  }, [saved, confirm, nf])

  const doApply = useCallback(async (target: ApplyTarget) => {
    if (!saved) return
    let revision: number | null = saved.revision
    if (nf.dirty) revision = await handleSaveResult(await nf.save())
    if (revision === null) return
    try {
      const versionId = viewedVersionId !== undefined ? viewedVersionId : saved.activeVersion?.id ?? null
      const result = await run.apply(target, revision, versionId)
      setApplyOpen(false)
      if (result.runId) toast.info('Applying the filters to the current graph…', 'Node filters')
      else toast.success('Active on new scans.', 'Node filters')
      await nf.load(true)
      onStatusChange?.()
    } catch (e) {
      await alertError(e instanceof Error ? e.message : 'Apply failed', 'Apply node filters')
    }
  }, [saved, nf, handleSaveResult, run, toast, alertError, onStatusChange, viewedVersionId])

  const disarm = useCallback(async () => {
    if (!projectId) return
    setBusyAction(true)
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters/disarm`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      })
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `Turn off failed (${res.status})`)
      toast.success('New scans no longer apply the filters. Nothing already muted changed.', 'Node filters')
      await nf.load(true)
      onStatusChange?.()
    } catch (e) {
      await alertError(e instanceof Error ? e.message : 'Turn off failed', 'Node filters')
    } finally {
      setBusyAction(false)
    }
  }, [projectId, nf, toast, alertError, onStatusChange])

  const clearExemptions = useCallback(async (label: string) => {
    if (!projectId) return
    const ok = await confirm(
      `Findings an operator unmuted are exempt from every rule. Clearing the exemptions on ${label} ` +
      'findings lets the rules mute them again at the next apply or scan.',
      'Clear exemptions?',
      { confirmLabel: 'Clear' },
    )
    if (!ok) return
    const res = await fetch(
      `/api/projects/${encodeURIComponent(projectId)}/node-filters/exemptions?label=${encodeURIComponent(label)}`,
      { method: 'DELETE' })
    if (!res.ok) {
      await alertError('The exemptions could not be cleared.', 'Node filters')
      return
    }
    const { cleared } = await res.json()
    toast.success(`Cleared ${cleared} exemption${cleared === 1 ? '' : 's'}.`, 'Node filters')
    await nf.load(true)
    preview.retry()
  }, [projectId, confirm, alertError, toast, nf, preview])

  if (!projectId) return <div className={styles.empty}>Select a project to filter its nodes.</div>

  if (nf.error?.status === 404) {
    return <div className={styles.empty}>Node filters are not available for this project.</div>
  }
  if (nf.error && !saved) {
    return (
      <div className={styles.empty}>
        <p>{nf.error.message}</p>
        <button type="button" className={styles.button} onClick={() => void nf.load()}>
          <RotateCcw size={12} /> Retry
        </button>
      </div>
    )
  }
  if (nf.loading && !saved) {
    return (
      <div className={styles.wrap} aria-busy="true">
        <div className={styles.header}>
          {[0, 1, 2].map(i => <div key={i} className={styles.skeleton} style={{ width: `${60 - i * 12}%` }} />)}
        </div>
      </div>
    )
  }
  if (!saved) return null

  const kind = catalog.kinds[selected]
  const last = saved.lastCompleted
  const lastFailed = saved.lastRun && saved.lastRun.status !== 'completed' && saved.lastRun.status !== 'running'
    ? saved.lastRun : null
  const changedSinceApply = !!last && (
    (saved.activeVersion && last.versionId !== saved.activeVersion.id) || last.revision !== saved.revision)
  const scanned = run.run?.stats?.progress?.scanned
  const kindErrors = kind ? nf.validation.kindErrors[kind.id] ?? [] : []
  const docErrors = nf.validation.errors

  return (
    <div className={styles.wrap}>
      <div className={styles.header}>
        <div className={styles.headerRow}>
          <SlidersHorizontal size={14} />
          <span className={styles.label}>Mode</span>
          <ModeToggle mode={nf.draftMode} onChange={m => void changeMode(m)} disabled={run.running} />
          <span className={styles.spacer} />
          {nf.dirty && <span className={styles.dirty}>Unsaved changes</span>}
          {nf.dirty && (
            <button type="button" className={styles.button} onClick={nf.discard} disabled={nf.saving}>Discard</button>
          )}
          <button
            type="button"
            className={styles.button}
            onClick={() => void save()}
            disabled={!nf.dirty || nf.saving || run.running || nf.errors.length > 0}
            title={nf.errors.length ? 'Fix the rules marked in red first' : undefined}
          >
            {nf.saving && <Loader2 size={12} className={styles.spin} />} Save
          </button>
          <button
            type="button"
            className={`${styles.button} ${styles.primary}`}
            onClick={() => setApplyOpen(true)}
            disabled={run.running || nf.saving || nf.errors.length > 0}
          >
            Apply…
          </button>
          <WikiInfoButton target="NodeFilters" />
        </div>
        <div className={styles.headerRow}>
          <ArmedStatus
            armed={saved.applyToScans}
            rules={armedCounts.rules}
            kinds={armedCounts.kinds}
            mode={saved.mode}
            onTurnOff={() => void disarm()}
            busy={busyAction}
          />
        </div>
        {(last || lastFailed) && (
          <div className={styles.headerRow}>
            {last && (
              <span className={styles.lastApply}>
                Last applied to the current graph: {fmtWhen(last.finishedAt ?? last.startedAt)}
                {' · '}muted {(last.stats?.totals?.muted ?? 0).toLocaleString()}
                {' · '}unmuted {(last.stats?.totals?.unmuted ?? 0).toLocaleString()}
              </span>
            )}
            {changedSinceApply && (
              <span className={styles.changedNote}>· the graph or the rules changed since then</span>
            )}
            {lastFailed && (
              <span className={styles.changedNote}>
                · the last apply {lastFailed.status}{lastFailed.error ? `: ${lastFailed.error}` : ''}
              </span>
            )}
          </div>
        )}
        {(preview.state === 'unavailable' || preview.result?.partial) && (
          <div className={styles.headerRow}>
            {preview.state === 'unavailable' && (
              <span className={styles.changedNote}>
                Preview unavailable: {preview.message}{' '}
                <button type="button" className={styles.linkButton} onClick={preview.retry}>Retry</button>
              </span>
            )}
            {preview.result?.partial && <span className={styles.lastApply}>Counts are partial (≥): the graph is large.</span>}
          </div>
        )}
        {run.running && (
          <div className={styles.progress} role="status">
            <Loader2 size={13} className={styles.spin} />
            Applying…{typeof scanned === 'number' ? ` ${scanned.toLocaleString()} nodes checked` : ''}
          </div>
        )}
        {docErrors.length > 0 && (
          <div className={`${styles.banner} ${styles.bannerWarn}`} role="alert">
            <ul className={styles.errorList}>{docErrors.map(e => <li key={e}>{e}</li>)}</ul>
          </div>
        )}
      </div>

      <div className={styles.body}>
        <KindRail
          catalog={catalog}
          kinds={kinds}
          doc={nf.draft}
          active={nf.validation.activeKinds}
          selected={selected}
          onSelect={setSelected}
        />
        {kind ? (
          <KindPanel
            projectId={projectId}
            catalog={catalog}
            kind={kind}
            doc={nf.draft}
            mode={nf.draftMode}
            kindErrors={kindErrors}
            active={nf.validation.activeKinds.includes(kind.id)}
            preview={preview.result?.kinds?.[kind.id] ?? null}
            previewState={preview.state}
            partial={!!preview.result?.partial}
            exemptions={saved.exemptionCounts[kind.graph_label] ?? 0}
            focusRuleId={focus?.kind === kind.id ? focus.ruleId : undefined}
            disabled={run.running}
            onChange={nf.setDraft}
            onClearExemptions={label => void clearExemptions(label)}
          />
        ) : (
          <section className={styles.panel} aria-label="Locked kinds">
            <h3 className={styles.panelTitle}>Locked</h3>
            {catalog.locked.map(l => (
              <p key={l.label} className={styles.note}><strong>{l.label}</strong>: {l.reason}</p>
            ))}
            <h3 className={styles.panelTitle}>Later phases</h3>
            {catalog.planned.map(p => (
              <p key={p.id} className={styles.note}>
                <strong>{p.label}</strong>: {p.behaviour === 'finding' ? 'mute' : p.behaviour}, phase {p.phase}
              </p>
            ))}
          </section>
        )}
      </div>

      <ApplyModal
        isOpen={applyOpen}
        onClose={() => setApplyOpen(false)}
        projectId={projectId}
        catalog={catalog}
        mode={nf.draftMode}
        rules={nf.draft}
        ruleCount={draftCounts.rules}
        dirty={nf.dirty}
        isViewingPastVersion={isViewingPastVersion}
        viewedVersionLabel={viewedVersionLabel}
        onConfirm={doApply}
      />
    </div>
  )
}

export default NodeFiltersView
