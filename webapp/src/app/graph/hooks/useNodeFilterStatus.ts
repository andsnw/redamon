'use client'

/**
 * The Node Filters tab's armed badge: fetched on load and when the project
 * changes, and refreshed by the page after a save, an apply or a disarm.
 * A failed fetch shows no badge rather than a stale one.
 */
import { useCallback, useEffect, useState } from 'react'
import type { NodeFilterStatus } from '../components/ViewTabs/ViewTabs'

export function useNodeFilterStatus(projectId: string | null) {
  const [status, setStatus] = useState<NodeFilterStatus | null>(null)

  const refresh = useCallback(async () => {
    if (!projectId) {
      setStatus(null)
      return
    }
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters/status`)
      setStatus(res.ok ? await res.json() : null)
    } catch {
      setStatus(null)
    }
  }, [projectId])

  useEffect(() => {
    setStatus(null)
    void refresh()
  }, [refresh])

  return { status, refresh }
}
