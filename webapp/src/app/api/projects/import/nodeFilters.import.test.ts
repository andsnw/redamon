/**
 * Node filters survive an export/import round trip, and arrive DISARMED.
 *
 * An operator's exemptions ("no rule may mute this again") must come along, or
 * the imported project re-mutes what they had unmuted. The rules come along too,
 * but never armed: a freshly imported project must not start muting what its
 * next scan finds before its new owner has looked at them.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const mockProjectCreate = vi.fn()
const mockFilterCreate = vi.fn()
const mockExemptionCreateMany = vi.fn()

vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => ({ userId: 'new-owner' }) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => mockProjectCreate(...a) },
    projectNodeFilter: { create: (...a: unknown[]) => mockFilterCreate(...a) },
    nodeFilterExemption: { createMany: (...a: unknown[]) => mockExemptionCreateMany(...a) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

const RULES = {
  version: 1,
  kinds: {
    'vuln.nuclei': {
      enabled: true, action: 'mute',
      rules: [{ id: 'k3f9a2', name: 'Informational templates', enabled: true,
                all: [{ field: 'severity', op: 'in', value: ['info'] }] }],
    },
  },
}

async function bundle(nodeFilter: unknown, exemptions: unknown) {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'Imported' }))
  zip.file('project.json', JSON.stringify({ id: 'old-project', userId: 'old-owner', name: 'Imported' }))
  if (nodeFilter) zip.file('node-filters/node-filters.json', JSON.stringify(nodeFilter))
  if (exemptions) zip.file('node-filters/node-filter-exemptions.json', JSON.stringify(exemptions))
  const buf = await zip.generateAsync({ type: 'uint8array' })
  const fd = new FormData()
  fd.set('file', new File([buf as BlobPart], 'export.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectCreate.mockResolvedValue({ id: 'new-project', name: 'Imported' })
  mockFilterCreate.mockResolvedValue({})
  mockExemptionCreateMany.mockImplementation(({ data }: { data: unknown[] }) => Promise.resolve({ count: data.length }))
})

describe('importing node filters', () => {
  test('the rules arrive disarmed, under the new owner', async () => {
    const res = await POST(await bundle({ mode: 'denylist', rules: RULES, revision: 7 }, null))
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(mockFilterCreate).toHaveBeenCalledWith({
      data: {
        projectId: 'new-project', mode: 'denylist', rules: RULES,
        applyToScans: false, updatedBy: 'new-owner',
      },
    })
    expect(body.stats.nodeFilters).toBe('imported (not applied to new scans)')
  })

  test('even a bundle claiming it was armed arrives disarmed', async () => {
    await POST(await bundle({ mode: 'allowlist', rules: RULES, applyToScans: true }, null))
    expect(mockFilterCreate.mock.calls[0][0].data.applyToScans).toBe(false)
  })

  test('the exemptions come along, finding labels only', async () => {
    const res = await POST(await bundle(null, [
      { label: 'Vulnerability', nodeKey: 'v1', createdAt: '2026-09-01T00:00:00Z' },
      { label: 'MalPackageFinding', nodeKey: 'f9' },
      { label: 'IP', nodeKey: '192.0.2.10' },
      { label: 'Secret', nodeKey: '' },
      'garbage',
    ]))
    expect(mockExemptionCreateMany).toHaveBeenCalledWith({
      data: [
        { projectId: 'new-project', label: 'Vulnerability', nodeKey: 'v1', createdBy: 'new-owner' },
        { projectId: 'new-project', label: 'MalPackageFinding', nodeKey: 'f9', createdBy: 'new-owner' },
      ],
      skipDuplicates: true,
    })
    expect((await res.json()).stats.nodeFilterExemptions).toBe(2)
  })

  test('rules this catalog cannot read are left out, and the import still succeeds', async () => {
    const bad = { version: 1, kinds: { 'vuln.retired_kind': { enabled: true, action: 'mute', rules: [] } } }
    const res = await POST(await bundle({ mode: 'denylist', rules: bad }, null))
    expect(res.status).toBe(200)
    expect(mockFilterCreate).not.toHaveBeenCalled()
    expect((await res.json()).stats.nodeFilters).toMatch(/^skipped: unknown kind/)
  })

  test('a bundle from before node filters imports as it always did', async () => {
    const res = await POST(await bundle(null, null))
    expect(res.status).toBe(200)
    expect(mockFilterCreate).not.toHaveBeenCalled()
    expect(mockExemptionCreateMany).not.toHaveBeenCalled()
  })
})
