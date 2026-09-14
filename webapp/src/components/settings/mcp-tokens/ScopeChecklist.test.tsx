/**
 * The grouped permission checklist.
 *
 * What this guards beyond "it renders" is the safety property the whole Agent
 * Profile feature rests on: **a profile ticks permissions on the operator's
 * behalf, and there are two it must NEVER tick.** Command execution at a live
 * target and irreversible graph destruction have to be deliberate acts, not
 * side effects of choosing a job from a dropdown. If that ever regresses, this
 * file is where it is caught in the UI, and profiles.test.ts is where it is
 * caught in the data.
 *
 * Run: npx vitest run src/components/settings/mcp-tokens/ScopeChecklist.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import { PROFILE_IDS, PROFILES, scopesForProfile } from '@/lib/mcp/profiles'
import { SCOPE_GROUPS } from '@/lib/mcp/scopeCopy'
import ScopeChecklist from './ScopeChecklist'

afterEach(() => cleanup())

/**
 * The scope code also appears in the opt-in footnote, so matching on text alone
 * is ambiguous. The label wraps its input, so the row's text IS the checkbox's
 * accessible name.
 */
const boxFor = (scope: McpScope) =>
  screen.getByRole('checkbox', { name: new RegExp(scope.replace(':', '\\:')) }) as HTMLInputElement

describe('the grouping', () => {
  test('every scope renders exactly once, under a group header', () => {
    render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    for (const scope of MCP_SCOPES) {
      expect(screen.getAllByText(scope), `${scope} renders ${screen.queryAllByText(scope).length} times`).toHaveLength(1)
    }
    for (const group of SCOPE_GROUPS) {
      expect(screen.getByText(group.label), `group ${group.id} has no header`).toBeDefined()
    }
  })

  test('the checkbox count matches the enforcement list, so none is orphaned', () => {
    const { container } = render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    expect(container.querySelectorAll('input[type="checkbox"]')).toHaveLength(MCP_SCOPES.length)
  })

  test('toggling a row reports that scope', () => {
    const onToggle = vi.fn()
    render(<ScopeChecklist selected={[]} onToggle={onToggle} />)
    fireEvent.click(boxFor('recon:scan'))
    expect(onToggle).toHaveBeenCalledWith('recon:scan')
  })

  test('a disabled checklist disables EVERY box, not just the first', () => {
    // Asserted on the inputs rather than by clicking: a disabled input's click
    // semantics are a jsdom detail, while "is it disabled" is the contract a
    // revoked token relies on.
    const { container } = render(<ScopeChecklist selected={[]} onToggle={vi.fn()} disabled />)
    const boxes = [...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')]
    expect(boxes).toHaveLength(MCP_SCOPES.length)
    expect(boxes.every(b => b.disabled)).toBe(true)
  })
})

describe('kali:exec is presented as a different KIND of permission', () => {
  test('it carries the long explanation, not the table-cell blurb', () => {
    render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    // The decision the operator is actually making, which is the framing the
    // short blurb cannot carry.
    expect(screen.getByText(/borrow\s+RedAmon's\?/)).toBeDefined()
    expect(screen.getByText(/not sufficient on its own/)).toBeDefined()
  })

  test('it links out to what the sandbox carries AND what it may run, kept apart', () => {
    render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    // Conflating these two is exactly the misunderstanding the panel exists to
    // prevent: the toolbox lists far more than exec is permitted to run.
    const carries = screen.getByText('What the sandbox carries') as HTMLAnchorElement
    const runs = screen.getByText('What this can actually run') as HTMLAnchorElement
    expect(carries.getAttribute('href')).toContain('kali_toolbox')
    expect(runs.getAttribute('href')).toContain('kali_exec')
  })

  test('it does not enumerate the allowlist, which grows', () => {
    const { container } = render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    // A list pasted into the UI goes stale the moment the guard gains a tool,
    // and a stale list that overstates the allowlist is wrong in the dangerous
    // direction.
    expect(container.textContent).not.toContain('searchsploit')
    expect(container.textContent).not.toContain('dnsrecon')
  })
})

describe('a profile ticks boxes, but never these two', () => {
  test.each(PROFILE_IDS)('%s never auto-ticks kali:exec or recon:overwrite', id => {
    render(<ScopeChecklist selected={scopesForProfile(id)} profile={id} onToggle={vi.fn()} />)
    expect(boxFor('kali:exec').checked, `${id} auto-ticked kali:exec`).toBe(false)
    expect(boxFor('recon:overwrite').checked, `${id} auto-ticked recon:overwrite`).toBe(false)
  })

  test.each(PROFILE_IDS)('%s ticks exactly its recommended set', id => {
    render(<ScopeChecklist selected={scopesForProfile(id)} profile={id} onToggle={vi.fn()} />)
    const expected = new Set(PROFILES[id].recommendedScopes)
    for (const scope of MCP_SCOPES) {
      expect(boxFor(scope).checked, `${id}/${scope}`).toBe(expected.has(scope))
    }
  })

  test('a profile that recommends a dangerous scope says so, with the box still clear', () => {
    render(<ScopeChecklist selected={scopesForProfile('pentest')} profile="pentest" onToggle={vi.fn()} />)
    expect(screen.getByText('recommended, tick it yourself')).toBeDefined()
    expect(boxFor('kali:exec').checked).toBe(false)
    expect(screen.getByText(/never ticks those for you/)).toBeDefined()
  })

  test('research, which recommends BOTH dangerous scopes, still ticks neither', () => {
    render(<ScopeChecklist selected={scopesForProfile('research')} profile="research" onToggle={vi.fn()} />)
    expect(boxFor('kali:exec').checked).toBe(false)
    expect(boxFor('recon:overwrite').checked).toBe(false)
    expect(screen.getAllByText('recommended, tick it yourself')).toHaveLength(2)
  })
})

describe('divergence from the profile is shown, not corrected', () => {
  test('a hand-added scope is tagged as added', () => {
    render(
      <ScopeChecklist
        selected={[...scopesForProfile('soc'), 'triage:write']}
        profile="soc"
        onToggle={vi.fn()}
      />
    )
    expect(screen.getByText('added')).toBeDefined()
    expect(boxFor('triage:write').checked).toBe(true)
  })

  test('a hand-removed scope is tagged as removed, and stays removed', () => {
    render(
      <ScopeChecklist
        selected={scopesForProfile('soc').filter(s => s !== 'graph:cypher')}
        profile="soc"
        onToggle={vi.fn()}
      />
    )
    expect(screen.getByText('removed')).toBeDefined()
    expect(boxFor('graph:cypher').checked).toBe(false)
  })

  test('with no profile there are no tags at all', () => {
    render(<ScopeChecklist selected={['recon:read', 'kali:exec']} onToggle={vi.fn()} />)
    expect(screen.queryByText('from profile')).toBeNull()
    expect(screen.queryByText('added')).toBeNull()
    expect(screen.queryByText(/never ticks those for you/)).toBeNull()
  })
})
