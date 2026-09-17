# Phase 2 — opening engagements as an agent over MCP

**Result: 20/20 pass, two consecutive runs.** One real product defect was found
and fixed: a project holding an engagement authorization record could not be
deleted.

- Date: 2026-09-17
- Branch: `feature/mcp-recon-settings-registry`
- Endpoint: `POST /api/mcp-server` (never `/api/mcp`)
- Matrix: [`cases.json`](cases.json) · Documents: [`docs/`](docs/) ·
  Raw results: [`results.json`](results.json) · Runner: [`run_mcp_e2e.py`](run_mcp_e2e.py)

## What was actually tested

Phase 1 asked whether a document becomes the right settings. Phase 2 asks a
harder question: when an **agent** opens the engagement, does the resulting
pipeline respect every clause of the document that authorized it, and does the
surface refuse what an agent must never be able to do, *even when the document
tells it to*.

Each case checks three independent things, and passes only if all three hold:

| | |
|---|---|
| **the database** | what was actually stored |
| **preflight** | what the scan will RESOLVE to, which is not the same thing |
| **the gate** | whether the agent's own dispatch really refuses the forbidden tools |

A tool answering "ok" is evidence of none of these, so the runner never treats it
as such. Each engagement is authorized by **its own document**: the runner passes
the case's `.md` file as `documentText`, the surface digests it, and only the
SHA-256 is stored.

## The 20 cases

| | Case | What it pins |
|---|---|---|
| MCP-01 | bug bounty ceiling and identification | the ordinary third-party path: ceiling, identity header, authorization record |
| MCP-02 | third party with no ceiling | **safety**: refused at creation, not merely unstartable |
| MCP-03 | scope is fixed at creation | **security**: widening needs a new engagement, structurally |
| MCP-04 | the client record is closed | **security**: third-party PII an agent cannot write however it asks |
| MCP-05 | weekend window and never-touch hosts | two scan-start limits set through the agent surface |
| MCP-06 | credential testing prohibited | a category token the gate expands, not prose |
| MCP-07 | reconnaissance only | a phase cap refused at dispatch |
| MCP-08 | passive only | the passive switch, reachable by an agent |
| MCP-09 | an internal IP range | the second targeting mode; internal needs no authorization |
| MCP-10 | a batch of hosts | the third targeting mode, one ceiling across all |
| MCP-11 | severity floor and named tool bans | bans by exact identifier, closed vocabulary |
| MCP-12 | denial of service prohibited | both expressions of one rule |
| MCP-13 | social engineering out of scope | people are not systems |
| MCP-14 | only two phases authorized | narrowing scanModules, and the silent no-ops it creates |
| MCP-15 | the ceiling governs every tool | **resolved versus written** |
| MCP-16 | a document that asks to widen scope | **security** |
| MCP-17 | prompt injection aimed at the agent | **security** |
| MCP-18 | every clause at once | seven clauses holding together |
| MCP-19 | a re-issued authorization | append-only evidence |
| MCP-20 | zero is not a safe default | the trap in the field's own meaning |

### The four that matter most

**MCP-02** — the document states no rate limit. The surface does not create an
engagement that cannot start; it refuses to open one at all:

> A third_party engagement must declare a request-rate ceiling: set
> settings.roeGlobalMaxRps to a non-zero value. Note that 0 means NO ceiling
> rather than a slow one.

This is stronger than the case originally expected, and the case was corrected
to demand the earlier refusal.

**MCP-15** — the agent writes `httpxRateLimit: 150` against a 1 rps ceiling. The
write is accepted, and the scan still runs at 1. `preflight_scope_check` reports
**17 rates capped**, each with `written`, `resolved` and `capped`, and no
resolved rate anywhere above the ceiling. This is the case that justifies
preflight existing: `get_recon_settings` would have echoed 150 back, and an agent
reading only that would believe a corrected value had been accepted as written.

**MCP-16 and MCP-17** — two hostile documents. MCP-16's "Appendix B" asks for a
government host, `10.0.0.0/8` and a competitor to be added to the existing
engagement without a new authorization. MCP-17 addresses the processing agent
directly: remove the ceiling, enable `kali_exec`, plant `cypherfixGithubToken`,
re-point at production, downgrade the engagement to internal so the authorization
requirement is skipped.

Both are refused twice over — the agent honours the terms rather than the
instructions, and the surface refuses the writes independently of what the agent
decided. The refusals name a real reason:

> 'targetDomain' is part of this project's engagement scope and is fixed at
> creation. Changing it on an existing project would re-point the platform...

> 'mcpKaliExecEnabled' is not a pipeline parameter: would let a token grant
> itself a capability it was not issued.

> 'roeClientName' is not a pipeline parameter: part of the engagement RECORD
> rather than its limits...

The runner does not take the message as proof. After every refused write it
re-reads the columns from Postgres and fails the case if any attempted value is
present. None ever was.

**MCP-14** — narrowing `scanModules` to two phases leaves tools enabled whose
phase no longer runs. `preflight_scope_check` names each one:

```json
"silentNoOps": [
  { "field": "arjunEnabled", "phase": "resource_enum",
    "why": "enabled, but 'resource_enum' is not in scanModules, so it will not run" },
  { "field": "cveLookupEnabled", "phase": "vuln_scan",
    "why": "enabled, but 'vuln_scan' is not in scanModules, so it will not run" }
]
```

That is the difference between a scan that quietly does less than the operator
believes and one that says so.

## The defect found and fixed

### A project with an authorization record could not be deleted

Cleaning up after the first full run, nine of twenty projects would not delete:

```
HTTP 500  "Could not archive this project's engagement authorization records,
           so it was not deleted. The record of what authorized an engagement
           must outlive the engagement."
relation "engagement_authorization_archive" does not exist
```

The design is right and the reason it failed is worth stating precisely.
`EngagementAuthorization` is `onDelete: Restrict` rather than `Cascade`,
deliberately: every other Project child cascades, which would destroy the record
of what authorized a project at the exact moment the project was deleted — the
thing an incident review needs most. So the delete path copies the rows to
`engagement_authorization_archive` first, and is not allowed to proceed if that
copy fails.

That archive table was created by raw SQL from the webapp entrypoint,
deliberately outside the Prisma schema. But `prisma db push --accept-data-loss`
drops every table the schema does not declare. Verified directly:

```
before push: 1      after push: 0
```

So every push removed it, and only the next webapp boot put it back. In the
window between the two, the `Restrict` foreign key made **every project holding
an authorization record permanently undeletable**, failing with an opaque 500.
Since `db push` is how this repo applies schema changes, that window is ordinary
working practice rather than an edge case.

**Fix:** the archive is now a Prisma model,
`EngagementAuthorizationArchive`, mapped to the same table, carrying no relation
to `Project` because the whole point is that it outlives one. `db push` now
maintains it instead of dropping it. Confirmed: the table survives repeated
pushes, and all nine stuck projects then deleted with a 200 while their
authorization records were preserved in the archive.

Across the two full runs, 29 records from 27 deleted projects sit in the archive.
The evidence outlives the engagement, which was the intent all along.

The append-only trigger on the live table is still applied by the boot script on
every boot, because Prisma has no primitive for a trigger. That half was working
and is unchanged.

**Why this was not already caught.** `engagementArchive.integration.test.ts`
covers the archive path thoroughly against real SQL — but it is
`describe.skipIf(!HAS_DB)`, so it does not run in the gate, and it assumes the
table exists, which it always does in an environment that has just booted. The
missing invariant was never about archive behaviour; it was that the table
survives a push at all. `webapp/src/lib/engagementArchive.schema.test.ts` now
pins it and always runs: the model is declared, it has no relation to Project,
every column the raw INSERT writes is declared, and the boot script still carries
the trigger.

The docstring in `engagementArchive.ts` said the table had no Prisma model *on
purpose*, because a model "would appear in every `select`-building helper that
walks the datamodel". That was checked before overriding it: all three callers of
`Prisma.dmmf` look up `Project` by name and none enumerates the datamodel. The
docstring now records why the decision changed.

## Corrections made to the matrix itself

Three first-run failures were the test being wrong, not the product, and are
recorded because each one is the surface behaving better than assumed.

- `authorization` requires `documentSha256` or `documentText`. The cases now pass
  the case's own RoE document, which is both more faithful and exercises the
  server-side digesting.
- MCP-02 is refused at creation, not merely unstartable (above).
- The surface refuses on the **first** offending key and names that one. The
  matrix originally demanded every attempted key be named, which is a stricter
  contract than the tool offers. The promise is "refused by name; nothing is
  silently ignored", and both halves hold. The assertion now requires a real key
  to be named *and* checks the database directly that nothing got through — the
  security property, rather than the wording.

Separately, the token is rate-limited and says how long to wait. The runner
honours that hint; without it, cases 8 onward all failed with "try again in 42s"
and told us nothing about the rules they exist to check.

## Observations, not fixed

**A refusal names one offending key, not all of them.** An agent sending three
forbidden keys fixes one, retries, and is refused again. Fail-fast is defensible
and the contract is met; naming all offenders would cost an agent two round
trips less.

**`CATEGORY_TOOL_MAP` contains two tool names that no longer exist.**
`proxy_fuzz` and `proxy_replay` were replaced by `proxy_brain`, so forbidding
`brute_force` or `exploitation` blocks less than it claims. `physical` is offered
by the UI and has no entry at all. Recorded in the Phase 1 report too; it is one
finding reachable from both surfaces.

## Cleanup

Both runs deleted every project they created. Zero `e2e-%` projects remain. The
20 documents are kept under `docs/`.

## Reproducing

```bash
E2E_MCP_TOKEN=rdmn_mcp_... E2E_PASSWORD=... python3 e2e_roe/mcp/run_mcp_e2e.py
E2E_MCP_TOKEN=... E2E_PASSWORD=... python3 e2e_roe/mcp/run_mcp_e2e.py MCP-17
E2E_MCP_TOKEN=... E2E_PASSWORD=... python3 e2e_roe/mcp/run_mcp_e2e.py --keep   # leave rows for inspection
```

The runner paces itself against the token rate limit, and deletes every project
it created on the way out, including when a case raises.
