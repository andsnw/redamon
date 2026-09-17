# Real disclosure policies through the MCP surface

**GREEN.** 20/20 clean. Twenty engagements opened by an agent from twenty real
policies, every stated rule stored, **zero scan jobs**, and the twenty projects
left in place for inspection.

- Date: 2026-09-17
- Endpoint: `POST /api/mcp-server`
- Matrix: [`cases.json`](cases.json) · Documents: [`docs/`](docs/) ·
  Results: [`results.json`](results.json) · Runner: [`../../run_real.py`](../../run_real.py)

```bash
E2E_MCP_TOKEN=... E2E_PASSWORD=... python3 e2e_roe/run_real.py --phase mcp --keep
```

## Nothing was scanned

This was the binding constraint on the whole exercise: RedAmon's interaction
surface is under test, not any target. It is enforced three ways rather than
promised.

1. The runner refuses to call `start_recon`, `queue_recon`, `stop_recon`,
   `cancel_queued_scan` or any `kali_*` tool. `call_tool` raises on the name.
2. `assert_no_scan_tools` pulls the live tool list from `tools/list` and checks
   it against every tool this module can reach, so the guarantee is verified
   against the running surface rather than read off the source. It printed
   `34 tools on the surface, none of them reachable from here`.
3. Every case asserts `scan_jobs = 0` for its own project afterwards.

Confirmed in the database after the run:

```
projects kept:  20
scan_jobs:       0
scan_versions:   0
```

The sanitised targets are reserved-TLD names that resolve nowhere, so even a
mistake could not have reached anything.

## What the agent does

For each policy, the agent opens a third-party engagement with `create_project`:

- the **policy itself** is the authorization document, passed as `documentText`.
  The surface digests it and stores only the SHA-256, never the text
- the settings are the ones the document states
- where a rule has several correct encodings, the agent picks one MCP can
  actually write. `roeAllowPhysicalAccess` is engagement RECORD and closed to an
  agent; `roeForbiddenCategories` is an engagement LIMIT and is not
- where the policy states **no** ceiling, the agent still sets one. A third-party
  engagement with `roeGlobalMaxRps = 0` is not a slow engagement, it is an
  unlimited one, and the surface refuses to open it at all

Then the project row is read back from Postgres, because the tool answering "ok"
is not evidence that anything was stored.

## Results

All twenty engagements opened and stored what their policy states. A sample of
the final rows:

| case | kind | rps | dos | social | categories | identity header |
|---|---|---|---|---|---|---|
| MCP-01 | third_party | 10 | off | off | | `X-Researcher-Resea…` |
| MCP-05 | third_party | 5 | off | off | 2 | |
| MCP-08 | third_party | 5 | off | off | 2 | `X-Bug-Bounty: reda…` |
| MCP-09 | third_party | 5 | off | off | 2 | |

`rps = 10` is the one policy in this half that states a rate. The rest are the
agent's own conservative ceiling, which is the point of the rule above.

## The defect this phase found

Ten of twenty cases failed on the first run, all identically, and it was the
runner rather than the product: when a rule had several correct encodings the
agent picked the **first** option rather than the first **settable** one. For the
physical-access rule that is `roeAllowPhysicalAccess`, which is `mcp: never`, so
the agent set nothing at all and the case then failed for a rule the surface had
never been asked to store.

Worth recording because it is the same mistake an unattended agent would make
reading the tool descriptions: the two halves of the RoE split are not
interchangeable, and choosing the record half means writing nothing. The
corrected runner picks a settable encoding and merges list-valued rules rather
than overwriting them.

## Where this differs from the synthetic MCP suite

The synthetic suite next door tests what the surface **refuses**: re-pointing
scope, writing the client record, planting a credential, opening a third-party
engagement without a ceiling, prompt injection aimed at the agent. Those cases
are sharper with purpose-built documents, and they stay there.

This suite tests whether an agent handed a real 2,500 to 31,000 character policy
ends up with an engagement that matches it. Both matter; neither replaces the
other.
