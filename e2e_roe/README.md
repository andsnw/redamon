# RoE end-to-end validation

Two surfaces, two kinds of document, 80 documents in all. Everything green.

**Synthetic** documents state one rule each, crisply. They test whether a stated
rule reaches the thing that enforces it.

| | | Result | Report |
|---|---|---|---|
| UI | a document uploaded through the form becomes the right settings | 20/20, five consecutive runs | [ui/report.md](ui/report.md) |
| MCP | an agent opens engagements that respect the document | 20/20, four consecutive runs | [mcp/report.md](mcp/report.md) |

**Real** policies are the opposite: 2,218 to 41,734 characters of reporting
procedure, payout tables and safe-harbour clauses, with the occasional rule
buried in it. They test restraint, and they found four defects the synthetic set
could not.

| | | Result | Report |
|---|---|---|---|
| UI | twenty real disclosure policies, sanitised | safety 100/100 over five runs; extraction 95% | [ui/real/report.md](ui/real/report.md) |
| MCP | an agent opens engagements from the same kind of document | 20/20, zero scan jobs | [mcp/real/report.md](mcp/real/report.md) |

Nothing in either suite scans, probes or queues anything. The real documents'
targets are reserved-TLD names that resolve nowhere, and the MCP runner verifies
against the live tool list that no scan tool is reachable from it.

Both phases read the verdict out of Postgres. A proposal that looks right over a
row that holds something else is precisely the failure this feature can have, and
only the database settles it. Phase 1 additionally follows one document through
the browser and past the database into the enforcement gate; Phase 2 additionally
checks what the scan will *resolve* to, which is not what was written.

## What it found

Ten defects, all fixed. The synthetic suites found six:

| | Where | |
|---|---|---|
| 1 | `/roe/parse` | returned 503 for every model: the endpoint read its credentials from a project scope it does not have during project creation |
| 2 | registry | a forbidden **tool** was recorded and never enforced: the gate matches exactly, the registry called the column free text, the model answered `hydra` for `execute_hydra` |
| 3 | registry | forbidden **categories** the same way. A live project held seven, and not one matched the four tokens the gate knows |
| 4 | prompt generator | a closed vocabulary on a **list** field told the model to send a single scalar, which the validator then refused |
| 5 | registry | `stealthMode` did not describe itself as the passive switch it is |
| 6 | schema | a project holding an engagement authorization record **could not be deleted**, because the archive table was dropped by every `prisma db push` |

Defects 2 and 3 are the same failure and the serious one: a rule an operator
entered, that the UI renders as a rule, that the agent's prompt repeats as
advice, and that refuses nothing. Both were fixed at the root by declaring the
vocabulary in `recon_settings/registry.yaml`, which is one change with two
effects — the generated prompt teaches the model the exact tokens, and the
validator refuses anything outside them.

Defect 4 was introduced by that fix and caught by the matrix, which is the
argument for having run it.

The real policies found four more, and every one of them is a thing a
purpose-built document could not have surfaced:

| | Where | |
|---|---|---|
| 7 | prompt generator | `engagementIdentityHeader` was **not in the parse prompt at all**. More real policies require an identification header than state a rate limit, and the field for it was unreachable from every one of them |
| 8 | parse route | one document made the model return **631 of 658 fields**, all individually legal so nothing rejected any of it. Per-field validation cannot see a failure in the SHAPE of an answer; there is now a bound, and it fires |
| 9 | registry | `supplyChainInputMode` was a closed set the registry called free text, so the parse accepted a value the save refused. Third instance of defect 2's class, first one found by a real document |
| 10 | registry | the forbidden-category vocabulary never said what its tokens cover, so "credential stuffing" rarely became `brute_force` |

## Running them

```bash
E2E_PASSWORD=...                     python3 e2e_roe/ui/run_ui_e2e.py
E2E_MCP_TOKEN=... E2E_PASSWORD=...   python3 e2e_roe/mcp/run_mcp_e2e.py

E2E_PASSWORD=...                     python3 e2e_roe/run_real.py --phase ui --runs 5
E2E_MCP_TOKEN=... E2E_PASSWORD=...   python3 e2e_roe/run_real.py --phase mcp --keep
```

Both create their own projects and delete them on the way out, including when a
case raises. The 40 documents are kept.

## A note on the matrices

Neither matrix lets a case pass by accident, and that took deliberate work.

Phase 1 seeds every asserted column with a value the case does **not** expect
before each run, because "DoS is prohibited" expects `roeAllowDos = false`, which
is also the shipped default — three cases were going green on documents the
parser had ignored entirely, and a fourth turned out to be a genuine failure the
moment seeding was added.

Phase 2 never accepts a tool's own success message as evidence: every refused
write is re-read from the database, and every resolved value comes from
`preflight_scope_check` rather than from the settings the agent wrote.

Phase 1 goes through an LLM, so it was run five times rather than once. That is
how UI-07 was caught pinning one of three equally correct encodings of the same
rule, passing about half the time and looking like a product bug.


## Judging an LLM-backed suite

Two lessons from the real policies, both of which made a correct parser look
broken before they were understood.

**A technique named in a policy is usually not a prohibition.** "Brute force
reports without demonstrated impact" and "reports involving phishing are not
eligible" are payout exclusions, and a document saying either must produce no
setting. Expectations are derived with a sentence-level classifier for that
reason.

**Extraction of one clause from a long document is not deterministic, so it is
measured rather than asserted.** The real suites hard-fail only on safety - scope
moved, engagement loosened, something written after a refusal - and on a rule
that lands in no run of three or more attempts. Everything else is a rate, and
the rate is reported. Across five runs: 315 of 330 stated rules landed, and not
one change loosened an engagement.
