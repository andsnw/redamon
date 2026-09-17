# RoE end-to-end validation

Two phases, 40 synthetic Rules-of-Engagement documents, both green.

| | | Result | Report |
|---|---|---|---|
| Phase 1 | a document uploaded through the **UI** becomes the right settings | 20/20, five consecutive runs | [ui/report.md](ui/report.md) |
| Phase 2 | an **agent** over MCP opens engagements that respect the document | 20/20, four consecutive runs | [mcp/report.md](mcp/report.md) |

Both phases read the verdict out of Postgres. A proposal that looks right over a
row that holds something else is precisely the failure this feature can have, and
only the database settles it. Phase 1 additionally follows one document through
the browser and past the database into the enforcement gate; Phase 2 additionally
checks what the scan will *resolve* to, which is not what was written.

## What it found

Six defects, all fixed:

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

## Running them

```bash
E2E_PASSWORD=...                     python3 e2e_roe/ui/run_ui_e2e.py
E2E_MCP_TOKEN=... E2E_PASSWORD=...   python3 e2e_roe/mcp/run_mcp_e2e.py
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
