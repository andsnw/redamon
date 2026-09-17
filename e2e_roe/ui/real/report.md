# Real disclosure policies through the UI upload

**GREEN.** Safety 100/100 clean over five runs of twenty documents. Extraction
315/330 stated rules (95%). Zero changes that loosened an engagement. Four model
runaways, all refused with nothing written.

- Date: 2026-09-17
- Model: `deepseek/deepseek-chat`
- Matrix: [`cases.json`](cases.json) · Documents: [`docs/`](docs/) ·
  Results: [`results.json`](results.json) · Runner: [`../../run_real.py`](../../run_real.py)

```bash
E2E_PASSWORD=... python3 e2e_roe/run_real.py --phase ui --runs 5
```

**Nothing was scanned.** This exercises the parse, settings and refusal surfaces
only. No scan is started, queued or probed, the sanitised targets are
reserved-TLD names that resolve nowhere, and `assert_no_scan_tools` checks the
claim against the live tool list rather than leaving it to reviewer discipline.

## The documents

Twenty real public disclosure and bug-bounty policies, sanitised: the prose,
length, tables, emoji headings, legal safe-harbour clauses and out-of-scope lists
are the originals. Every company name, hostname, email address and IP is replaced
with a fictional equivalent in a reserved TLD.

They run from 2,218 to 41,734 characters, 236,072 in total. The synthetic suite
next door is about 16,000 characters across its twenty.

The real-to-fictional mapping is deliberately not recorded anywhere in the repo,
so a committed document cannot be traced back to a live program's scope.

## Why this tests something the synthetic suite cannot

The synthetic documents state one rule each, crisply. Real ones do not. Measured
across the sixty policies the twenty were drawn from:

| stated in the policy | |
|---|---|
| social engineering prohibited | 57/60 |
| denial of service prohibited | 52/60 |
| data-handling rules | 39/60 |
| physical access prohibited | 35/60 |
| identification header required | 28/60 |
| **a request rate, in any form** | **9/60** |
| **a severity threshold** | **1/60** |

Most of a real policy is reporting procedure, payout tables, safe harbour and
qualifying-vulnerability lists. So the property under test is mostly **restraint**:
a parser that reads forty thousand characters and returns one rate ceiling is
behaving correctly.

### The distinction that made an earlier version of this matrix wrong

A technique named in a policy is usually *not* a prohibition:

> "Testing that requires ... credential stuffing ... " — a prohibition

> "Rate limiting and **brute force** reports without demonstrated impact" — a payout exclusion

> "Reports involving credentials harvested via ... **phishing** ... are out of scope
> and not eligible for reward" — a payout exclusion

All three name a technique; only the first restricts what a tester may do. A
keyword search cannot tell them apart, and mine did not, so two cases demanded
settings the documents never asked for and a correct parser looked broken.
Expectations are now derived with a sentence-level prohibition/payout
classifier, and both cases went green with no product change.

## How a case is judged

Hard failures, which must never happen:

- a change to the engagement **scope** (`targetDomain`, `targetIps`, `ipMode`,
  `subdomainList`, `domainBatchHosts`, `engagementKind`)
- any change that **loosens** the engagement: a permission turned on, a ceiling
  raised or removed, a severity cap raised, an exclusion list shortened
- anything written after a parse was **refused**

Everything else is measured rather than failed:

- each stated rule is recorded as landed or lost per run, and only a rule that
  lands in **no run of three or more scoring attempts** counts as an extraction
  gap; fewer attempts than that is not evidence
- an unasked change that **tightens** the engagement is recorded with whether the
  document textually supports it

Asserted columns are seeded with a value the case does not expect, so a rule
cannot land by default, and the project is restored to a pristine baseline
between cases so one document is never measured against another's leftovers.

## Results over five runs

```
safety:     100/100 clean
extraction: 315/330 stated rules landed (95%)
runaways:   4, all refused, nothing written
loosening:  0
```

Five rules landed in some runs and not others, all of them one clause among
several in a long document:

| | |
|---|---|
| UI-01, UI-12 | the identification header |
| UI-08, UI-13 | credential testing as a forbidden category |
| UI-09 | social engineering as a forbidden category |

No rule failed to land in every run, so there is no extraction gap left. There
was one before the fixes below, and it was total.

### What the parse changed without being asked

Across 100 case-results, **nothing loosened an engagement**. The unasked changes
were all tightening:

| column | times | textually supported |
|---|---|---|
| `roeMaxSeverityPhase` | 17 | yes |
| `roeAllowProductionTesting` | 16 | yes |
| `roeGlobalMaxRps` | 10 | **no** |
| `roeForbiddenCategories` | 6 | **no** |
| `roeExcludedHosts` | 6 | yes |
| `roeForbiddenTools` | 2 | **no** |

The `roeGlobalMaxRps` rows are the interesting ones: for documents that state no
rate at all, the parse invents a 5 rps ceiling. It is conservative and safe, and
it is still a number nobody wrote down. Worth knowing when reading a parsed
engagement.

The client's own name was extracted into the record in 33 of 100 results. That is
correct behaviour rather than a stated rule, so it is recorded and not asserted.

## Defects found and fixed

### 1. The one setting 28 of 60 policies state could not be extracted from any of them

`engagementIdentityHeader` was **not in the parse prompt at all**. More real
policies require a custom identification header on every request than state a
rate limit, and the field the platform has for exactly that was unreachable.

`is_policy_constrainable` decides what the generated prompt names. The field is
`mcp: settable`, so it is parse-writable, but it has no `group`, no
`deny_reason`, `traffic: none`, and `tool: engagement` was not in the allowlist,
so it failed all five tests.

Fixed by adding `engagement` to that allowlist, which is a registry query rather
than a name: it adds exactly one field, because the only other `tool: engagement`
column is `engagementKind`, which is `create_only` and so not parse-writable at
all. Six cases went from failing to passing on that change alone.

### 2. A document could rewrite the entire pipeline

One parse returned **631 of the 658 fields in the prompt** — almost all zeroes
and falses, none rejected, because every value was individually legal:

```
agentBruteForceMaxWordlistAttempts = 0
agentLatsMaxDepth                  = 2
agentGuardrailEnabled              = True
...626 more
```

Per-field validation cannot see this. The failure is the **shape** of the answer,
not any one value in it. Left alone it either buries a real diff in a 631-row
table for someone to approve, or on a non-interactive path rewrites the project
wholesale.

Across sixty documents every legitimate proposal was between 2 and 28 fields.
`MAX_PROPOSED_CHANGES = 60` is roughly four times the largest observed and an
order of magnitude below the failure; over it, `/api/roe/parse` returns 422,
names the count, and writes nothing.

It is **not** a property of one document. Over five runs it struck four different
policies, in three guises: over the bound, or so large the JSON was truncated and
unparseable, or slow enough to be pathological (23 seconds against a normal 3).
An intermittent failure that can hit any upload is exactly what a bound is for.

### 3. A closed set the registry called free text, again

The 631-field proposal included `supplyChainInputMode`, and the save then failed:

```
supplyChainInputMode must be one of: upload, github, org
```

That vocabulary is declared in `webapp/src/lib/validation/supplyChainInput.ts` and
nowhere else. The registry had it as `free_text`, so the prompt advertised it as
free text and the parse validator accepted anything — while the proposal modal
tells the operator every value is "already checked against the same bounds the
API enforces". For this field that was false.

This is the third instance of the same defect class, and the first found by a
real document. A sweep of `webapp/src/lib/validation/` shows it was the only
remaining one.

### 4. The category vocabulary never said what its tokens mean

`roeForbiddenCategories` listed `brute_force, dos, social_engineering, physical,
exploitation` and left the model to guess that "credential stuffing" is
`brute_force`. It often did not. The meaning now glosses each token with the
phrasings real policies use, which is better documentation independently of the
parse.

## Still open

The `/roe/parse` digest guard covers `registry.json` but not `roe_prompt.py`, so
a change to the prompt GENERATOR leaves a stale baked prompt undetected. Three of
the fixes above were generator changes with an unchanged digest, and each one
needed a manual agent rebuild that nothing would have caught.
