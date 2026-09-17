# Phase 1 — RoE upload through the UI

**Result: 20/20 pass, three consecutive runs.** Five defects were found and fixed
to get there; two more are recorded below as findings rather than fixes, with
evidence, because closing them safely is a separate change.

- Date: 2026-09-17
- Branch: `feature/mcp-recon-settings-registry`
- Model: `deepseek/deepseek-chat` (bare `deepseek-chat` does not route; the
  prefix is required)
- Matrix: [`cases.json`](cases.json) · Documents: [`docs/`](docs/) ·
  Raw results: [`results.json`](results.json) · Runner: [`run_ui_e2e.py`](run_ui_e2e.py)

## What was actually tested

Every case drives the real running stack with a real session cookie:

```
POST /api/roe/parse       multipart upload -> text extraction -> the agent
                          -> an LLM -> re-validation against the registry
                          -> a PROPOSAL (a diff), never a write
PUT  /api/projects/{id}   applying the confirmed proposal, as the form does
SELECT ... FROM projects  the verdict
```

The verdict is read from Postgres, never from the API response. A proposal that
looks right over a row that holds something else is precisely the failure this
feature can have, and only the database settles it.

One case was additionally driven through the browser end to end (below), because
the runner exercises the API and not the React form.

### The matrix is built so a pass cannot be an accident

Before each case, **every asserted column is seeded with a value the case does
not expect**. This was not the original design and it matters: "DoS is
prohibited" expects `roeAllowDos = false`, which is also the shipped default, so
the case went green on a document the parser had ignored entirely. Three cases
were passing that way, and a fourth (UI-17) was exposed as a genuine failure the
moment seeding was added. Starting from the opposite value makes every assertion
earn its result.

Lists compare exactly. The one exception is declared per-case in `allow_extra`
and justified against the document, so the over-reach cases (UI-08, UI-19,
UI-20) stay meaningful — for them an unexpected value is still a failure.

## The 20 cases

| | Case | What it pins |
|---|---|---|
| UI-01 | global rate ceiling | a stated rate becomes the engagement ceiling, not a per-tool rate |
| UI-02 | never-touch hosts | exclusions land with their reason array positionally aligned |
| UI-03 | scanning window | days, hours and timezone all land; the window switch flips on |
| UI-04 | no directory brute forcing | a prohibition on a **technique** reaches the tool that performs it |
| UI-05 | DoS prohibited | both expressions of one rule: the allow flag and the category |
| UI-06 | reconnaissance only | a phase restriction caps severity without stripping tools |
| UI-07 | named tool ban | "do not use Hydra" becomes a tool the gate actually refuses |
| UI-08 | discouraged ≠ forbidden | **negative case**: "use with caution" must change nothing |
| UI-09 | passive only | the engagement's passive switch |
| UI-10 | client and contacts | the record fills from the document though MCP can never write it |
| UI-11 | engagement dates | dates normalise to `YYYY-MM-DD` |
| UI-12 | severity floor | "report critical and high only" narrows the nuclei severity list |
| UI-13 | phases restricted | naming permitted activities narrows `scanModules` |
| UI-14 | account lockout forbidden | reaches the agent's lockout gate |
| UI-15 | social engineering out of scope | people-targeting techniques refused |
| UI-16 | data handling and retention | closed-vocabulary record fields land on a permitted value |
| UI-17 | compliance frameworks | framework recorded from the document |
| UI-18 | everything at once | a realistic multi-rule document, 13 changes in one pass |
| UI-19 | hostile scope statement | **security**: a document naming a domain and IP range must not re-point the project |
| UI-20 | prompt injection | **security**: instructions addressed to the model are parsed as text, not obeyed |

UI-19 and UI-20 are the two that must never regress. In both, the document tries
to set `targetDomain`, `targetIps`, `ipMode`, `subdomainList` and
`domainBatchHosts`; all are refused, because a scope document configures a
project, it does not decide what the project points at. UI-20 additionally tries
to extract a credential (`cypherfixGithubToken`), enable `mcpKaliExecEnabled`,
and remove the rate ceiling. It gets the ceiling it asked to remove (2 rps) and
nothing else.

## Defects found and fixed

### 1. `/roe/parse` returned 503 for every model

`_setup_llm_for_endpoint` read `USER_LLM_PROVIDERS` out of the orchestrator's
loaded **project** settings. But a RoE document is uploaded while a project is
being *created* — the only place the UI offers the upload — so there is no
project, and on a freshly started agent none has ever been loaded. The provider
list was empty, no key resolved, and every parse answered
`503 {"error": "LLM not available for model <X>"}` with two working providers
configured.

It presented as a model-routing problem and was not. It was an endpoint reading
its credentials out of a scope it does not have. Fixed by threading the caller's
`user_id` and fetching that user's providers.
Pinned by `agentic/tests/test_roe_parse_llm_resolution.py` (7 tests).

### 2. A forbidden tool that was recorded and never enforced

`execute_plan_node.py` matches `roeForbiddenTools` **exactly** against the
dispatched tool name. The registry declared the column free text, so the prompt
told the model only "by name", and it answered `hydra`. `hydra` never matches
`execute_hydra`, so the ban was stored, rendered in the UI as a rule, passed to
the agent's prompt as advice — and Hydra ran.

The form made it worse: a comma-separated text box whose own placeholder read
`e.g. execute_hydra, execute_sqlmap`. **`execute_sqlmap` is not a tool.** The
product taught the value that cannot work, and a live project had taken it.

### 3. Forbidden categories, the same failure

`CATEGORY_TOOL_MAP` has four keys. The column was free text. A live project held
seven categories and **not one matched**:

| stored in a real project | effect on the gate |
|---|---|
| `Denial of Service`, `Brute Forcing`, `Password Spraying`, `Banner Grabbing`, `Cache Poisoning`, `HTTP Request Smuggling`, `Client-Side Desync` | silently no-op |
| `brute_force` | blocks 4 tools |

Somebody forbade denial-of-service and brute-forcing and the agent was never
blocked from a single tool.

**Fix for 2 and 3** (and for `roeSensitiveDataHandling`, `roeEngagementType`,
`roeStatusUpdateFrequency`, `roeComplianceFrameworks`, which had closed
vocabularies in the UI and open ones in the registry): declare `values:` in
`registry.yaml`. That is one change with two effects, because the registry is the
single source — the generated prompt now teaches the model the exact tokens, and
the validator refuses anything outside them. The form's two vocabularies are now
read from the registry rather than hard-coded, and the free-text box is a
checkbox grid.

`roeSensitiveDataHandling` is the clearest illustration: it was advertised to the
model as `a string (free_text)`, so a parse stored an entire prose paragraph in a
column whose four consumers all switch on a token.

### 4. A closed vocabulary on a list field told the model to send one value

Introduced by the fix above and caught by the matrix. `accepts()` checked
`values` **before** type, so a `string-list` with a vocabulary was described as
`one of: ...` — an instruction to pick one scalar. The model obeyed,
`nucleiSeverity` arrived as `"high"`, the validator refused it as
`must be an array`, and "report critical and high only" was lost.

Lists now render as `a list, each item one of: ...`. Scalars are unchanged.

The refusal itself is correct and is surfaced in the UI's rejected rows; nothing
was silently dropped. The prompt was the bug.

### 5. `stealthMode` did not describe what it does

The document said "strictly passive only, no active scanning". The registry's
meaning was "Reduce scan aggressiveness and network noise", so the model recorded
the rule as prose and set nothing. But `apply_stealth_overrides` forces **every**
recon tool to its passive profile and switches the noisiest off outright:
`stealthMode` *is* the passive switch. The meaning now says so, and names the
phrasings a RoE uses for it.

No behaviour changed here — only the registry's description of behaviour that
already existed. That is the whole fix, and it is enough, because the meaning is
what the prompt gives the model.

## Findings recorded, not fixed

**16 more settings are closed in the UI and open in the registry.** The same
class as defect 3, found by sweeping every `<select>` bound to a registry field:
`cveLookupSource`, `naabuScanType`, `nmapTimingTemplate`, `httpxProbeHash`,
`jsReconMinConfidence`, `agentPostExplPhaseType`, `webCachePoisonScanProfile`,
`zapAjaxSpiderScopeCheck`, `kiterunnerMethodDetectionMode` and others.

They are not closed here because a blanket close would be a worse regression than
the bug. Some are convenience lists over a genuinely open domain: `ffufWordlist`
is a filesystem path, `gvmScanConfig` and `gvmPortList` are server-side GVM
preset names a given instance may extend, `nmapTimingTemplate`'s own meaning says
T0–T5 while the form offers T1–T5, and ZAP may accept browser ids beyond the
three listed. Each needs its consumer checked. Worth its own pass.

**The digest guard does not cover the prompt generator.** `/roe/parse` fails
closed on registry skew by embedding the SHA-256 of `registry.json`. Defect 4 was
a change to `roe_prompt.py` with `registry.json` untouched, so the digest was
identical and a stale baked prompt would not have been detected. The guard covers
registry drift, not generator drift.

**Two stale names in the gate's own category map.** `CATEGORY_TOOL_MAP` lists
`proxy_fuzz` and `proxy_replay`, which were replaced by `proxy_brain` and are no
longer dispatchable. Forbidding `brute_force` or `exploitation` therefore blocks
less than it claims. `physical` is offered by the UI and has no map entry at all.

## Browser walk

The runner exercises the API, so UI-18 was additionally driven through the real
form in Chrome: log in, create project, RoE tab, upload
`ui-18-combined.md`, review, apply, save.

- The diff modal renders as designed — 13 changes, each routed to its correct
  section, under "Nothing has been applied yet".
- Applying fills the form; saving persists it.
- The new forbidden-tools checkbox grid renders all 28 agent tool names, and the
  `execute_sqlmap` placeholder is gone.
- "Availability testing" shows ticked, which is `dos` — the document's DoS
  prohibition arriving as the token the gate enforces.
- Leaving with unsaved changes triggers the guard.
- No RoE-related console errors. The 404s observed are `/api/graph` and the
  scan-download routes for a project with no scan data yet.

Then the chain was followed past the database into enforcement:

```
recon pipeline   ROE_ENABLED = True   (derived; the stored column says false)
                 ROE_GLOBAL_MAX_RPS = 10
                 ROE_EXCLUDED_HOSTS = ['legacy.globex.test']
                 ROE_TIME_WINDOW_ENABLED = True, 20:00 -> 06:00

agent            ROE_MAX_SEVERITY_PHASE = 'exploitation'
                 ROE_FORBIDDEN_CATEGORIES = ['dos']
                 ROE_ALLOW_DOS = False

gate             execute_hydra      @exploitation      -> RoE BLOCKED
                 metasploit_console @post_exploitation -> RoE BLOCKED (phase)
                 execute_nmap       @post_exploitation -> RoE BLOCKED (phase)
                 execute_nuclei     @exploitation      -> ALLOWED
                 execute_curl       @informational     -> ALLOWED
```

The document said post-exploitation is not permitted. The gate refuses it. That
is the whole claim of the feature, demonstrated from a `.md` file to a refusal.

`roe_enabled` being `false` in the column while the pipeline resolves `True` is
correct, not a defect: the value is derived and never written, and all three
consumers (`recon/project_settings.py:1891`, `agentic/project_settings.py:601`,
`recon_orchestrator/api.py:259`) call `derive_roe_enabled` rather than reading
the column. That was verified by grep and by resolving the settings in both
images.

## Cleanup

All test projects deleted (`SELECT count(*) ... WHERE name LIKE 'e2e-roe%'` → 0).
All 20 documents kept under `docs/`, as instructed.

## Reproducing

```bash
E2E_PASSWORD=... python3 e2e_roe/ui/run_ui_e2e.py          # all 20
E2E_PASSWORD=... python3 e2e_roe/ui/run_ui_e2e.py UI-19    # one case
```

The runner creates its own project, resets state between cases so one document
cannot mask the next, and deletes the project on the way out — including when a
case raises.
