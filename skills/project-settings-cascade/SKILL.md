---
name: project-settings-cascade
description: >
  Changing or adding a project setting / default value in RedAmon. A single
  setting is duplicated across Prisma, two separate Python settings modules, the
  orchestrator defaults endpoint, and the frontend fallback; miss a layer and the
  UI shows one value while the backend uses another, and existing projects keep
  the old value forever.
  Trigger: editing a @default in webapp/prisma/schema.prisma; editing
  DEFAULT_AGENT_SETTINGS or fetch_agent_settings in agentic/project_settings.py,
  or DEFAULT_SETTINGS or fetch_project_settings in recon/project_settings.py;
  editing the /defaults endpoint or RUNTIME_ONLY_KEYS in recon_orchestrator/api.py;
  changing a default toggle/number/string in a ProjectForm section.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [webapp, agentic, recon]
  auto_invoke:
    - "Changing or adding a project setting or default value"
    - "Editing a Prisma @default, a Python settings default, or the /defaults endpoint"
---

## When to Use

- Adding a new project setting, or changing the default value of an existing one.

This skill is the settings sub-pattern the tool/skill skills depend on; they link
here rather than restating it. For the surrounding tool wiring, see
`agentic-tool-integration`,
`recon-tool-integration`, or
`builtin-agent-skill`.

---

## Critical Rules

- **NEVER change a default in one layer only.** A setting is synchronized across
  every layer in the table below. Update them in one commit or the UI and backend
  drift silently.
- **NEVER assume existing projects pick up a new/changed default.** A Prisma
  `@default` applies to **new** projects only. Existing rows keep their stored
  value; changing behaviour for them needs an explicit SQL `UPDATE` (ask before
  running it - it mutates every project).
- **NEVER share settings code between agent and recon.** `agentic/project_settings.py`
  and `recon/project_settings.py` are **separate** modules with their own default
  dicts (`DEFAULT_AGENT_SETTINGS` vs `DEFAULT_SETTINGS`). A setting used by both
  is declared in both.
- **NEVER use `prisma migrate`.** This project is push-based:
  `docker compose exec webapp npx prisma db push`.
- **ALWAYS keep the name triad aligned**: DB column `snake_case` (via `@map()`),
  Prisma field + frontend + API `camelCase`, Python key `SCREAMING_SNAKE_CASE`.
  A mismatch means `fetch_*_settings` reads `None` and silently falls back to the default.
- **ALWAYS give the frontend `onChange` a fallback** equal to the Python/Prisma
  default, so a project saved before the field existed does not write `undefined`.
- **A new column FAILS THE BUILD until it has a registry entry.** Every
  parameter is described once, in
  [recon_settings/registry.yaml](../../recon_settings/registry.yaml), with its
  unit, phase, traffic class, engagement-cap flag, MCP disposition, meaning, and
  either a bound or a named validator. Add the column, run
  `python3 tooling/scripts/extract_recon_registry.py` to draft the entry, EDIT
  IT, then `python3 recon_settings/build.py`. The draft is a starting point: no
  extraction can tell whether a `meaning` is true or a bound is right.
- **NEVER hand-edit `registry.json`.** It is a build artifact, written to two
  places (`recon_settings/` for Python, `webapp/src/lib/reconSettings/` for
  TypeScript) by one build, and `build.py --check` fails the gate when either is
  stale. Edit the YAML.
- **NEVER add a rate field without `roe_capped: true`.** An `rps` field with
  `traffic: active` and no cap fails the build, because that gap is how three
  rate limits shipped reachable over MCP and outside the engagement ceiling.
- **State what `0` means on any field that defaults to it.** Several rates treat
  `0` as UNLIMITED, which makes it the FASTEST value rather than the safest. A
  numeric defaulting to 0 without `zero_means` fails the build, and the `meaning`
  has to repeat it in words.

---

## The layers (recon example: `katanaTimeout`)

| Layer | File | Form |
| --- | --- | --- |
| DB / schema | [webapp/prisma/schema.prisma](../../webapp/prisma/schema.prisma) | `katanaTimeout Int @default(3600) @map("katana_timeout")` |
| Python default | [recon/project_settings.py:21](../../recon/project_settings.py#L21) `DEFAULT_SETTINGS` (or [agentic/project_settings.py](../../agentic/project_settings.py) `DEFAULT_AGENT_SETTINGS`) | `'KATANA_TIMEOUT': 3600` |
| Fetch mapping | [recon/project_settings.py:863](../../recon/project_settings.py#L863) `fetch_project_settings` (or `fetch_agent_settings` in the agent module) | `settings['KATANA_TIMEOUT'] = project.get('katanaTimeout', DEFAULT_SETTINGS['KATANA_TIMEOUT'])` |
| Registry | [recon_settings/registry.yaml](../../recon_settings/registry.yaml) | `katanaTimeout: { tool: katana, runtime_key: KATANA_TIMEOUT, unit: seconds, phase: resource_enum, traffic: active, roe_capped: false, mcp: settable, bounds: {...}, meaning: ... }` |
| Served defaults | [recon_orchestrator/api.py](../../recon_orchestrator/api.py) `/defaults` | nothing to do: the payload and its exclusions are REGISTRY QUERIES now. A key with no column is excluded by `source: internal`, and the column name comes from the registry rather than a snake-to-camel guess (which could not recover an intercap, so nine settings never reached the form). |
| Frontend | the tool's `ProjectForm` section component | control with an `onChange` fallback equal to the default. Its `min`/`max` must not be WIDER than the registry bounds, or the form accepts a value the save refuses. |

Agent-only settings use `DEFAULT_AGENT_SETTINGS` + `fetch_agent_settings`; recon-only
use `DEFAULT_SETTINGS` + `fetch_project_settings`. There is no shared module.

## Commands

```bash
python3 tooling/scripts/extract_recon_registry.py             # draft the registry entry for a new column
python3 recon_settings/build.py                               # rebuild both artifacts (--check in the gate)
cd webapp && npm run docs:settings                            # regenerate the wiki settings registry
docker compose exec webapp npx prisma db push                 # apply schema; NEVER prisma migrate
docker compose build agent && docker compose up -d agent      # only if you changed agentic/ defaults
docker compose restart recon-orchestrator                     # if you changed the /defaults endpoint
# existing projects (ask first - mutates every row):
docker compose exec postgres psql -U redamon -d redamon -c "UPDATE projects SET katana_timeout = 3600 WHERE katana_timeout IS NULL;"
```

## Resources

- Naming + servement details in [docs/readmes/coding_agent_prompts/PROMPT.ADD_RECON_TOOL.md](../../docs/readmes/coding_agent_prompts/PROMPT.ADD_RECON_TOOL.md) (settings multi-layer flow)
- Related skills: `agentic-tool-integration`, `recon-tool-integration`, `recon-ai-enrichment`
