# `recon_settings` — the one place a recon parameter is described

`registry.yaml` is the single hand-maintained description of every recon
parameter and every pipeline tool. `registry.json` is its build artifact, and
the artifact is what every consumer reads.

## What lives here and what does not

Prisma stays the source of truth for the database. It owns which columns exist,
their type and their `@default()`, so the registry never restates any of those:
the build joins them from `webapp/prisma/schema.prisma`. Copying a default in
here would create a third definition of a value that already has two, which is
the drift this directory exists to remove.

| Lives in | Holds |
| --- | --- |
| `webapp/prisma/schema.prisma` | existence, type, `@default()`, `@map` |
| `recon_settings/registry.yaml` | `runtime_key`, `bounds`, `validator`, `zero_means`, `fallback`, `coerce`, `unit`, `tool`, `phase`, `traffic`, `roe_capped`, `mcp`, `meaning`, and the `tools:` blocks |
| a Postgres row | one project's actual values |

Descriptions never enter the database. A description is identical for every
project, so it is metadata about the schema rather than data about a project;
storing it in Postgres would mean a migration to fix a typo and would force the
recon pipeline to take a database dependency just to know what a field means.
It also preserves a property the MCP surface already advertises:
`describe_recon_settings` answers even when Postgres and Neo4j are down.

## Files

| File | Role |
| --- | --- |
| `registry.yaml` | authored source. Edit this. |
| `registry.schema.json` | JSON Schema the YAML validates against |
| `build.py` | YAML -> JSON, validating; writes both artifacts |
| `registry.json` | build artifact, read by Python |
| `webapp/src/lib/reconSettings/registry.json` | the same artifact, read by TypeScript |

Both artifacts are emitted by one build from one source and are byte-compared
by the drift tests, so the duplicate copy cannot diverge. Two copies exist
because a scan container mounts `recon/` but never `webapp/`, and the webapp
build tree cannot import across its own root.

## Rebuilding

```bash
python3 recon_settings/build.py           # writes both artifacts
python3 recon_settings/build.py --check   # fails if either is stale
```

`--check` is what the drift tests run.

## The `mcp:` disposition

| Value | Meaning |
| --- | --- |
| `settable` | write any time through `update_recon_settings` |
| `create_only` | write once at `create_project`; immutable afterwards |
| `tighten_only` | the RoE block: may move in the safe direction only |
| `never` | not a pipeline parameter; `deny_reason` says which class |

The allowlist is no longer the control. Validation at the point of use is: a
field is open and its value is bounded, validated, or pinned at scan start.
`sanitize_image_settings()` is the shipped precedent — the `*DockerImage`
columns accept any string and the runtime pins a non-allowlisted one back to the
shipped default.

## Three keys that exist because uniformity is a lie

- **`zero_means: unlimited`** — several rate fields treat `0` as unlimited,
  which is the *fastest* value available and not the slowest. Without this key a
  reader concludes `0` is the gentlest setting and writes it onto a 3 rps
  engagement.
- **`fallback: falsy`** — a few mappings are `project.get(k) or DEFAULT` rather
  than `project.get(k, DEFAULT)`, so a stored empty value is replaced by the
  default instead of being honoured.
- **`coerce: int | strip`** — a few mappings wrap the stored value.
