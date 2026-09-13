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
> | **MCP Inbound** (this document) | **inbound** — other agents are the *clients*, RedAmon is the *server* | Global Settings → *MCP Inbound* |

---

## 1. What is and is not exposed

**Exposed (nine tools).**

| Tool | What it does | Permission |
| --- | --- | --- |
| `list_projects` | The token owner's projects. Nothing else is visible. | `recon:read` |
| `get_recon_status` | Whether a scan is running, and its phase. | `recon:read` |
| `get_recon_settings` | The tuning subset this token may change. | `recon:read` |
| `graph_summary` | Count per node type + relationships present. | `recon:read` |
| `graph_schema` | What the graph *means*. No arguments, no data. | `recon:read` |
| `query_graph` | Ask the graph a question in natural language. | `recon:read` (+ `graph:cypher` for raw Cypher) |
| `start_recon` | Start the full recon pipeline. | `recon:scan` (+ `recon:overwrite` for `mode:"overwrite"`) |
| `stop_recon` | Stop a running scan. | `recon:scan` |
| `update_recon_settings` | Change allowlisted recon tuning. | `recon:settings` |

**Deliberately not exposed:** the agent chat, Kali and exploitation tools,
partial recon, project create/delete/import, secrets and LLM keys, target and
scope fields, Rules of Engagement, guardrails, GVM/TruffleHog/supply-chain/AI
attack-surface scan control, and any graph **write**.

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

**Global Settings → MCP Inbound → New token.**

- **Minting is self-only**, judged on your real login identity. An admin viewing
  another user's settings sees the form disabled with a reason: a token minted
  that way would outlive the act-as session, need no further authentication, and
  be indistinguishable from the user's own calls. Admins *can* list and revoke —
  revoking is a safe privilege; minting is not.
- It asks for your **password again**. A stolen 7-day session cookie must not
  silently become a credential that outlives logout.
- **Permissions default to read-only.** Every write permission is opt-in, and
  each says what it allows. `recon:overwrite` says plainly that it permits
  discarding the current graph.
- **Expiry** defaults to 90 days. It is re-checked on *every call*, so expiry and
  revocation take effect mid-session rather than at the client's next reconnect.
- The token is shown **once**. Afterwards only its first 8 characters are ever
  displayed.

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
- [GRAPH.SCHEMA.md](GRAPH.SCHEMA.md) — node labels and relationships
