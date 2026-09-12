# tls_target — TLS Certificate Grab (tlsx) harness

Validates the **GROUP 3.6 tlsx** module and every consumer that reads a
certificate, against real TLS handshakes rather than fixtures.

```bash
cd testing/guinea_pigs/tls_target && docker compose up -d --build
# target: 192.88.98.10   (IMAPS 993, LDAPS 636)
docker compose down
```

## Why this target serves no HTTP

tlsx exists because httpx only grabs certificates on the five HTTPS ports it
dials. A host whose TLS lives on 993/636 was found "open", labelled from a
static IANA table, and never inspected again. Serving **no HTTP at all** is the
honest reproduction of that gap: `http_probe` finds nothing here, so every
`Certificate` node in the graph after a run demonstrably came from tlsx.

## Why 192.88.98.10 and not 127.0.0.1

`_build_tlsx_targets` filters every candidate through `is_non_routable_ip()`
before a packet is sent, and `merge_discovered_hostnames` resolve-checks each
SAN name the same way. Loopback, RFC1918 and every TEST-NET range are rejected,
so a lab on `127.0.0.1` yields **zero** tlsx targets and proves nothing.

`192.88.98.0/24` is in the deprecated 6to4 relay block (RFC 7526), which
Python's `ipaddress` reports as global — so the SSRF control stays **armed** and
the run exercises the real production path. Nothing leaves the host. A distinct
/24 from `supply_chain_target`'s `192.88.99.0/24` so both labs can run at once
(Docker refuses overlapping subnets).

## What each port exercises

| Port | Certificate | Pipeline step it proves |
|---|---|---|
| 993 | self-signed, valid, SAN: `mail.tlslab.test`, `imap.tlslab.test`, **`outsider.example-evil.test`** | cert grab on a non-HTTP port; `Service.tls_service_hint = imaps`; `COVERS_HOST` for in-scope SANs only (domain mode; IP mode fails closed, see Expected result); the out-of-scope SAN must never be injected as a scan target; `tls_self_signed` + `tls_hostname_mismatch` findings |
| 636 | **expired** (notAfter 2024-02-01) | `tls_expired` at `high`. Before the fix an already-expired certificate produced **zero** findings — the most severe case was the one dropped; `Service.tls_service_hint = ldaps` |

The out-of-scope SAN is the point of the harness, not decoration: a SAN list is
chosen by the scanned host, so it is attacker-controlled input. This lab proves
the apex allow-list holds against a certificate that actually carries a foreign
name.

## Expected result

Verified against a real IP-mode pipeline run (target `192.88.98.10`):

```
[+][Tlsx] grabbed 2 cert(s) from 2 target(s)
summary: targets=2 responded=2 with_cert=2 expired=1 self_signed=2 mismatched=2

Certificates      mail.tlslab.test (sha256:7a7247…), ldap.tlslab.test (sha256:abe91b…, expired)
                  source=tlsx  observed_by=['tlsx']     <- nothing here serves HTTP
IP HAS_CERTIFICATE  2
Subdomain nodes   1, the reverse-DNS placeholder        <- no SAN name was promoted
Findings          tls_expired(high) + tls_self_signed x2 + tls_hostname_mismatch x2
```

Two results look like failures and are not.

**`COVERS_HOST` is 0 in IP mode.** SAN promotion is scope-contained behind an
apex allow-list, and IP mode has no apex, so it fails closed: `discovered_hostnames`
lists all four SAN names and none becomes a `Subdomain`. The edges only appear
when a root domain is in scope (domain mode), which needs `*.tlslab.test` to
resolve on the host. The graph write itself is covered by
`tests/test_tlsx_graph_live.py`.

**`Service` enrichment needs a PTR record.** naabu emits no `host` field when it
scans a bare IP with no reverse DNS, so `port_scan.by_host` is empty and
`port_mixin` -- which creates `Port`/`Service` only from `by_host` -- creates
neither. tlsx computes the hint correctly either way (`tls_service_hint=imaps`
on 993, `ldaps` on 636, both in the recon JSON); with no `Service` node there is
nothing to MATCH and enrich. Expected once a Service exists:

```
Service 993       tls=true  tls_version=tls13  tls_service_hint=imaps   name UNCHANGED
Service 636       tls=true  tls_version=tls13  tls_service_hint=ldaps   name UNCHANGED
```

`Service.name` staying `unknown` is an assertion, not an accident: `name` is part
of the Service MERGE key, so a tlsx run that "corrected" it would orphan the node
the port scan created and silently duplicate the service.

**Findings need the master switch.** The six TLS toggles sit behind the Security
Checks master toggle (`securityCheckEnabled`). With it off there are certificates
and zero findings, which looks identical to a broken check.

> ⚠️ Intentionally weak certificates. Local/trusted Docker host only.
