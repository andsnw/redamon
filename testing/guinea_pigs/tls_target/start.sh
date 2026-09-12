#!/bin/sh
# Serve TLS on NON-HTTP ports only. That is the whole point of this harness:
# httpx never dials 993/636, so before tlsx these certificates were invisible
# and the ports carried nothing but a static IANA label.
set -eu
CERTS=/certs
mkdir -p "$CERTS"

# 1. IMAPS (993): self-signed, multi-SAN. One SAN is deliberately OUT OF SCOPE
#    so the SAN feedback path's apex allow-list can be proven on real data.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$CERTS/imaps.key" -out "$CERTS/imaps.crt" \
  -subj "/CN=mail.tlslab.test/O=RedAmon TLS Lab" \
  -addext "subjectAltName=DNS:mail.tlslab.test,DNS:imap.tlslab.test,DNS:outsider.example-evil.test" \
  >/dev/null 2>&1

# 2. LDAPS (636): EXPIRED. Before the fix an already-expired certificate
#    produced ZERO findings -- the most severe case was the one dropped.
openssl req -x509 -newkey rsa:2048 -nodes \
  -not_before 20240101000000Z -not_after 20240201000000Z \
  -keyout "$CERTS/ldaps.key" -out "$CERTS/ldaps.crt" \
  -subj "/CN=ldap.tlslab.test/O=RedAmon TLS Lab" \
  -addext "subjectAltName=DNS:ldap.tlslab.test" \
  >/dev/null 2>&1

echo "[tls_target] IMAPS 993 (self-signed, 3 SANs) + LDAPS 636 (expired) ready"

# -naccept bounds each s_server; the loop makes the listener effectively
# permanent so a scan's retries and a later partial-recon run both work.
while true; do
  openssl s_server -accept 993 -cert "$CERTS/imaps.crt" -key "$CERTS/imaps.key" \
    -naccept 50 -quiet >/dev/null 2>&1 || true
done &
while true; do
  openssl s_server -accept 636 -cert "$CERTS/ldaps.crt" -key "$CERTS/ldaps.key" \
    -naccept 50 -quiet >/dev/null 2>&1 || true
done &
wait
