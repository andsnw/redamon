#!/usr/bin/env bash
# =============================================================================
# The inbound MCP endpoint's nginx location.
# Run:  bash tests/deploy_mcp_nginx_test.sh
#
# Two traps this pins, both of which fail SILENTLY in production:
#
# 1. EXACT MATCH. A prefix block written `location /api/mcp-server/ {` does NOT
#    match the endpoint URL `/api/mcp-server`. The request would fall through to
#    `location /api/` and get the UI rate zone plus - under
#    GATE_MODE=basic_auth - a gate that eats the Authorization header the
#    client needs. Nothing errors; MCP just stops working, or works with the
#    wrong limits.
#
# 2. HEADER INHERITANCE. A location carrying ANY add_header does not inherit the
#    server-level ones, so HSTS/CSP and Cache-Control are lost unless re-emitted.
#    The template already records this trap on the login location; this endpoint
#    has the same shape.
#
# Plus the §14.2 decision: under basic_auth the endpoint is CLOSED by default,
# because Basic and Bearer cannot both travel in one Authorization header.
#
# The rendered configs are validated with a real `nginx -t` when Docker is
# available, and skipped cleanly when it is not.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host"
TMPL="$DEPLOY/nginx/redamon.conf.tmpl"
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
skip() { SKIP=$((SKIP+1)); printf '  skip %s (%s)\n' "$1" "$2"; }
eq()   { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

# render <GATE_MODE> [MCP_EDGE_ALLOW_BEARER] -> the rendered vhost on stdout
render() {
    ( cd "$REPO_ROOT" && \
      GATE_MODE="$1" MCP_EDGE_ALLOW_BEARER="${2:-false}" \
      OPERATOR_ALLOW_CIDRS="1.2.3.4/32" \
      SERVER_NAME=redamon.example SSL_CERT_REMOTE=/c.pem SSL_KEY_REMOTE=/k.pem \
      CSP_CONNECT="'self'" CSP_HEADER_NAME=Content-Security-Policy \
      WS_AUTH_REQUEST="" REDIRECT_HOST=redamon.example TLS_MODE=selfsigned \
      _NGINX_MOD="$DEPLOY/modules/nginx.sh" _TMPL="$TMPL" \
      bash -c '
        set -uo pipefail
        is_true() { [[ "$(printf "%s" "${1:-}" | tr "[:upper:]" "[:lower:]")" == "true" || "${1:-}" == "1" ]]; }
        source "$_NGINX_MOD"
        _render_template "$_TMPL"
      ' 2>/dev/null )
}

# The body of the exact-match MCP location, for content assertions.
mcp_block() {
    awk '/location = \/api\/mcp-server \{/{f=1} f{print} f&&/^    \}/{exit}'
}

echo "== the location is an EXACT match, not a prefix =="
IP_CONF="$(render ip_allowlist)"
if grep -qF 'location = /api/mcp-server {' <<<"$IP_CONF"; then
    ok "location = /api/mcp-server (exact)"
else
    bad "location = /api/mcp-server (exact)" "absent" "an exact-match block"
fi
# A trailing-slash prefix block would not match the endpoint URL at all.
if grep -qE 'location +/api/mcp-server/ *\{' <<<"$IP_CONF"; then
    bad "no trailing-slash prefix block" "present" "absent"
else
    ok "no trailing-slash prefix block"
fi

echo
echo "== it has its own rate zone, not the UI's =="
if grep -qE 'limit_req_zone .* zone=mcp:' <<<"$IP_CONF"; then
    ok "a dedicated 'mcp' limit_req_zone is declared"
else
    bad "a dedicated 'mcp' limit_req_zone is declared" "absent" "zone=mcp"
fi
BLOCK="$(mcp_block <<<"$IP_CONF")"
if grep -qF 'limit_req zone=mcp' <<<"$BLOCK"; then
    ok "the location uses zone=mcp"
else
    bad "the location uses zone=mcp" "$(grep -o 'zone=[a-z]*' <<<"$BLOCK" | head -1)" "zone=mcp"
fi
if grep -qF 'zone=api' <<<"$BLOCK"; then
    bad "the location does NOT use the UI zone" "zone=api" "zone=mcp only"
else
    ok "the location does NOT use the UI zone"
fi

echo
echo "== security headers are re-emitted (they are NOT inherited) =="
for hdr in Strict-Transport-Security X-Frame-Options X-Content-Type-Options \
           Referrer-Policy Cache-Control; do
    if grep -qF "add_header $hdr" <<<"$BLOCK"; then
        ok "$hdr re-emitted"
    else
        bad "$hdr re-emitted" "absent" "add_header $hdr"
    fi
done
if grep -qF 'no-store' <<<"$BLOCK"; then
    ok "Cache-Control is no-store"
else
    bad "Cache-Control is no-store" "absent" "no-store"
fi

echo
echo "== long-lived proxy settings match location /api/ =="
grep -qF 'proxy_read_timeout 3600s' <<<"$BLOCK" && ok "proxy_read_timeout 3600s" \
    || bad "proxy_read_timeout 3600s" "absent" "3600s"
grep -qF 'proxy_buffering off' <<<"$BLOCK" && ok "proxy_buffering off" \
    || bad "proxy_buffering off" "absent" "off"

echo
echo "== the gate decision (plan 14.2): closed by default under basic_auth =="
BASIC_BLOCK="$(render basic_auth | mcp_block)"
if grep -qF 'return 403;' <<<"$BASIC_BLOCK"; then
    ok "basic_auth alone -> 403 (Basic and Bearer cannot share the header)"
else
    bad "basic_auth alone -> 403" "no return 403" "return 403"
fi
BEARER_BLOCK="$(render basic_auth true | mcp_block)"
if grep -qF 'auth_basic off;' <<<"$BEARER_BLOCK"; then
    ok "MCP_EDGE_ALLOW_BEARER=true -> auth_basic off"
else
    bad "MCP_EDGE_ALLOW_BEARER=true -> auth_basic off" "absent" "auth_basic off"
fi
if grep -qF 'return 403;' <<<"$BEARER_BLOCK"; then
    bad "the opt-in removes the 403" "still 403" "no 403"
else
    ok "the opt-in removes the 403"
fi
if grep -qE 'return 403|auth_basic' <<<"$BLOCK"; then
    bad "ip_allowlist inherits the server gate unchanged" "overridden" "inherited"
else
    ok "ip_allowlist inherits the server gate unchanged"
fi

echo
echo "== the rendered config is valid nginx =="
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    skip "nginx -t on the rendered config" "docker unavailable"
else
    # The scratchpad is not bind-mountable, so stage inside the repo.
    WORK="$REPO_ROOT/.mcp-nginx-check.$$"
    mkdir -p "$WORK/snip"
    render ip_allowlist            > "$WORK/r_ip.conf"
    render basic_auth              > "$WORK/r_basic.conf"
    render basic_auth true         > "$WORK/r_bearer.conf"
    cp "$DEPLOY/nginx/snippets/security-headers.conf" "$WORK/snip/redamon-security-headers.conf"
    cp "$DEPLOY/nginx/snippets/proxy-common.conf"     "$WORK/snip/redamon-proxy-common.conf"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
        -days 1 -subj "/CN=test" >/dev/null 2>&1

    # Guard against a false pass: nginx -t succeeds on an EMPTY conf.d, so a
    # render that silently produced nothing would look green. Prove each file
    # actually carries the block under test before trusting the parse.
    for f in r_ip r_basic r_bearer; do
        if grep -qF 'location = /api/mcp-server {' "$WORK/$f.conf"; then
            ok "$f rendered a real config"
        else
            bad "$f rendered a real config" "empty or missing the MCP block" "a rendered vhost"
        fi
    done

    OUT="$(docker run --rm -v "$WORK:/s:ro" --entrypoint sh nginx:alpine -c '
        mkdir -p /etc/nginx/snippets && cp /s/snip/*.conf /etc/nginx/snippets/
        cp /s/c.pem /c.pem && cp /s/k.pem /k.pem
        mkdir -p /var/www/certbot; touch /etc/nginx/.redamon_htpasswd
        for f in r_ip r_basic r_bearer; do
            cp /s/$f.conf /etc/nginx/conf.d/redamon.conf
            if nginx -t 2>&1 | grep -q "test is successful"; then echo "$f OK";
            else echo "$f FAIL: $(nginx -t 2>&1 | grep emerg | head -1)"; fi
            rm -f /etc/nginx/conf.d/redamon.conf
        done' 2>/dev/null)"
    rm -rf "$WORK"

    for f in r_ip r_basic r_bearer; do
        if grep -qF "$f OK" <<<"$OUT"; then
            ok "nginx -t passes ($f)"
        else
            bad "nginx -t passes ($f)" "$(grep -F "$f" <<<"$OUT")" "test is successful"
        fi
    done
fi

echo
printf 'passed %d, failed %d, skipped %d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
