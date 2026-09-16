"""
Build the first `recon_settings/registry.yaml` from the sources that already
describe the recon pipeline.

This runs ONCE to seed the registry, and then again whenever a re-seed is
cheaper than a hand edit. It is not part of the gate: `recon_settings/build.py`
is. Everything it emits is a starting point a human then reads, because no
extraction can tell whether a `meaning` is TRUE or whether a bound is right.

Sources, and what each one is authoritative for:

  webapp/prisma/schema.prisma          existence, type, @default(), /// docs
  recon/project_settings.py            runtime_key, fallback/coerce shape
  reconSettingsAllowlist.generated.ts  today's bounds and deny classification
  ProjectForm/sections/*.tsx           min/max and the operator-facing hint
  recon-preset-schema.ts catalog       474 prose descriptions

Nothing here invents a default or a type: those stay in Prisma and are joined
at build time.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from parse_settings_mappings import parse_mappings  # noqa: E402
from prisma_project_columns import Column, project_columns  # noqa: E402
from recon_registry_meanings import meaning_for as authored_meaning  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SECTIONS_DIR = REPO_ROOT / "webapp" / "src" / "components" / "projects" / "ProjectForm" / "sections"
ALLOWLIST_TS = REPO_ROOT / "webapp" / "src" / "lib" / "reconSettingsAllowlist.generated.ts"
PRESET_SCHEMA_TS = REPO_ROOT / "webapp" / "src" / "lib" / "recon-preset-schema.ts"
RECON_SETTINGS_PY = REPO_ROOT / "recon" / "project_settings.py"
OUT_YAML = REPO_ROOT / "recon_settings" / "registry.yaml"

# --- the tool table -------------------------------------------------------------
# camelCase column prefix -> tool id. Longest prefix wins, so `aiSurfaceRecon`
# beats `ai` and `supplyChainRecon` beats `supplyChain`. A prefix that is not a
# pipeline tool (roe, agent, project identity) still gets an id, because every
# field must belong to exactly one group and "ungrouped" is how a field stops
# being findable.
TOOL_PREFIXES: list[tuple[str, str]] = [
    ("aiSurfaceRecon", "ai_surface_recon"),
    ("aiInPipeline", "pipeline_ai"),
    ("aiPipelineModel", "pipeline_ai"),
    ("supplyChainRecon", "supply_chain_recon"),
    ("supplyChain", "supply_chain"),
    ("webCachePoison", "web_cache_poison"),
    ("securityCheck", "security_check"),
    ("originDiscovery", "origin_discovery"),
    ("pathTraversal", "path_traversal"),
    ("resourceEnumAi", "resource_enum_ai"),
    ("httpProbeAi", "http_probe_ai"),
    ("portScanAi", "port_scan_ai"),
    ("domainReconAi", "domain_recon_ai"),
    ("domainBatch", "targeting"),
    ("bannerGrab", "banner_grab"),
    ("cveLookup", "cve_lookup"),
    ("knockpyRecon", "knockpy"),
    ("hackerTarget", "hackertarget"),
    ("criminalIp", "criminalip"),
    ("virusTotal", "virustotal"),
    ("zoomEye", "zoomeye"),
    ("vhostSni", "vhost_sni"),
    ("jsRecon", "js_recon"),
    ("graphqlCop", "graphql_cop"),
    ("subdomainDiscovery", "subdomain_discovery"),
    ("subdomainTakeover", "takeover"),
    ("subdomainList", "targeting"),
    ("authProfile", "auth_profile"),
    ("captureProxy", "capture_proxy"),
    ("osintEnrichment", "osint_enrichment"),
    ("scaIntel", "supply_chain"),
    ("wafAi", "waf"),
    ("mcpKaliExec", "project"),
    ("attackSkill", "agent"),
    ("triageReview", "agent"),
    ("scanModules", "pipeline"),
    ("stealthMode", "pipeline"),
    ("updateGraphDb", "pipeline"),
    ("useBruteforceForSubdomains", "pipeline"),
    ("reconPresetId", "project"),
    ("verifyDomainOwnership", "targeting"),
    ("ownership", "targeting"),
    ("targetGuardrail", "targeting"),
    ("targetDomain", "targeting"),
    ("targetIps", "targeting"),
    ("ipMode", "targeting"),
    ("activation", "project"),
    # single-word prefixes
    ("amass", "amass"),
    ("arjun", "arjun"),
    ("agent", "agent"),
    ("baddns", "baddns"),
    ("censys", "censys"),
    ("crtsh", "crtsh"),
    ("cypherfix", "cypherfix"),
    ("dns", "dns"),
    ("dos", "dos"),
    ("ffuf", "ffuf"),
    ("fireteam", "fireteam"),
    ("fofa", "fofa"),
    ("gau", "gau"),
    ("github", "github"),
    ("graphql", "graphql"),
    ("gvm", "gvm"),
    ("hakrawler", "hakrawler"),
    ("httpx", "httpx"),
    ("hydra", "hydra"),
    ("jsluice", "jsluice"),
    ("katana", "katana"),
    ("kiterunner", "kiterunner"),
    ("masscan", "masscan"),
    ("mitre", "mitre"),
    ("naabu", "naabu"),
    ("netlas", "netlas"),
    ("nmap", "nmap"),
    ("nuclei", "nuclei"),
    ("otx", "otx"),
    ("paramspider", "paramspider"),
    ("phishing", "phishing"),
    ("puredns", "puredns"),
    ("rce", "rce"),
    ("roe", "roe"),
    ("shodan", "shodan"),
    ("sqli", "sqli"),
    ("ssrf", "ssrf"),
    ("subfinder", "subfinder"),
    ("subjack", "subjack"),
    ("takeover", "takeover"),
    ("tlsx", "tlsx"),
    ("trufflehog", "trufflehog"),
    ("uncover", "uncover"),
    ("urlscan", "urlscan"),
    ("wappalyzer", "wappalyzer"),
    ("whois", "whois"),
    ("zap", "zap"),
]

# tool id -> (phase, traffic). `standalone` means "a separate job, not gated by
# scanModules", which is a real distinction the MCP surface already documents.
TOOL_PHASE_TRAFFIC: dict[str, tuple[str, str]] = {
    "agent": ("standalone", "active"),
    "ai_surface_recon": ("http_probe", "active"),
    "amass": ("domain_discovery", "passive"),
    "arjun": ("resource_enum", "active"),
    "auth_profile": ("http_probe", "active"),
    "baddns": ("vuln_scan", "active"),
    "banner_grab": ("port_scan", "active"),
    "capture_proxy": ("standalone", "active"),
    "censys": ("domain_discovery", "passive"),
    "criminalip": ("domain_discovery", "passive"),
    "crtsh": ("domain_discovery", "passive"),
    "cve_lookup": ("vuln_scan", "passive"),
    "cypherfix": ("standalone", "none"),
    "dns": ("domain_discovery", "active"),
    "domain_recon_ai": ("domain_discovery", "none"),
    "domain_discovery": ("domain_discovery", "active"),
    "dos": ("standalone", "active"),
    "ffuf": ("resource_enum", "active"),
    "fireteam": ("standalone", "active"),
    "fofa": ("domain_discovery", "passive"),
    "gau": ("resource_enum", "passive"),
    "github": ("standalone", "passive"),
    "graphql": ("vuln_scan", "active"),
    "graphql_cop": ("vuln_scan", "active"),
    "gvm": ("standalone", "active"),
    "hackertarget": ("domain_discovery", "passive"),
    "hakrawler": ("resource_enum", "active"),
    "http_probe_ai": ("http_probe", "none"),
    "httpx": ("http_probe", "active"),
    "hydra": ("standalone", "active"),
    "js_recon": ("js_recon", "active"),
    "jsluice": ("js_recon", "active"),
    "katana": ("resource_enum", "active"),
    "kiterunner": ("resource_enum", "active"),
    "knockpy": ("domain_discovery", "passive"),
    "masscan": ("port_scan", "active"),
    "mitre": ("vuln_scan", "none"),
    "naabu": ("port_scan", "active"),
    "netlas": ("domain_discovery", "passive"),
    "nmap": ("port_scan", "active"),
    "nuclei": ("vuln_scan", "active"),
    "origin_discovery": ("http_probe", "active"),
    "osint_enrichment": ("domain_discovery", "passive"),
    "otx": ("domain_discovery", "passive"),
    "paramspider": ("resource_enum", "passive"),
    "path_traversal": ("standalone", "active"),
    "phishing": ("standalone", "active"),
    "pipeline": ("standalone", "none"),
    "pipeline_ai": ("standalone", "none"),
    "port_scan_ai": ("port_scan", "none"),
    "project": ("standalone", "none"),
    "puredns": ("domain_discovery", "active"),
    "rce": ("standalone", "active"),
    "resource_enum_ai": ("resource_enum", "none"),
    "roe": ("standalone", "none"),
    "security_check": ("http_probe", "active"),
    "shodan": ("domain_discovery", "passive"),
    "sqli": ("standalone", "active"),
    "ssrf": ("standalone", "active"),
    "subdomain_discovery": ("domain_discovery", "passive"),
    "subfinder": ("domain_discovery", "passive"),
    "subjack": ("vuln_scan", "active"),
    "supply_chain": ("standalone", "passive"),
    "supply_chain_recon": ("standalone", "passive"),
    "takeover": ("vuln_scan", "active"),
    "targeting": ("standalone", "none"),
    "tlsx": ("http_probe", "active"),
    "trufflehog": ("standalone", "passive"),
    "uncover": ("domain_discovery", "passive"),
    "urlscan": ("domain_discovery", "passive"),
    "vhost_sni": ("http_probe", "active"),
    "waf": ("http_probe", "none"),
    "wappalyzer": ("http_probe", "active"),
    "web_cache_poison": ("standalone", "active"),
    "whois": ("domain_discovery", "passive"),
    "zap": ("resource_enum", "active"),
    "zoomeye": ("domain_discovery", "passive"),
}

TOOL_TITLES: dict[str, str] = {
    "ai_surface_recon": "AI attack-surface recon",
    "banner_grab": "Banner grab",
    "capture_proxy": "Capture proxy",
    "criminalip": "CriminalIP",
    "cve_lookup": "CVE lookup",
    "domain_recon_ai": "Domain recon AI hints",
    "graphql_cop": "GraphQL Cop",
    "http_probe_ai": "HTTP probe AI hints",
    "js_recon": "JS recon",
    "origin_discovery": "Origin discovery",
    "osint_enrichment": "OSINT enrichment",
    "path_traversal": "Path traversal",
    "pipeline_ai": "Pipeline AI master switch",
    "port_scan_ai": "Port scan AI catalog",
    "resource_enum_ai": "Resource enum AI hints",
    "roe": "Rules of Engagement",
    "security_check": "Security checks",
    "subdomain_discovery": "Subdomain discovery",
    "supply_chain": "Supply chain scan",
    "supply_chain_recon": "Supply chain recon",
    "vhost_sni": "Vhost / SNI enumeration",
    "web_cache_poison": "Web cache poisoning",
    "zoomeye": "ZoomEye",
}

# --- dispositions ---------------------------------------------------------------

NEVER: dict[str, tuple[str, str]] = {
    # column -> (deny_reason, why)
    "id": ("identity", "row identity"),
    "userId": ("identity", "writing it reassigns the project to another user"),
    "createdById": ("identity", "audit column"),
    "updatedById": ("identity", "audit column"),
    "createdAt": ("identity", "audit column"),
    "updatedAt": ("identity", "audit column"),
    "activationState": ("internal", "version-activation lock flag"),
    "activationStartedAt": ("internal", "version-activation lock flag"),
    "activationVersionId": ("internal", "version-activation lock flag"),
    "reconPresetId": ("internal", "app-written state machine"),
    "mcpKaliExecEnabled": ("escalation", "a token granting itself shell access"),
    "cypherfixGithubToken": ("secret", "a stored credential"),
}

UPLOAD_MANAGED: dict[str, str] = {
    "jsReconUploadedFiles": "/api/js-recon/[projectId]/upload",
    "jsReconCustomPatterns": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomSourcemapPaths": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomPackages": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomEndpointKeywords": "/api/js-recon/[projectId]/custom-files",
    "jsReconCustomFrameworks": "/api/js-recon/[projectId]/custom-files",
    "supplyChainSbomFile": "/api/supply-chain/[projectId]/upload",
}

# Scope and other-target columns: settable once at create_project, immutable
# after. `ownershipToken` / `ownershipTxtPrefix` are the DNS proof of ownership
# for the scope, so they move with it.
CREATE_ONLY = {
    "targetDomain", "subdomainList", "targetIps", "ipMode",
    "domainBatchMode", "domainBatchHosts", "domainBatchGroups",
    "verifyDomainOwnership", "ownershipToken", "ownershipTxtPrefix",
    "targetGuardrailEnabled",
    "githubTargetOrg", "githubTargetRepos", "gvmScanTargets",
    "supplyChainOrgName", "supplyChainRepoRef", "supplyChainRepoScope",
    "supplyChainRepoUrl", "scaIntelCorrelationEnabled",
}

# The RoE block moves in one direction only after creation.
TIGHTEN_DIRECTION: dict[str, str] = {
    "roeEnabled": "false_to_true",
    "roeGlobalMaxRps": "decrease",
}

# Columns holding a filesystem path a scan container opens. The deny class was
# the only control on these; `project_file` replaces it.
PROJECT_FILE_FIELDS = {
    "ffufWordlist",
    "vhostSniCustomWordlist",
    "nucleiCustomTemplates",
    "nucleiSelectedCustomTemplates",
}

HEADER_FIELDS_RE = re.compile(r"(CustomHeaders|^kiterunnerHeaders$|Headers$)")

# A field whose traffic differs from its tool's. gau itself only reads public
# archives, but its verify and method-detect passes dial the target, which is
# what decides whether the engagement ceiling applies.
TRAFFIC_OVERRIDE: dict[str, str] = {
    "gauVerifyRateLimit": "active",
    "gauVerifyThreads": "active",
    "gauVerifyEnabled": "active",
    "gauVerifyTimeout": "active",
    "gauMethodDetectRateLimit": "active",
    "gauMethodDetectThreads": "active",
    "gauMethodDetectEnabled": "active",
    "gauMethodDetectTimeout": "active",
    "paramspiderVerifyEnabled": "active",
}

# Capped by the engagement ceiling although the unit is not rps. hakrawler has
# no rate flag at all, so its thread count IS its throttle, which is why the
# shipped cap list already carries it.
ROE_CAPPED_EXTRA = {"hakrawlerThreads"}

# Where a name-based heuristic gets a field wrong. Each is a fractional
# coefficient whose name reads like a count, or a 0-1 fraction whose name reads
# like a percentage.
UNIT_OVERRIDE: dict[str, str] = {
    "webCachePoisonMinConfidence": "ratio",
}

# Where the extracted bound is wrong rather than merely wide: a UI max that was
# never meant as a semantic bound, or a coefficient whose range a form never
# stated.
BOUNDS_OVERRIDE: dict[str, tuple[float, float]] = {
    "agentLatsPruneFloor": (0.0, 1.0),
    "agentLatsUctC": (0.0, 10.0),
    "graphqlRetryBackoff": (1.0, 60.0),
    "webCachePoisonMinConfidence": (0.0, 1.0),
    "cveLookupMinCvss": (0.0, 10.0),
}

# --- unit inference -------------------------------------------------------------
# T32 asserts these same rules, so the inference and the test agree by
# construction. The heuristic exists because it catches the mistake a human
# actually makes filling 700 rows by hand.
UNIT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(RateLimit|MaxRpsPerHost)$"), "rps"),
    (re.compile(r"^(masscanRate|ffufRate|originDiscoveryRate)$"), "rps"),
    (re.compile(r"Rate$"), "rps"),
    (re.compile(r"(Threads|Concurrency|Workers|Parallelism|Connections|BulkSize|NumberOfBrowsers)$"), "threads"),
    (re.compile(r"(TimeoutMs|DelayMs)$"), "milliseconds"),
    (re.compile(r"^naabuTimeout$"), "milliseconds"),
    (re.compile(r"(Timeout|TimeoutPerReq|ValidationTimeout|ScanTimeout|RunTimeout|MaxTime|MaxDuration|Wait|BehavioralDelay)$"), "seconds"),
    (re.compile(r"(Depth|DepthLimit|RecursionDepth|CrawlDepth)$"), "depth"),
    (re.compile(r"(MaxBytes|MaxLength|MaxSize|FilterSize|SizeTolerance)$"), "bytes"),
    (re.compile(r"MinCvss$"), "ratio"),
    (re.compile(r"(MinConfidence|Threshold)$"), "percent"),
    (re.compile(r"(Max[A-Z]\w*|Retries|MaxRetries|RetryCount|ChunkSize|Budget|Days|Attempts|Calls|Limit)$"), "count"),
    (re.compile(r"(Port|Lport)$"), "port"),
]

# Unit -> a defensible bound when no source carries one. Deliberately wide:
# the bound is a sanity fence, and the engagement ceiling is what actually
# controls a rate. A narrow guess here would refuse a legitimate value.
UNIT_BOUNDS: dict[str, tuple[int, int]] = {
    "rps": (0, 100000),
    "seconds": (1, 86400),
    "minutes": (1, 1440),
    "milliseconds": (1, 3600000),
    "threads": (1, 500),
    "count": (0, 10000000),
    "bytes": (0, 1073741824),
    "depth": (0, 50),
    "percent": (0, 100),
    "ratio": (0, 100),
    "port": (1, 65535),
    "none": (0, 10000000),
}

# Runtime keys that exist in DEFAULT_SETTINGS with NO Prisma column. They are
# not MCP-reachable, but the derived cap list is queried over the registry, so a
# rate that lives only here still has to be in it. `VIRUSTOTAL_RATE_LIMIT` and
# `ORIGIN_DISCOVERY_RATE` are exactly that case.
RUNTIME_ONLY: dict[str, dict] = {
    "PROJECT_ID": {
        "source": "internal", "unit": "none", "roe_capped": False,
        "meaning": "The project whose settings were loaded. Written by the loader, never configured.",
    },
    "ORIGIN_DISCOVERY_RATE": {
        "source": "internal", "tool": "origin_discovery", "unit": "rps", "roe_capped": True,
        "zero_means": "unlimited",
        "meaning": (
            "Requests per second the origin-IP discovery active probe sends. ZERO MEANS "
            "UNLIMITED, so 0 is the most aggressive value available and not the safest. "
            "No Prisma column: it is internal to the pipeline, tuned by the stealth pass "
            "and capped by the engagement ceiling."
        ),
    },
    "VIRUSTOTAL_RATE_LIMIT": {
        "source": "internal", "tool": "virustotal", "unit": "rps", "roe_capped": True,
        "meaning": (
            "Requests per second sent to the VirusTotal API. Aimed at VirusTotal rather "
            "than the engagement target, but still capped by the ceiling because a shared "
            "ceiling that some callers ignore is not a ceiling."
        ),
    },
    "VIRUSTOTAL_MAX_TARGETS": {
        "source": "internal", "tool": "virustotal", "unit": "count", "roe_capped": False,
        "meaning": "Maximum hosts submitted to the VirusTotal API in one pass. No Prisma column.",
    },
    "NETLAS_MAX_RESULTS": {
        "source": "internal", "tool": "netlas", "unit": "count", "roe_capped": False,
        "meaning": "Maximum results pulled from the Netlas API. No Prisma column; the memory governor still budgets it.",
    },
    "TAKEOVER_CNAME_VALIDATION_ENABLED": {
        "source": "internal", "tool": "takeover", "unit": "none", "roe_capped": False,
        "meaning": "Whether a takeover candidate's CNAME is re-resolved before it is reported. No Prisma column.",
    },
    "SUPPLY_CHAIN_IMPORT_MAX_FILES": {
        "source": "env", "tool": "supply_chain", "unit": "count", "roe_capped": False,
        "meaning": "Maximum files the import miner reads. Read from the environment, not from the project row.",
    },
    "SUPPLY_CHAIN_IMPORT_MAX_BYTES": {
        "source": "env", "tool": "supply_chain", "unit": "bytes", "roe_capped": False,
        "meaning": "Byte budget for the import miner. Read from the environment, not from the project row.",
    },
}

# Every API key: the user's own account credential, fetched per scan and never a
# project column. Listed so that "a runtime key with no registry entry" stays a
# build failure rather than a class of exceptions.
for _key, _tool in [
    ("SHODAN_API_KEY", "shodan"), ("URLSCAN_API_KEY", "urlscan"), ("NVD_API_KEY", "cve_lookup"),
    ("VULNERS_API_KEY", "cve_lookup"), ("CENSYS_API_TOKEN", "censys"), ("CENSYS_ORG_ID", "censys"),
    ("FOFA_API_KEY", "fofa"), ("OTX_API_KEY", "otx"), ("NETLAS_API_KEY", "netlas"),
    ("VIRUSTOTAL_API_KEY", "virustotal"), ("ZOOMEYE_API_KEY", "zoomeye"),
    ("CRIMINALIP_API_KEY", "criminalip"), ("SECURITYTRAILS_API_KEY", "osint_enrichment"),
    ("VIEWDNS_API_KEY", "osint_enrichment"), ("UNCOVER_QUAKE_API_KEY", "uncover"),
    ("UNCOVER_HUNTER_API_KEY", "uncover"), ("UNCOVER_PUBLICWWW_API_KEY", "uncover"),
    ("UNCOVER_HUNTERHOW_API_KEY", "uncover"), ("UNCOVER_GOOGLE_API_KEY", "uncover"),
    ("UNCOVER_GOOGLE_API_CX", "uncover"), ("UNCOVER_ONYPHE_API_KEY", "uncover"),
    ("UNCOVER_DRIFTNET_API_KEY", "uncover"),
]:
    RUNTIME_ONLY[_key] = {
        "source": "user_account", "tool": _tool, "unit": "none", "roe_capped": False,
        "secret": True,
        "meaning": (
            "The user's own API credential for this data source, fetched per scan from the "
            "user account. Never a project column, so it is not reachable from any "
            "project-scoped surface."
        ),
    }

SEVERITY_VALUES = ["info", "low", "medium", "high", "critical", "unknown"]
SCAN_MODULE_VALUES = [
    "domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon",
]


def tool_for(column: str) -> str:
    best = ""
    best_tool = "project"
    for prefix, tool in TOOL_PREFIXES:
        if column.startswith(prefix) and len(prefix) > len(best):
            best, best_tool = prefix, tool
    return best_tool


def unit_for(column: str, col: Column) -> str:
    if col.kind in ("boolean", "json", "datetime", "string", "string-list", "number-list"):
        return "none"
    for pattern, unit in UNIT_RULES:
        if pattern.search(column):
            return unit
    # A Float that no rule claimed is a coefficient, not a countable quantity.
    # `count` on a fractional value is the mistake this catches.
    return "ratio" if col.kind == "float" else "count"


# --- source parsers ---------------------------------------------------------------

def parse_allowlist() -> tuple[dict[str, dict], dict[str, str]]:
    text = ALLOWLIST_TS.read_text(encoding="utf-8")
    allow: dict[str, dict] = {}
    allow_block = text[text.index("RECON_SETTINGS_ALLOWLIST"): text.index("RECON_SETTINGS_DENYLIST")]
    for m in re.finditer(r"^\s+([A-Za-z0-9_]+): \{ kind: '([a-z-]+)'(?:, min: (-?\d+), max: (-?\d+))? \},", allow_block, re.M):
        key, kind, mn, mx = m.groups()
        entry: dict = {"kind": kind}
        if mn is not None:
            entry["min"] = int(mn)
            entry["max"] = int(mx)
        allow[key] = entry
    deny_block = text[text.index("RECON_SETTINGS_DENYLIST"):]
    deny = {m.group(1): m.group(2) for m in re.finditer(r"^\s+([A-Za-z0-9_]+): '([a-z-]+)',", deny_block, re.M)}
    return allow, deny


def parse_catalog() -> dict[str, str]:
    """key -> prose meaning, from RECON_PARAMETER_CATALOG."""
    text = PRESET_SCHEMA_TS.read_text(encoding="utf-8")
    start = text.index("RECON_PARAMETER_CATALOG = `")
    body = text[start + len("RECON_PARAMETER_CATALOG = `"):]
    body = body[: body.index("`\n")]
    out: dict[str, str] = {}
    for raw in body.splitlines():
        line = raw.strip()
        m = re.match(r"^-\s+([A-Za-z0-9_]+):\s*[^-]*?(?:\s+-\s+(.*))?$", line)
        if m and m.group(2):
            out[m.group(1)] = m.group(2).strip()
    return out


def parse_form_sections() -> tuple[dict[str, dict], dict[str, str]]:
    """key -> {min,max}, and key -> operator hint, from the ProjectForm sections."""
    bounds: dict[str, dict] = {}
    hints: dict[str, str] = {}
    section_of: dict[str, str] = {}
    for path in sorted(SECTIONS_DIR.glob("*.tsx")):
        if path.name.endswith(".test.tsx"):
            continue
        text = path.read_text(encoding="utf-8")
        hits = list(re.finditer(r"updateField\(\s*'([A-Za-z0-9_]+)'", text))
        for i, m in enumerate(hits):
            key = m.group(1)
            end = hits[i + 1].start() if i + 1 < len(hits) else min(len(text), m.end() + 1200)
            chunk = text[m.end(): end]
            mn = re.search(r"\bmin=\{(-?\d+)\}", chunk)
            mx = re.search(r"\bmax=\{(-?\d+)\}", chunk)
            if mn or mx:
                cur = bounds.setdefault(key, {})
                if mn and "min" not in cur:
                    cur["min"] = int(mn.group(1))
                if mx and "max" not in cur:
                    cur["max"] = int(mx.group(1))
            hint = re.search(r"fieldHint\}>([^<{]{6,400})<", chunk)
            if hint and key not in hints:
                hints[key] = " ".join(hint.group(1).split())
            section_of.setdefault(key, path.stem)
    return bounds, hints


def runtime_keys() -> dict[str, tuple[str, str, str | None]]:
    """column -> (runtime_key, fallback, coerce)."""
    out: dict[str, tuple[str, str, str | None]] = {}
    for key, mapping in parse_mappings(RECON_SETTINGS_PY).items():
        out[mapping.column] = (key, mapping.fallback, mapping.coerce)
    # Multi-line mappings the line parser cannot see, recorded by hand so the
    # registry is not silently missing a runtime key that exists.
    out.setdefault("subdomainList", ("SUBDOMAIN_LIST", "missing", "strip_list"))
    out.setdefault("targetIps", ("TARGET_IPS", "missing", "strip_list"))
    out.setdefault("domainBatchMode", ("DOMAIN_BATCH_MODE", "missing", None))
    out.setdefault("domainBatchGroups", ("DOMAIN_BATCH_GROUPS", "missing", None))
    out.setdefault("jsluiceVerifyAcceptStatus", ("JSLUICE_VERIFY_ACCEPT_STATUS", "falsy", None))
    out.setdefault("jsluiceExcludePatterns", ("JSLUICE_EXCLUDE_PATTERNS", "falsy", None))
    return out


# --- emit --------------------------------------------------------------------------

def yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v))


def yaml_block(text: str, indent: str) -> str:
    """A folded scalar, wrapped, for the prose fields."""
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > 76:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    body = "\n".join(f"{indent}  {line}" for line in lines)
    return f">-\n{body}"


def build() -> str:
    columns = project_columns()
    allow, deny = parse_allowlist()
    catalog = parse_catalog()
    form_bounds, form_hints = parse_form_sections()
    rkeys = runtime_keys()

    fields: dict[str, dict] = {}
    for name in sorted(columns):
        col = columns[name]
        tool = tool_for(name)
        phase, traffic = TOOL_PHASE_TRAFFIC.get(tool, ("standalone", "none"))
        traffic = TRAFFIC_OVERRIDE.get(name, traffic)
        unit = UNIT_OVERRIDE.get(name) or unit_for(name, col)

        entry: dict = {
            "tool": tool,
            "runtime_key": rkeys.get(name, (None, "missing", None))[0],
            "unit": unit,
            "phase": phase,
            "traffic": traffic,
            "roe_capped": (unit == "rps" and traffic == "active") or name in ROE_CAPPED_EXTRA,
            "mcp": "settable",
        }

        fallback = rkeys.get(name, (None, "missing", None))[1]
        coerce = rkeys.get(name, (None, "missing", None))[2]
        if fallback == "falsy":
            entry["fallback"] = "falsy"
        if coerce:
            entry["coerce"] = coerce

        # disposition
        if name in NEVER:
            entry["mcp"] = "never"
            entry["deny_reason"] = NEVER[name][0]
        elif name in UPLOAD_MANAGED:
            entry["mcp"] = "never"
            entry["deny_reason"] = "upload-managed"
            entry["written_by"] = UPLOAD_MANAGED[name]
        elif name in CREATE_ONLY:
            entry["mcp"] = "create_only"
        elif name.startswith("roe"):
            entry["mcp"] = "tighten_only"
            if name in TIGHTEN_DIRECTION:
                entry["tighten"] = TIGHTEN_DIRECTION[name]
            elif col.kind == "string-list":
                entry["tighten"] = "superset"
            elif col.kind == "boolean":
                entry["tighten"] = "true_to_false"
            elif col.kind in ("int", "float"):
                entry["tighten"] = "decrease"
            else:
                entry["tighten"] = "narrow"

        # bounds / values / validator
        if col.kind in ("int", "float"):
            src = allow.get(name, {})
            b = {}
            if "min" in src:
                b = {"min": src["min"], "max": src["max"]}
            elif name in form_bounds and "min" in form_bounds[name] and "max" in form_bounds[name]:
                b = dict(form_bounds[name])
            else:
                lo, hi = UNIT_BOUNDS.get(unit, UNIT_BOUNDS["count"])
                fb = form_bounds.get(name, {})
                b = {"min": fb.get("min", lo), "max": fb.get("max", hi)}
            dv = col.default_value
            if isinstance(dv, (int, float)) and not isinstance(dv, bool):
                b["min"] = min(b["min"], dv)
                b["max"] = max(b["max"], dv)
            if name in BOUNDS_OVERRIDE:
                lo, hi = BOUNDS_OVERRIDE[name]
                b = {"min": lo, "max": hi}
            entry["bounds"] = b
            if dv == 0:
                entry["zero_means"] = "unlimited" if unit == "rps" else "literal"
        elif col.kind == "boolean":
            pass
        elif name in PROJECT_FILE_FIELDS:
            entry["validator"] = "project_file"
        elif name.endswith("DockerImage"):
            entry["validator"] = "docker_image"
        elif HEADER_FIELDS_RE.search(name):
            entry["validator"] = "http_header"
        elif name == "scanModules":
            entry["values"] = list(SCAN_MODULE_VALUES)
            entry["validator"] = "scan_modules"
        elif re.search(r"(Severity|Severities)$", name):
            entry["values"] = list(SEVERITY_VALUES)
            entry["validator"] = "severity"
        elif re.search(r"(StatusCodes?|MatchCodes|FilterCodes|AcceptStatus)$", name):
            entry["validator"] = "status_codes"
        elif col.kind == "json":
            entry["validator"] = "json_object"
        else:
            entry["validator"] = "free_text"

        # An authored description always wins: the catalog and the UI hints are
        # written for a different reader, and several are a label rather than a
        # sentence ("Seconds", "Enable OTX"). Nothing about a field that would
        # surprise a reader may come from a template.
        title = TOOL_TITLES.get(tool, tool.replace("_", " "))
        meaning = authored_meaning(name, title, unit)
        if not meaning:
            meaning = catalog.get(name) or form_hints.get(name) or col.doc
        if not meaning or len(meaning.strip()) < 20:
            longer = catalog.get(name) or form_hints.get(name) or col.doc or ""
            meaning = longer if len(longer.strip()) >= 20 else (meaning or "")
        if not meaning:
            meaning = f"TODO: describe {name}."
        entry["meaning"] = meaning
        if name in deny:
            entry["group"] = deny[name]
        fields[name] = entry

    used_tools = sorted({f["tool"] for f in fields.values()})
    tools: dict[str, dict] = {}
    for tool in used_tools:
        phase, traffic = TOOL_PHASE_TRAFFIC.get(tool, ("standalone", "none"))
        tools[tool] = {
            "title": TOOL_TITLES.get(tool, tool.replace("_", " ").title()),
            "phase": phase,
            "traffic": traffic,
        }

    out: list[str] = []
    out.append("# RedAmon recon settings registry.")
    out.append("#")
    out.append("# The one hand-maintained description of every recon parameter. See README.md")
    out.append("# beside this file for what belongs here and what stays in Prisma.")
    out.append("#")
    out.append("# `type` and `default` are DELIBERATELY absent: Prisma owns them and the build")
    out.append("# joins them, so a value that already has two definitions never gains a third.")
    out.append("version: 1")
    out.append("")
    out.append("tools:")
    for tool in sorted(tools):
        t = tools[tool]
        out.append(f"  {tool}:")
        out.append(f"    title: {yaml_scalar(t['title'])}")
        out.append(f"    phase: {t['phase']}")
        out.append(f"    traffic: {t['traffic']}")
    out.append("")
    out.append("fields:")
    for name in sorted(fields):
        f = fields[name]
        out.append(f"  {name}:")
        for key in ("tool", "runtime_key", "unit", "phase", "traffic", "roe_capped", "mcp"):
            out.append(f"    {key}: {yaml_scalar(f[key]) if f[key] is not None else 'null'}")
        if "bounds" in f:
            out.append(f"    bounds: {{ min: {f['bounds']['min']}, max: {f['bounds']['max']} }}")
        if "values" in f:
            out.append(f"    values: [{', '.join(yaml_scalar(v) for v in f['values'])}]")
        for key in ("validator", "zero_means", "fallback", "coerce", "tighten", "deny_reason", "written_by", "group"):
            if key in f:
                out.append(f"    {key}: {yaml_scalar(f[key])}")
        out.append(f"    meaning: {yaml_block(f['meaning'], '    ')}")
    out.append("")
    out.append("# Runtime keys with no Prisma column. Not MCP-reachable, but the derived")
    out.append("# cap list is a query over this file, so a rate that lives only here is in it.")
    out.append("runtime_only:")
    for key in sorted(RUNTIME_ONLY):
        r = RUNTIME_ONLY[key]
        out.append(f"  {key}:")
        out.append(f"    source: {r['source']}")
        if "tool" in r:
            out.append(f"    tool: {r['tool']}")
        out.append(f"    unit: {r['unit']}")
        out.append(f"    roe_capped: {yaml_scalar(r['roe_capped'])}")
        if "zero_means" in r:
            out.append(f"    zero_means: {r['zero_means']}")
        if r.get("secret"):
            out.append("    secret: true")
        out.append(f"    meaning: {yaml_block(r['meaning'], '    ')}")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    text = build()
    OUT_YAML.write_text(text, encoding="utf-8")
    todo = text.count("TODO: describe")
    print(f"wrote {OUT_YAML.relative_to(REPO_ROOT)}  ({len(text.splitlines())} lines, {todo} meanings still TODO)")
