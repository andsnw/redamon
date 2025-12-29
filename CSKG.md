# Cybersecurity Knowledge Graph (CSKG) Documentation

## Overview

The CSKG is the **Global Memory and Reasoning Engine** for the AI-driven penetration testing system. It enables agents to visualize attack paths, track discovered assets, correlate vulnerabilities, and reason about lateral movement opportunities.

---

!!! cambiare i nodi e gli schemi in recon in base ai json finali dei tools utilizzati!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      CSKG Architecture                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Neo4j     │◄───│   Graph     │◄───│  Tool Outputs       │  │
│  │   (Graph)   │    │   Manager   │    │  (Nmap, Nuclei...)  │  │
│  └──────┬──────┘    └─────────────┘    └─────────────────────┘  │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ PostgreSQL  │    │  AI Query   │    │  Visualization      │  │
│  │ (Raw Logs)  │    │  Interface  │    │  (Sigma.js/Bloom)   │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Database Stack
- **Neo4j**: Primary graph database for nodes, relationships, and attack path queries
- **PostgreSQL**: Raw tool outputs, HTTP request/response logs, binary evidence

---

## 2. Complete Node Ontology

### Layer A: Infrastructure Layer

#### Node: `Asset`
The root entity representing a target system or domain.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier (UUID) |
| `name` | String | ✓ | Human-readable name |
| `asset_type` | Enum | ✓ | `domain`, `subdomain`, `server`, `network_range` |
| `criticality` | Integer | ✓ | Business impact score (1-10) |
| `environment` | Enum | ✓ | `production`, `staging`, `development`, `unknown` |
| `discovery_source` | String | ✓ | Tool that discovered it |
| `discovery_timestamp` | DateTime | ✓ | When discovered |
| `in_scope` | Boolean | ✓ | Within Rules of Engagement |
| `notes` | String | | Agent observations |

```cypher
CREATE (a:Asset {
  uid: randomUUID(),
  name: "api.target.com",
  asset_type: "subdomain",
  criticality: 8,
  environment: "production",
  discovery_source: "user_input",
  discovery_timestamp: datetime(),
  in_scope: true
})
```

#### Node: `IPAddress`
Network address associated with assets.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `address` | String | ✓ | IPv4 or IPv6 address |
| `version` | Enum | ✓ | `ipv4`, `ipv6` |
| `is_public` | Boolean | ✓ | Public vs private range |
| `isp` | String | | Internet Service Provider |
| `asn` | String | | Autonomous System Number |
| `geo_country` | String | | Country code |
| `geo_city` | String | | City name |
| `reverse_dns` | String | | PTR record |
| `last_seen` | DateTime | ✓ | Last confirmation |

```cypher
CREATE (ip:IPAddress {
  uid: randomUUID(),
  address: "203.0.113.50",
  version: "ipv4",
  is_public: true,
  asn: "AS12345",
  geo_country: "US",
  last_seen: datetime()
})
```

#### Node: `Port`
Network ports discovered on IP addresses.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `port_number` | Integer | ✓ | Port number (0-65535) |
| `protocol` | Enum | ✓ | `tcp`, `udp`, `sctp` |
| `state` | Enum | ✓ | `open`, `closed`, `filtered`, `open|filtered` |
| `state_reason` | String | | Why this state (e.g., `syn-ack`) |
| `discovery_method` | String | ✓ | Scan type used |
| `last_scanned` | DateTime | ✓ | Last scan timestamp |

```cypher
CREATE (p:Port {
  uid: randomUUID(),
  port_number: 443,
  protocol: "tcp",
  state: "open",
  state_reason: "syn-ack",
  discovery_method: "nmap_syn_scan",
  last_scanned: datetime()
})
```

#### Node: `Service`
Software running on a port.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `service_name` | String | ✓ | Service type (http, ssh, mysql) |
| `product_name` | String | | Software name (nginx, openssh) |
| `version` | String | | Version string |
| `version_confidence` | Integer | | Confidence 1-10 |
| `vendor` | String | | Software vendor |
| `cpe_id` | String | | CPE identifier for NVD lookup |
| `extra_info` | String | | Additional fingerprint data |
| `banner` | String | | Raw banner grab |
| `is_ssl` | Boolean | | SSL/TLS enabled |
| `ssl_cert_cn` | String | | Certificate Common Name |
| `ssl_cert_issuer` | String | | Certificate issuer |
| `ssl_cert_expiry` | DateTime | | Certificate expiration |

```cypher
CREATE (s:Service {
  uid: randomUUID(),
  service_name: "http",
  product_name: "nginx",
  version: "1.22.1",
  vendor: "NGINX Inc",
  cpe_id: "cpe:2.3:a:nginx:nginx:1.22.1:*:*:*:*:*:*:*",
  is_ssl: true,
  ssl_cert_cn: "*.target.com"
})
```

#### Node: `OperatingSystem`
Host operating system information.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `family` | Enum | ✓ | `linux`, `windows`, `macos`, `bsd`, `unknown` |
| `distribution` | String | | Distro (Ubuntu, CentOS) |
| `version` | String | | Version string |
| `build` | String | | Build number |
| `kernel_version` | String | | Kernel version |
| `architecture` | Enum | | `x86`, `x64`, `arm`, `arm64` |
| `detection_confidence` | Integer | ✓ | Confidence score 1-10 |

```cypher
CREATE (os:OperatingSystem {
  uid: randomUUID(),
  family: "linux",
  distribution: "Ubuntu",
  version: "22.04",
  kernel_version: "5.15.0",
  architecture: "x64",
  detection_confidence: 9
})
```

### Layer B: Application Layer

#### Node: `WebApplication`
Web application discovered on a service.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `root_url` | String | ✓ | Base URL |
| `title` | String | | Page title |
| `status_code` | Integer | ✓ | HTTP response code |
| `content_length` | Integer | | Response size |
| `content_type` | String | | MIME type |
| `has_waf` | Boolean | ✓ | WAF detected |
| `waf_vendor` | String | | WAF product name |
| `technologies` | List | | Detected tech stack |
| `crawl_depth` | Integer | | Spider depth reached |
| `last_crawled` | DateTime | | Last spider run |

```cypher
CREATE (wa:WebApplication {
  uid: randomUUID(),
  root_url: "https://api.target.com",
  title: "API Documentation",
  status_code: 200,
  has_waf: true,
  waf_vendor: "Cloudflare",
  technologies: ["Node.js", "Express", "React"],
  last_crawled: datetime()
})
```

#### Node: `Endpoint`
Specific URL path/route in a web application.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `full_url` | String | ✓ | Complete URL |
| `path` | String | ✓ | URL path only |
| `method` | Enum | ✓ | HTTP method |
| `status_code` | Integer | | Response code |
| `content_type` | String | | Response MIME |
| `auth_required` | Boolean | ✓ | Requires authentication |
| `auth_type` | Enum | | `bearer`, `cookie`, `basic`, `api_key` |
| `is_api` | Boolean | ✓ | API endpoint vs page |
| `is_file_upload` | Boolean | | Accepts file uploads |
| `response_time_ms` | Integer | | Baseline response time |
| `word_count` | Integer | | Response word count |
| `line_count` | Integer | | Response line count |
| `fuzz_state` | Enum | ✓ | `pending`, `in_progress`, `complete` |

```cypher
CREATE (e:Endpoint {
  uid: randomUUID(),
  full_url: "https://api.target.com/v1/users",
  path: "/v1/users",
  method: "GET",
  status_code: 200,
  auth_required: true,
  auth_type: "bearer",
  is_api: true,
  response_time_ms: 45,
  fuzz_state: "pending"
})
```

#### Node: `Parameter`
Input parameter on an endpoint.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `name` | String | ✓ | Parameter name |
| `location` | Enum | ✓ | `query`, `body`, `path`, `header`, `cookie` |
| `data_type` | Enum | ✓ | `string`, `integer`, `boolean`, `array`, `object` |
| `is_required` | Boolean | | Required parameter |
| `is_pii` | Boolean | ✓ | Contains PII |
| `sample_value` | String | | Example value observed |
| `reflection_detected` | Boolean | ✓ | Value reflected in response |
| `fuzz_count` | Integer | ✓ | Times fuzzed |
| `interesting_score` | Integer | ✓ | AI interest score 1-10 |

```cypher
CREATE (p:Parameter {
  uid: randomUUID(),
  name: "user_id",
  location: "path",
  data_type: "integer",
  is_pii: true,
  sample_value: "12345",
  reflection_detected: false,
  fuzz_count: 0,
  interesting_score: 7
})
```

#### Node: `Technology`
Software component/framework detected.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `name` | String | ✓ | Technology name |
| `category` | Enum | ✓ | `framework`, `language`, `library`, `server`, `cms`, `cdn` |
| `version` | String | | Version if detected |
| `cpe_id` | String | | CPE for NVD lookup |
| `detection_method` | String | ✓ | How detected |
| `confidence` | Integer | ✓ | Detection confidence 1-10 |

```cypher
CREATE (t:Technology {
  uid: randomUUID(),
  name: "Express.js",
  category: "framework",
  version: "4.18.2",
  detection_method: "wappalyzer",
  confidence: 9
})
```

#### Node: `Identity`
User account, role, or principal.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `identity_type` | Enum | ✓ | `user`, `service_account`, `role`, `group` |
| `username` | String | | Username |
| `email` | String | | Email address |
| `role` | String | | Role/privilege level |
| `is_admin` | Boolean | ✓ | Administrative privileges |
| `source` | String | ✓ | How obtained |
| `credential_type` | Enum | | `password`, `hash`, `token`, `key` |
| `credential_value` | String | | Obfuscated credential |
| `is_valid` | Boolean | ✓ | Credential validity tested |

```cypher
CREATE (i:Identity {
  uid: randomUUID(),
  identity_type: "user",
  username: "admin",
  role: "administrator",
  is_admin: true,
  source: "sqli_extraction",
  credential_type: "hash",
  is_valid: false
})
```

#### Node: `Session`
Authentication session/token.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `token_type` | Enum | ✓ | `jwt`, `cookie`, `bearer`, `api_key` |
| `token_value` | String | ✓ | Token (encrypted at rest) |
| `claims` | JSON | | Decoded JWT claims |
| `issued_at` | DateTime | | Token issue time |
| `expires_at` | DateTime | | Token expiration |
| `is_valid` | Boolean | ✓ | Currently valid |
| `scope` | List | | Token permissions |
| `extraction_method` | String | ✓ | How obtained |

```cypher
CREATE (s:Session {
  uid: randomUUID(),
  token_type: "jwt",
  token_value: "eyJhbG...[ENCRYPTED]",
  claims: {sub: "admin", role: "admin"},
  is_valid: true,
  extraction_method: "sqli_data_exfil"
})
```

### Layer C: Threat Intelligence Layer

#### Node: `Vulnerability`
Specific vulnerability instance.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `cve_id` | String | | CVE identifier |
| `title` | String | ✓ | Vulnerability name |
| `description` | String | | Full description |
| `cvss_v3_score` | Float | | CVSS 3.x score |
| `cvss_v3_vector` | String | | CVSS vector string |
| `epss_score` | Float | | Exploit prediction score |
| `severity` | Enum | ✓ | `critical`, `high`, `medium`, `low`, `info` |
| `vuln_type` | String | ✓ | Type (sqli, xss, rce, etc.) |
| `status` | Enum | ✓ | `potential`, `validated`, `exploited`, `false_positive` |
| `confidence` | Integer | ✓ | Detection confidence 1-10 |
| `discovery_tool` | String | ✓ | Tool that found it |
| `discovery_timestamp` | DateTime | ✓ | When discovered |
| `validation_timestamp` | DateTime | | When validated |
| `patch_available` | Boolean | | Patch exists |
| `exploit_available` | Boolean | | Public exploit exists |
| `evidence_id` | String | | Link to PostgreSQL evidence |

```cypher
CREATE (v:Vulnerability {
  uid: randomUUID(),
  cve_id: null,
  title: "SQL Injection in user_id parameter",
  cvss_v3_score: 9.8,
  severity: "critical",
  vuln_type: "sqli",
  status: "validated",
  confidence: 9,
  discovery_tool: "sqlmap",
  discovery_timestamp: datetime(),
  validation_timestamp: datetime()
})
```

#### Node: `Weakness`
CWE weakness category.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `cwe_id` | String | ✓ | CWE identifier |
| `name` | String | ✓ | Weakness name |
| `description` | String | | Full description |
| `abstraction` | Enum | ✓ | `pillar`, `class`, `base`, `variant` |
| `parent_cwe` | String | | Parent CWE ID |
| `likelihood` | Enum | | `high`, `medium`, `low` |
| `impact` | Enum | | `high`, `medium`, `low` |

```cypher
CREATE (w:Weakness {
  uid: randomUUID(),
  cwe_id: "CWE-89",
  name: "SQL Injection",
  abstraction: "base",
  parent_cwe: "CWE-943",
  likelihood: "high",
  impact: "high"
})
```

#### Node: `Technique`
MITRE ATT&CK technique.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `mitre_id` | String | ✓ | MITRE ID (T1059) |
| `name` | String | ✓ | Technique name |
| `tactic` | Enum | ✓ | ATT&CK tactic |
| `description` | String | | Full description |
| `platforms` | List | ✓ | Applicable platforms |
| `data_sources` | List | | Detection sources |
| `is_subtechnique` | Boolean | ✓ | Sub-technique flag |
| `parent_technique` | String | | Parent technique ID |

**Tactic Values**: `reconnaissance`, `resource_development`, `initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`

```cypher
CREATE (t:Technique {
  uid: randomUUID(),
  mitre_id: "T1190",
  name: "Exploit Public-Facing Application",
  tactic: "initial_access",
  platforms: ["Linux", "Windows", "macOS"],
  is_subtechnique: false
})
```

#### Node: `Payload`
Attack payload used.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `name` | String | ✓ | Payload identifier |
| `payload_type` | Enum | ✓ | `detection`, `exploitation`, `exfiltration` |
| `content` | String | ✓ | Payload content |
| `content_hash` | String | ✓ | SHA256 hash |
| `encoding` | List | | Encodings applied |
| `obfuscation` | String | | Obfuscation technique |
| `is_safe` | Boolean | ✓ | Non-destructive |
| `success_count` | Integer | ✓ | Times succeeded |
| `failure_count` | Integer | ✓ | Times failed |
| `target_vuln_type` | String | ✓ | Target vulnerability type |

```cypher
CREATE (p:Payload {
  uid: randomUUID(),
  name: "sqli_time_based_sleep",
  payload_type: "detection",
  content: "1' AND SLEEP(5)--",
  content_hash: "abc123...",
  is_safe: true,
  success_count: 1,
  failure_count: 0,
  target_vuln_type: "sqli"
})
```

### Layer D: Engagement Layer

#### Node: `Engagement`
Root node for a pentest engagement.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `name` | String | ✓ | Engagement name |
| `client` | String | | Client organization |
| `start_date` | DateTime | ✓ | Engagement start |
| `end_date` | DateTime | | Engagement end |
| `status` | Enum | ✓ | `active`, `paused`, `completed` |
| `scope_type` | Enum | ✓ | `whitebox`, `greybox`, `blackbox` |
| `success_metric` | String | ✓ | Goal definition |

```cypher
CREATE (e:Engagement {
  uid: randomUUID(),
  name: "Target Corp Q4 2024",
  start_date: datetime(),
  status: "active",
  scope_type: "blackbox",
  success_metric: "Extract database schema"
})
```

#### Node: `RulesOfEngagement`
Constraints and permissions.

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `uid` | String | ✓ | Unique identifier |
| `scope_includes` | List | ✓ | In-scope targets |
| `scope_excludes` | List | ✓ | Excluded targets |
| `allowed_techniques` | List | | Permitted attack types |
| `forbidden_techniques` | List | | Prohibited attacks |
| `testing_hours` | String | | Allowed hours |
| `max_requests_per_second` | Integer | | Rate limiting |
| `notify_on_critical` | Boolean | ✓ | Alert on critical finds |
| `allow_social_engineering` | Boolean | ✓ | SE permitted |
| `allow_physical` | Boolean | ✓ | Physical access tests |
| `allow_dos` | Boolean | ✓ | DoS testing allowed |

```cypher
CREATE (roe:RulesOfEngagement {
  uid: randomUUID(),
  scope_includes: ["*.target.com", "192.168.1.0/24"],
  scope_excludes: ["payments.target.com"],
  forbidden_techniques: ["dos", "social_engineering"],
  max_requests_per_second: 100,
  notify_on_critical: true,
  allow_dos: false
})
```

---

## 3. Complete Relationship Schema

### Infrastructure Relationships

| Relationship | Source | Target | Properties |
|--------------|--------|--------|------------|
| `RESOLVES_TO` | Asset | IPAddress | `resolution_type`, `ttl`, `timestamp` |
| `LISTENS_ON` | IPAddress | Port | `first_seen`, `last_seen` |
| `RUNS_SERVICE` | Port | Service | `detection_method`, `confidence` |
| `HAS_OS` | IPAddress | OperatingSystem | `detection_method`, `confidence` |
| `HOSTS` | Service | WebApplication | `vhost`, `discovered_via` |
| `BELONGS_TO` | Asset | Engagement | `added_timestamp` |
| `GOVERNED_BY` | Engagement | RulesOfEngagement | `version` |

```cypher
// Asset resolves to IP
MATCH (a:Asset {name: "api.target.com"})
MATCH (ip:IPAddress {address: "203.0.113.50"})
CREATE (a)-[:RESOLVES_TO {
  resolution_type: "A",
  ttl: 300,
  timestamp: datetime()
}]->(ip)

// IP listens on Port
MATCH (ip:IPAddress {address: "203.0.113.50"})
MATCH (p:Port {port_number: 443})
CREATE (ip)-[:LISTENS_ON {
  first_seen: datetime(),
  last_seen: datetime()
}]->(p)

// Port runs Service
MATCH (p:Port {port_number: 443})
MATCH (s:Service {product_name: "nginx"})
CREATE (p)-[:RUNS_SERVICE {
  detection_method: "nmap_service_scan",
  confidence: 9
}]->(s)
```

### Application Relationships

| Relationship | Source | Target | Properties |
|--------------|--------|--------|------------|
| `HAS_ENDPOINT` | WebApplication | Endpoint | `discovery_method`, `depth` |
| `HAS_PARAMETER` | Endpoint | Parameter | `discovery_method` |
| `USES_TECHNOLOGY` | WebApplication | Technology | `detection_method`, `confidence` |
| `USES_LIBRARY` | Service | Technology | `detection_method` |
| `LINKS_TO` | Endpoint | Endpoint | `link_type`, `anchor_text` |
| `REDIRECTS_TO` | Endpoint | Endpoint | `status_code`, `redirect_type` |
| `REQUIRES_AUTH` | Endpoint | Identity | `auth_type` |
| `HAS_SESSION` | Identity | Session | `created_at`, `source` |
| `CAN_ACCESS` | Identity | Endpoint | `permission_level` |
| `CAN_ACCESS` | Session | Endpoint | `verified` |

```cypher
// WebApp has Endpoint
MATCH (wa:WebApplication {root_url: "https://api.target.com"})
MATCH (e:Endpoint {path: "/v1/users"})
CREATE (wa)-[:HAS_ENDPOINT {
  discovery_method: "katana_spider",
  depth: 2
}]->(e)

// Endpoint has Parameter
MATCH (e:Endpoint {path: "/v1/users"})
MATCH (p:Parameter {name: "user_id"})
CREATE (e)-[:HAS_PARAMETER {
  discovery_method: "response_analysis"
}]->(p)

// Identity can access Endpoint
MATCH (i:Identity {username: "admin"})
MATCH (e:Endpoint {path: "/admin/backups"})
CREATE (i)-[:CAN_ACCESS {
  permission_level: "full"
}]->(e)
```

### Threat Intelligence Relationships

| Relationship | Source | Target | Properties |
|--------------|--------|--------|------------|
| `AFFECTED_BY` | Service | Vulnerability | `match_type`, `cpe_match` |
| `AFFECTED_BY` | Technology | Vulnerability | `version_range` |
| `VULNERABLE_AT` | Endpoint | Vulnerability | `parameter`, `evidence_id` |
| `VULNERABLE_AT` | Parameter | Vulnerability | `payload_used`, `evidence_id` |
| `MAPS_TO` | Vulnerability | Weakness | `confidence` |
| `EXPLOITABLE_VIA` | Weakness | Technique | `effectiveness` |
| `CHILD_OF` | Weakness | Weakness | - |
| `SUBTECHNIQUE_OF` | Technique | Technique | - |
| `USED_PAYLOAD` | Vulnerability | Payload | `success`, `timestamp` |
| `PROVIDES_ACCESS` | Vulnerability | Identity | `access_type`, `privilege_level` |
| `PROVIDES_ACCESS` | Vulnerability | Session | `access_type` |
| `LEADS_TO` | Vulnerability | Vulnerability | `attack_chain_step` |

```cypher
// Service affected by Vulnerability (from NVD)
MATCH (s:Service {cpe_id: "cpe:2.3:a:nginx:nginx:1.22.1:*:*:*:*:*:*:*"})
MATCH (v:Vulnerability {cve_id: "CVE-2023-XXXXX"})
CREATE (s)-[:AFFECTED_BY {
  match_type: "cpe_exact",
  cpe_match: true
}]->(v)

// Vulnerability maps to Weakness
MATCH (v:Vulnerability {vuln_type: "sqli"})
MATCH (w:Weakness {cwe_id: "CWE-89"})
CREATE (v)-[:MAPS_TO {confidence: 10}]->(w)

// Weakness exploitable via Technique
MATCH (w:Weakness {cwe_id: "CWE-89"})
MATCH (t:Technique {mitre_id: "T1190"})
CREATE (w)-[:EXPLOITABLE_VIA {
  effectiveness: "high"
}]->(t)

// Critical: Vulnerability provides access to Identity (PIVOT EDGE)
MATCH (v:Vulnerability {title: "SQL Injection in user_id parameter"})
MATCH (i:Identity {username: "admin"})
CREATE (v)-[:PROVIDES_ACCESS {
  access_type: "credential_extraction",
  privilege_level: "admin"
}]->(i)
```

### Hypothesis & Validation Relationships

| Relationship | Source | Target | Properties |
|--------------|--------|--------|------------|
| `POTENTIALLY_VULNERABLE_TO` | Endpoint | Weakness | `confidence`, `hypothesis_reason`, `created_at` |
| `POTENTIALLY_VULNERABLE_TO` | Parameter | Weakness | `confidence`, `hypothesis_reason` |
| `TESTED_WITH` | Parameter | Payload | `timestamp`, `response_time_ms`, `status_code` |

```cypher
// AI creates hypothesis
MATCH (e:Endpoint {path: "/search"})
MATCH (w:Weakness {cwe_id: "CWE-89"})
CREATE (e)-[:POTENTIALLY_VULNERABLE_TO {
  confidence: 0.8,
  hypothesis_reason: "Numeric ID parameter with direct SQL error in response",
  created_at: datetime()
}]->(w)

// After validation, upgrade to confirmed vulnerability
MATCH (e:Endpoint)-[h:POTENTIALLY_VULNERABLE_TO]->(w:Weakness)
WHERE e.path = "/search" AND w.cwe_id = "CWE-89"
DELETE h
WITH e, w
CREATE (v:Vulnerability {
  uid: randomUUID(),
  title: "Confirmed SQL Injection",
  status: "validated",
  vuln_type: "sqli"
})
CREATE (e)-[:VULNERABLE_AT {evidence_id: "pg_evidence_123"}]->(v)
CREATE (v)-[:MAPS_TO]->(w)
```

---

## 4. Workflow Integration: Graph Updates by Phase

### Phase 1: Ingestion & Scoping

**Trigger**: User inputs target domain and Rules of Engagement

**Graph Operations**:
```cypher
// Create Engagement
CREATE (eng:Engagement {
  uid: randomUUID(),
  name: "Target Pentest 2024",
  status: "active",
  scope_type: "blackbox",
  success_metric: "Extract DB Schema",
  start_date: datetime()
})

// Create RoE
CREATE (roe:RulesOfEngagement {
  uid: randomUUID(),
  scope_includes: ["api.target.com", "*.target.com"],
  scope_excludes: ["payments.target.com"],
  max_requests_per_second: 50,
  allow_dos: false
})

// Link them
CREATE (eng)-[:GOVERNED_BY]->(roe)

// Create root Asset
CREATE (a:Asset {
  uid: randomUUID(),
  name: "api.target.com",
  asset_type: "domain",
  criticality: 8,
  environment: "unknown",
  discovery_source: "user_input",
  discovery_timestamp: datetime(),
  in_scope: true
})

CREATE (a)-[:BELONGS_TO]->(eng)
```

### Phase 2: Autonomous Recon

**Tools**: Subfinder → Nmap → Httpx → Katana

**Subfinder Results** (subdomain discovery):
```cypher
// For each discovered subdomain
UNWIND $subdomains AS sub
MERGE (a:Asset {name: sub.domain})
ON CREATE SET 
  a.uid = randomUUID(),
  a.asset_type = "subdomain",
  a.discovery_source = "subfinder",
  a.discovery_timestamp = datetime(),
  a.in_scope = sub.in_scope,
  a.criticality = 5

// Link to parent domain
WITH a, sub
MATCH (parent:Asset {name: sub.parent_domain})
MERGE (a)-[:SUBDOMAIN_OF]->(parent)
```

**Nmap Results** (port/service discovery):
```cypher
// Create IP, Port, Service chain
MERGE (ip:IPAddress {address: $ip_address})
ON CREATE SET
  ip.uid = randomUUID(),
  ip.version = "ipv4",
  ip.is_public = $is_public,
  ip.last_seen = datetime()

MERGE (p:Port {port_number: $port, protocol: $protocol})
ON CREATE SET
  p.uid = randomUUID(),
  p.state = $state,
  p.discovery_method = "nmap",
  p.last_scanned = datetime()

MERGE (s:Service {service_name: $service_name, product_name: $product, version: $version})
ON CREATE SET
  s.uid = randomUUID(),
  s.vendor = $vendor,
  s.cpe_id = $cpe

// Create relationships
MERGE (ip)-[:LISTENS_ON]->(p)
MERGE (p)-[:RUNS_SERVICE]->(s)

// Link Asset to IP
MATCH (a:Asset {name: $hostname})
MERGE (a)-[:RESOLVES_TO]->(ip)
```

**Automatic NVD Lookup** (triggered by CPE):
```cypher
// When Service has CPE, query NVD and create vulnerabilities
MATCH (s:Service) WHERE s.cpe_id IS NOT NULL
WITH s
UNWIND $nvd_results AS vuln
MERGE (v:Vulnerability {cve_id: vuln.cve_id})
ON CREATE SET
  v.uid = randomUUID(),
  v.title = vuln.title,
  v.cvss_v3_score = vuln.cvss_score,
  v.epss_score = vuln.epss,
  v.severity = vuln.severity,
  v.status = "potential",
  v.discovery_tool = "nvd_api",
  v.discovery_timestamp = datetime(),
  v.patch_available = vuln.patch_available

MERGE (s)-[:AFFECTED_BY]->(v)
```

**Httpx Results** (web application fingerprinting):
```cypher
MERGE (wa:WebApplication {root_url: $url})
ON CREATE SET
  wa.uid = randomUUID(),
  wa.title = $title,
  wa.status_code = $status_code,
  wa.has_waf = $waf_detected,
  wa.waf_vendor = $waf_name,
  wa.technologies = $tech_stack,
  wa.last_crawled = datetime()

// Link to Service
MATCH (s:Service {service_name: "http"})
MATCH (p:Port)<-[:RUNS_SERVICE]-(s)
WHERE p.port_number = $port
MATCH (ip:IPAddress)-[:LISTENS_ON]->(p)
MATCH (a:Asset)-[:RESOLVES_TO]->(ip)
WHERE a.name = $hostname
MERGE (s)-[:HOSTS]->(wa)

// Create Technology nodes
UNWIND $technologies AS tech
MERGE (t:Technology {name: tech.name})
ON CREATE SET
  t.uid = randomUUID(),
  t.category = tech.category,
  t.version = tech.version,
  t.confidence = tech.confidence

MERGE (wa)-[:USES_TECHNOLOGY]->(t)
```

**Katana Results** (web spidering):
```cypher
// Create Endpoints
UNWIND $endpoints AS ep
MERGE (e:Endpoint {full_url: ep.url, method: ep.method})
ON CREATE SET
  e.uid = randomUUID(),
  e.path = ep.path,
  e.status_code = ep.status,
  e.auth_required = ep.auth_required,
  e.is_api = ep.is_api,
  e.fuzz_state = "pending"

// Link to WebApplication
MATCH (wa:WebApplication {root_url: $root_url})
MERGE (wa)-[:HAS_ENDPOINT {
  discovery_method: "katana",
  depth: ep.depth
}]->(e)

// Create Parameters
UNWIND ep.parameters AS param
MERGE (p:Parameter {name: param.name})
ON CREATE SET
  p.uid = randomUUID(),
  p.location = param.location,
  p.data_type = param.type,
  p.sample_value = param.value,
  p.fuzz_count = 0,
  p.interesting_score = 5

MERGE (e)-[:HAS_PARAMETER]->(p)
```

### Phase 3: Vulnerability Mapping & Triage

**Nuclei/SQLmap Scanner Results**:
```cypher
// Create potential vulnerability
CREATE (v:Vulnerability {
  uid: randomUUID(),
  title: $vuln_title,
  vuln_type: $vuln_type,
  severity: $severity,
  status: "potential",
  confidence: $confidence,
  discovery_tool: $tool_name,
  discovery_timestamp: datetime()
})

// Link to affected endpoint/parameter
MATCH (e:Endpoint {full_url: $affected_url})
CREATE (e)-[:VULNERABLE_AT {
  parameter: $param_name,
  evidence_id: $pg_evidence_id
}]->(v)

// Link to CWE
MATCH (w:Weakness {cwe_id: $cwe_id})
MERGE (v)-[:MAPS_TO]->(w)
```

**AI Triage Agent - Tech Stack Validation**:
```cypher
// Query to validate vulnerability against tech stack
MATCH (e:Endpoint)-[:VULNERABLE_AT]->(v:Vulnerability)
WHERE v.status = "potential" AND v.vuln_type = "php_rce"
MATCH (e)<-[:HAS_ENDPOINT]-(wa:WebApplication)-[:USES_TECHNOLOGY]->(t:Technology)
WHERE t.name IN ["PHP", "Laravel", "WordPress"]
RETURN v, e, t

// If no PHP tech found, mark as false positive
MATCH (v:Vulnerability {uid: $vuln_id})
WHERE NOT EXISTS {
  MATCH (v)<-[:VULNERABLE_AT]-(e:Endpoint)<-[:HAS_ENDPOINT]-(wa:WebApplication)-[:USES_TECHNOLOGY]->(t:Technology)
  WHERE t.name =~ "(?i)php.*"
}
SET v.status = "false_positive",
    v.triage_reason = "Tech stack mismatch: PHP vulnerability on non-PHP stack"
```

**Prioritization Query**:
```cypher
// P0-P3 Assignment based on CVSS, EPSS, and reachability
MATCH (v:Vulnerability)
WHERE v.status = "potential"
OPTIONAL MATCH (v)<-[:VULNERABLE_AT]-(e:Endpoint)
OPTIONAL MATCH (e)<-[:HAS_ENDPOINT]-(wa:WebApplication)
WITH v, e, wa,
  CASE
    WHEN v.cvss_v3_score >= 9.0 AND v.epss_score >= 0.5 THEN "P0"
    WHEN v.cvss_v3_score >= 7.0 AND e.auth_required = false THEN "P0"
    WHEN v.cvss_v3_score >= 7.0 THEN "P1"
    WHEN v.cvss_v3_score >= 4.0 THEN "P2"
    ELSE "P3"
  END AS priority
SET v.priority = priority
RETURN v.title, v.severity, priority
ORDER BY priority
```

### Phase 4: Strategy & Technique Selection

**MITRE ATT&CK Query for Attack Planning**:
```cypher
// Find applicable techniques for discovered weaknesses
MATCH (v:Vulnerability)-[:MAPS_TO]->(w:Weakness)-[:EXPLOITABLE_VIA]->(t:Technique)
WHERE v.status IN ["potential", "validated"]
MATCH (e:Endpoint)-[:VULNERABLE_AT]->(v)
MATCH (e)<-[:HAS_ENDPOINT]-(wa:WebApplication)-[:USES_TECHNOLOGY]->(tech:Technology)
RETURN 
  v.title AS vulnerability,
  w.cwe_id AS weakness,
  t.mitre_id AS technique,
  t.name AS technique_name,
  t.tactic AS attack_phase,
  collect(DISTINCT tech.name) AS tech_stack
ORDER BY 
  CASE t.tactic 
    WHEN "initial_access" THEN 1
    WHEN "execution" THEN 2
    WHEN "privilege_escalation" THEN 3
    WHEN "credential_access" THEN 4
    WHEN "lateral_movement" THEN 5
    ELSE 6
  END
```

**AI Chain-of-Thought Reasoning Storage**:
```cypher
// Store AI reasoning trace
CREATE (r:ReasoningTrace {
  uid: randomUUID(),
  timestamp: datetime(),
  phase: "technique_selection",
  thought: $ai_thought,
  decision: $selected_technique,
  confidence: $confidence
})

MATCH (v:Vulnerability {uid: $vuln_id})
CREATE (v)-[:REASONED_ABOUT]->(r)
```

### Phase 5: Execution & Verification

**Payload Execution Tracking**:
```cypher
// Record payload attempt
CREATE (p:Payload {
  uid: randomUUID(),
  name: $payload_name,
  payload_type: "detection",
  content: $payload_content,
  content_hash: $hash,
  is_safe: true,
  target_vuln_type: $vuln_type
})

// Link to vulnerability test
MATCH (v:Vulnerability {uid: $vuln_id})
CREATE (v)-[:USED_PAYLOAD {
  success: $success,
  timestamp: datetime(),
  response_time_ms: $response_time,
  evidence_id: $pg_evidence_id
}]->(p)

// Update payload stats
SET p.success_count = CASE WHEN $success THEN 1 ELSE 0 END,
    p.failure_count = CASE WHEN NOT $success THEN 1 ELSE 0 END
```

**Vulnerability Validation Update**:
```cypher
// Upgrade potential to validated
MATCH (v:Vulnerability {uid: $vuln_id})
SET v.status = "validated",
    v.validation_timestamp = datetime(),
    v.confidence = 10,
    v.evidence_id = $pg_evidence_id

// Update hypothesis edge if exists
MATCH (e:Endpoint)-[h:POTENTIALLY_VULNERABLE_TO]->(w:Weakness)
WHERE (e)-[:VULNERABLE_AT]->(v) AND (v)-[:MAPS_TO]->(w)
DELETE h
```

### Phase 6: Post-Exploitation & Pivoting

**Credential/Session Extraction**:
```cypher
// Create extracted identity
CREATE (i:Identity {
  uid: randomUUID(),
  identity_type: "user",
  username: $username,
  role: $role,
  is_admin: $is_admin,
  source: "sqli_extraction",
  credential_type: $cred_type,
  credential_value: $encrypted_cred,
  is_valid: false
})

// Link vulnerability to identity (THE PIVOT EDGE)
MATCH (v:Vulnerability {uid: $vuln_id})
CREATE (v)-[:PROVIDES_ACCESS {
  access_type: "credential_extraction",
  privilege_level: $role
}]->(i)

// Create session if token extracted
CREATE (s:Session {
  uid: randomUUID(),
  token_type: $token_type,
  token_value: $encrypted_token,
  is_valid: true,
  extraction_method: $method
})
CREATE (i)-[:HAS_SESSION]->(s)
```

**Access Discovery for Pivoting**:
```cypher
// Find new attack surface from extracted credentials
MATCH (v:Vulnerability)-[:PROVIDES_ACCESS]->(i:Identity)
WHERE i.is_admin = true
MATCH (e:Endpoint)
WHERE e.auth_required = true AND e.path CONTAINS "admin"
MERGE (i)-[:CAN_ACCESS {
  permission_level: "assumed",
  verified: false
}]->(e)

// Queue these endpoints for scanning
MATCH (i:Identity)-[:CAN_ACCESS {verified: false}]->(e:Endpoint)
SET e.fuzz_state = "pending",
    e.priority_boost = 10
RETURN e.full_url AS new_target, i.username AS access_via
```

**Internal Network Discovery**:
```cypher
// When internal IP discovered via SSRF or data leak
CREATE (ip:IPAddress {
  uid: randomUUID(),
  address: $internal_ip,
  version: "ipv4",
  is_public: false,
  last_seen: datetime()
})

// Mark as pivot point
CREATE (pivot:PivotPoint {
  uid: randomUUID(),
  discovery_method: $method,
  timestamp: datetime()
})

MATCH (v:Vulnerability {uid: $source_vuln_id})
CREATE (v)-[:DISCOVERED]->(ip)
CREATE (v)-[:ENABLED_PIVOT]->(pivot)
CREATE (pivot)-[:TARGETS]->(ip)

// Queue for internal recon (restart Phase 2)
SET ip.scan_queued = true,
    ip.scan_priority = "high"
```

---

## 5. Critical AI Query Patterns

### Attack Path Discovery
```cypher
// Find path from unauthenticated endpoint to critical asset
MATCH path = (e:Endpoint)-[:VULNERABLE_AT|PROVIDES_ACCESS|CAN_ACCESS*1..5]->(target)
WHERE e.auth_required = false
  AND (target:Identity {is_admin: true} OR target:Service {criticality: 10})
RETURN path, length(path) AS hops
ORDER BY hops
LIMIT 10
```

### WAF Bypass Route Finding
```cypher
// Find vulnerable endpoints not protected by WAF
MATCH (e:Endpoint)-[:VULNERABLE_AT]->(v:Vulnerability)
WHERE v.status = "validated"
MATCH (e)<-[:HAS_ENDPOINT]-(wa:WebApplication)
WHERE wa.has_waf = false
RETURN e.full_url, v.title, v.severity
ORDER BY v.cvss_v3_score DESC
```

### Credential Reuse Detection
```cypher
// Find if extracted credentials work elsewhere
MATCH (i:Identity)-[:HAS_SESSION]->(s:Session)
WHERE s.is_valid = true
MATCH (e:Endpoint)
WHERE e.auth_required = true AND e.auth_type = s.token_type
RETURN i.username, s.token_type, collect(e.full_url) AS potential_targets
```

### Full Kill Chain Query
```cypher
// Reconstruct complete attack chain
MATCH (start:Endpoint)-[r1:VULNERABLE_AT]->(v1:Vulnerability)
WHERE v1.status = "exploited"
OPTIONAL MATCH (v1)-[r2:PROVIDES_ACCESS]->(i:Identity)
OPTIONAL MATCH (i)-[r3:CAN_ACCESS]->(e2:Endpoint)
OPTIONAL MATCH (e2)-[r4:VULNERABLE_AT]->(v2:Vulnerability)
RETURN start.path AS entry_point,
       v1.title AS initial_vuln,
       i.username AS compromised_identity,
       e2.path AS pivot_target,
       v2.title AS secondary_vuln
```

---

## 6. PostgreSQL Schema for Evidence Storage

```sql
CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_uid UUID NOT NULL,
    evidence_type VARCHAR(50) NOT NULL, -- 'http_request', 'http_response', 'screenshot', 'log'
    request_method VARCHAR(10),
    request_url TEXT,
    request_headers JSONB,
    request_body TEXT,
    response_status INTEGER,
    response_headers JSONB,
    response_body TEXT,
    response_time_ms INTEGER,
    screenshot_path TEXT,
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    notes TEXT
);

CREATE INDEX idx_evidence_vuln ON evidence(vulnerability_uid);

CREATE TABLE tool_outputs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name VARCHAR(100) NOT NULL,
    command TEXT NOT NULL,
    raw_output TEXT,
    parsed_json JSONB,
    exit_code INTEGER,
    execution_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE ai_reasoning_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phase VARCHAR(50) NOT NULL,
    input_context JSONB,
    thought_process TEXT,
    decision TEXT,
    confidence FLOAT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## 7. Graph Manager Python Class

```python
from neo4j import GraphDatabase
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid
import json

class CSKGManager:
    """Manages the Cybersecurity Knowledge Graph"""
    
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def close(self):
        self.driver.close()
    
    def _run_query(self, query: str, params: Dict = None) -> List[Dict]:
        with self.driver.session() as session:
            result = session.run(query, params or {})
            return [record.data() for record in result]
    
    # ==================== PHASE 1: INITIALIZATION ====================
    
    def create_engagement(self, name: str, scope_type: str, 
                         success_metric: str, scope_includes: List[str],
                         scope_excludes: List[str] = None) -> str:
        """Initialize a new pentest engagement"""
        eng_uid = str(uuid.uuid4())
        roe_uid = str(uuid.uuid4())
        
        query = """
        CREATE (eng:Engagement {
            uid: $eng_uid,
            name: $name,
            status: 'active',
            scope_type: $scope_type,
            success_metric: $success_metric,
            start_date: datetime()
        })
        CREATE (roe:RulesOfEngagement {
            uid: $roe_uid,
            scope_includes: $scope_includes,
            scope_excludes: $scope_excludes,
            allow_dos: false,
            notify_on_critical: true
        })
        CREATE (eng)-[:GOVERNED_BY]->(roe)
        RETURN eng.uid AS engagement_id
        """
        
        self._run_query(query, {
            'eng_uid': eng_uid,
            'roe_uid': roe_uid,
            'name': name,
            'scope_type': scope_type,
            'success_metric': success_metric,
            'scope_includes': scope_includes,
            'scope_excludes': scope_excludes or []
        })
        return eng_uid
    
    def add_root_asset(self, engagement_uid: str, domain: str, 
                       criticality: int = 5) -> str:
        """Add initial target asset"""
        asset_uid = str(uuid.uuid4())
        
        query = """
        MATCH (eng:Engagement {uid: $eng_uid})
        CREATE (a:Asset {
            uid: $asset_uid,
            name: $domain,
            asset_type: 'domain',
            criticality: $criticality,
            environment: 'unknown',
            discovery_source: 'user_input',
            discovery_timestamp: datetime(),
            in_scope: true
        })
        CREATE (a)-[:BELONGS_TO]->(eng)
        RETURN a.uid AS asset_id
        """
        
        self._run_query(query, {
            'eng_uid': engagement_uid,
            'asset_uid': asset_uid,
            'domain': domain,
            'criticality': criticality
        })
        return asset_uid
    
    # ==================== PHASE 2: RECON ====================
    
    def ingest_subfinder_results(self, parent_domain: str, 
                                  subdomains: List[Dict]) -> int:
        """Process subfinder output"""
        query = """
        UNWIND $subdomains AS sub
        MERGE (a:Asset {name: sub.domain})
        ON CREATE SET 
            a.uid = randomUUID(),
            a.asset_type = 'subdomain',
            a.discovery_source = 'subfinder',
            a.discovery_timestamp = datetime(),
            a.in_scope = true,
            a.criticality = 5
        WITH a, sub
        MATCH (parent:Asset {name: $parent_domain})
        MERGE (a)-[:SUBDOMAIN_OF]->(parent)
        RETURN count(a) AS created
        """
        
        result = self._run_query(query, {
            'parent_domain': parent_domain,
            'subdomains': subdomains
        })
        return result[0]['created'] if result else 0
    
    def ingest_nmap_results(self, hostname: str, nmap_data: Dict) -> None:
        """Process nmap JSON output"""
        for host in nmap_data.get('hosts', []):
            ip = host.get('ip')
            
            # Create IP node
            ip_query = """
            MERGE (ip:IPAddress {address: $address})
            ON CREATE SET
                ip.uid = randomUUID(),
                ip.version = $version,
                ip.is_public = $is_public,
                ip.last_seen = datetime()
            ON MATCH SET
                ip.last_seen = datetime()
            
            WITH ip
            MATCH (a:Asset {name: $hostname})
            MERGE (a)-[:RESOLVES_TO]->(ip)
            """
            
            self._run_query(ip_query, {
                'address': ip,
                'version': 'ipv4' if '.' in ip else 'ipv6',
                'is_public': not self._is_private_ip(ip),
                'hostname': hostname
            })
            
            # Create Port and Service nodes
            for port_data in host.get('ports', []):
                port_query = """
                MATCH (ip:IPAddress {address: $ip_address})
                MERGE (p:Port {port_number: $port_num, protocol: $protocol})
                ON CREATE SET
                    p.uid = randomUUID(),
                    p.state = $state,
                    p.discovery_method = 'nmap',
                    p.last_scanned = datetime()
                MERGE (ip)-[:LISTENS_ON]->(p)
                
                WITH p
                WHERE $service_name IS NOT NULL
                MERGE (s:Service {
                    service_name: $service_name,
                    product_name: coalesce($product, 'unknown'),
                    version: coalesce($version, 'unknown')
                })
                ON CREATE SET
                    s.uid = randomUUID(),
                    s.cpe_id = $cpe
                MERGE (p)-[:RUNS_SERVICE]->(s)
                """
                
                self._run_query(port_query, {
                    'ip_address': ip,
                    'port_num': port_data['port'],
                    'protocol': port_data.get('protocol', 'tcp'),
                    'state': port_data.get('state', 'open'),
                    'service_name': port_data.get('service'),
                    'product': port_data.get('product'),
                    'version': port_data.get('version'),
                    'cpe': port_data.get('cpe')
                })
    
    def ingest_httpx_results(self, results: List[Dict]) -> None:
        """Process httpx JSON output"""
        for r in results:
            query = """
            MERGE (wa:WebApplication {root_url: $url})
            ON CREATE SET
                wa.uid = randomUUID(),
                wa.title = $title,
                wa.status_code = $status,
                wa.has_waf = $has_waf,
                wa.waf_vendor = $waf,
                wa.technologies = $tech,
                wa.last_crawled = datetime()
            
            WITH wa
            UNWIND $technologies AS tech
            MERGE (t:Technology {name: tech.name})
            ON CREATE SET
                t.uid = randomUUID(),
                t.category = tech.category,
                t.version = tech.version
            MERGE (wa)-[:USES_TECHNOLOGY]->(t)
            """
            
            self._run_query(query, {
                'url': r['url'],
                'title': r.get('title'),
                'status': r.get('status_code'),
                'has_waf': r.get('waf', {}).get('detected', False),
                'waf': r.get('waf', {}).get('name'),
                'tech': [t['name'] for t in r.get('technologies', [])],
                'technologies': r.get('technologies', [])
            })
    
    def ingest_katana_results(self, root_url: str, 
                               endpoints: List[Dict]) -> int:
        """Process katana spider output"""
        query = """
        MATCH (wa:WebApplication {root_url: $root_url})
        UNWIND $endpoints AS ep
        MERGE (e:Endpoint {full_url: ep.url, method: coalesce(ep.method, 'GET')})
        ON CREATE SET
            e.uid = randomUUID(),
            e.path = ep.path,
            e.status_code = ep.status,
            e.auth_required = coalesce(ep.auth_required, false),
            e.is_api = ep.url CONTAINS '/api/' OR ep.url CONTAINS '/v1/' OR ep.url CONTAINS '/v2/',
            e.fuzz_state = 'pending'
        MERGE (wa)-[:HAS_ENDPOINT]->(e)
        
        WITH e, ep
        UNWIND coalesce(ep.parameters, []) AS param
        MERGE (p:Parameter {name: param.name})
        ON CREATE SET
            p.uid = randomUUID(),
            p.location = param.location,
            p.data_type = coalesce(param.type, 'string'),
            p.sample_value = param.value,
            p.fuzz_count = 0,
            p.interesting_score = 5
        MERGE (e)-[:HAS_PARAMETER]->(p)
        
        RETURN count(DISTINCT e) AS endpoints_created
        """
        
        result = self._run_query(query, {
            'root_url': root_url,
            'endpoints': endpoints
        })
        return result[0]['endpoints_created'] if result else 0
    
    # ==================== PHASE 3: VULNERABILITY MAPPING ====================
    
    def add_vulnerability(self, endpoint_url: str, vuln_data: Dict,
                          parameter: str = None) -> str:
        """Add discovered vulnerability"""
        vuln_uid = str(uuid.uuid4())
        
        query = """
        CREATE (v:Vulnerability {
            uid: $uid,
            title: $title,
            cve_id: $cve_id,
            cvss_v3_score: $cvss,
            severity: $severity,
            vuln_type: $vuln_type,
            status: 'potential',
            confidence: $confidence,
            discovery_tool: $tool,
            discovery_timestamp: datetime()
        })
        
        WITH v
        MATCH (e:Endpoint {full_url: $endpoint_url})
        CREATE (e)-[:VULNERABLE_AT {
            parameter: $parameter,
            evidence_id: $evidence_id
        }]->(v)
        
        WITH v
        OPTIONAL MATCH (w:Weakness {cwe_id: $cwe_id})
        FOREACH (_ IN CASE WHEN w IS NOT NULL THEN [1] ELSE [] END |
            MERGE (v)-[:MAPS_TO]->(w)
        )
        
        RETURN v.uid AS vuln_id
        """
        
        self._run_query(query, {
            'uid': vuln_uid,
            'title': vuln_data['title'],
            'cve_id': vuln_data.get('cve_id'),
            'cvss': vuln_data.get('cvss_v3_score'),
            'severity': vuln_data['severity'],
            'vuln_type': vuln_data['type'],
            'confidence': vuln_data.get('confidence', 5),
            'tool': vuln_data['tool'],
            'endpoint_url': endpoint_url,
            'parameter': parameter,
            'evidence_id': vuln_data.get('evidence_id'),
            'cwe_id': vuln_data.get('cwe_id')
        })
        return vuln_uid
    
    def triage_vulnerability(self, vuln_uid: str) -> Dict:
        """AI triage: validate vuln against tech stack"""
        query = """
        MATCH (v:Vulnerability {uid: $uid})
        MATCH (e:Endpoint)-[:VULNERABLE_AT]->(v)
        MATCH (e)<-[:HAS_ENDPOINT]-(wa:WebApplication)
        OPTIONAL MATCH (wa)-[:USES_TECHNOLOGY]->(t:Technology)
        RETURN v.vuln_type AS vuln_type,
               v.title AS title,
               collect(DISTINCT t.name) AS tech_stack,
               wa.has_waf AS has_waf,
               e.auth_required AS auth_required
        """
        
        result = self._run_query(query, {'uid': vuln_uid})
        return result[0] if result else {}
    
    def update_vulnerability_status(self, vuln_uid: str, status: str,
                                     reason: str = None) -> None:
        """Update vulnerability status after triage/validation"""
        query = """
        MATCH (v:Vulnerability {uid: $uid})
        SET v.status = $status,
            v.triage_reason = $reason,
            v.validation_timestamp = CASE WHEN $status = 'validated' THEN datetime() ELSE v.validation_timestamp END
        """
        self._run_query(query, {
            'uid': vuln_uid,
            'status': status,
            'reason': reason
        })
    
    def prioritize_vulnerabilities(self) -> List[Dict]:
        """Assign P0-P3 priorities"""
        query = """
        MATCH (v:Vulnerability)
        WHERE v.status IN ['potential', 'validated']
        OPTIONAL MATCH (e:Endpoint)-[:VULNERABLE_AT]->(v)
        OPTIONAL MATCH (e)<-[:HAS_ENDPOINT]-(wa:WebApplication)
        WITH v, e, wa,
            CASE
                WHEN v.cvss_v3_score >= 9.0 THEN 'P0'
                WHEN v.cvss_v3_score >= 7.0 AND coalesce(e.auth_required, true) = false THEN 'P0'
                WHEN v.cvss_v3_score >= 7.0 THEN 'P1'
                WHEN v.cvss_v3_score >= 4.0 THEN 'P2'
                ELSE 'P3'
            END AS priority
        SET v.priority = priority
        RETURN v.uid AS uid, v.title AS title, v.severity AS severity, priority
        ORDER BY priority, v.cvss_v3_score DESC
        """
        return self._run_query(query)
    
    # ==================== PHASE 4 & 5: EXECUTION ====================
    
    def record_payload_attempt(self, vuln_uid: str, payload_data: Dict,
                                success: bool, evidence_id: str = None) -> str:
        """Record exploitation attempt"""
        payload_uid = str(uuid.uuid4())
        
        query = """
        CREATE (p:Payload {
            uid: $payload_uid,
            name: $name,
            payload_type: $type,
            content: $content,
            content_hash: $hash,
            is_safe: $is_safe,
            target_vuln_type: $target_type,
            success_count: CASE WHEN $success THEN 1 ELSE 0 END,
            failure_count: CASE WHEN NOT $success THEN 1 ELSE 0 END
        })
        
        WITH p
        MATCH (v:Vulnerability {uid: $vuln_uid})
        CREATE (v)-[:USED_PAYLOAD {
            success: $success,
            timestamp: datetime(),
            response_time_ms: $response_time,
            evidence_id: $evidence_id
        }]->(p)
        
        WITH v, p
        WHERE $success = true
        SET v.status = 'validated',
            v.validation_timestamp = datetime(),
            v.confidence = 10
        
        RETURN p.uid AS payload_id
        """
        
        self._run_query(query, {
            'payload_uid': payload_uid,
            'vuln_uid': vuln_uid,
            'name': payload_data['name'],
            'type': payload_data.get('type', 'detection'),
            'content': payload_data['content'],
            'hash': payload_data.get('hash'),
            'is_safe': payload_data.get('is_safe', True),
            'target_type': payload_data.get('target_type'),
            'success': success,
            'response_time': payload_data.get('response_time_ms'),
            'evidence_id': evidence_id
        })
        return payload_uid
    
    # ==================== PHASE 6: POST-EXPLOITATION ====================
    
    def extract_credentials(self, vuln_uid: str, creds: List[Dict]) -> List[str]:
        """Store extracted credentials and create pivot edges"""
        identity_uids = []
        
        for cred in creds:
            identity_uid = str(uuid.uuid4())
            identity_uids.append(identity_uid)
            
            query = """
            CREATE (i:Identity {
                uid: $identity_uid,
                identity_type: 'user',
                username: $username,
                email: $email,
                role: $role,
                is_admin: $is_admin,
                source: 'vulnerability_extraction',
                credential_type: $cred_type,
                credential_value: $cred_value,
                is_valid: false
            })
            
            WITH i
            MATCH (v:Vulnerability {uid: $vuln_uid})
            SET v.status = 'exploited'
            CREATE (v)-[:PROVIDES_ACCESS {
                access_type: 'credential_extraction',
                privilege_level: $role
            }]->(i)
            
            RETURN i.uid AS identity_id
            """
            
            self._run_query(query, {
                'identity_uid': identity_uid,
                'vuln_uid': vuln_uid,
                'username': cred.get('username'),
                'email': cred.get('email'),
                'role': cred.get('role', 'user'),
                'is_admin': cred.get('is_admin', False),
                'cred_type': cred.get('type', 'hash'),
                'cred_value': cred.get('value')
            })
        
        return identity_uids
    
    def discover_pivot_opportunities(self, identity_uid: str) -> List[Dict]:
        """Find new attack surface from compromised identity"""
        query = """
        MATCH (i:Identity {uid: $uid})
        MATCH (e:Endpoint)
        WHERE e.auth_required = true
          AND (
            (i.is_admin = true AND e.path CONTAINS 'admin')
            OR e.path CONTAINS 'user'
            OR e.path CONTAINS 'account'
          )
        MERGE (i)-[:CAN_ACCESS {
            permission_level: 'assumed',
            verified: false
        }]->(e)
        
        SET e.fuzz_state = 'pending'
        
        RETURN e.full_url AS target,
               e.path AS path,
               e.method AS method
        """
        return self._run_query(query, {'uid': identity_uid})
    
    # ==================== AI QUERY INTERFACE ====================
    
    def find_attack_paths(self, max_hops: int = 5) -> List[Dict]:
        """Find paths from unauth endpoints to high-value targets"""
        query = """
        MATCH path = (e:Endpoint)-[:VULNERABLE_AT|PROVIDES_ACCESS|CAN_ACCESS*1..$max_hops]->(target)
        WHERE e.auth_required = false
          AND (
            (target:Identity AND target.is_admin = true)
            OR (target:Service AND target.criticality >= 8)
            OR (target:Endpoint AND target.path CONTAINS 'admin')
          )
        RETURN 
            [n IN nodes(path) | 
                CASE 
                    WHEN n:Endpoint THEN n.path
                    WHEN n:Vulnerability THEN n.title
                    WHEN n:Identity THEN n.username
                    WHEN n:Service THEN n.product_name
                    ELSE 'unknown'
                END
            ] AS path_nodes,
            length(path) AS hops,
            [r IN relationships(path) | type(r)] AS relationships
        ORDER BY hops
        LIMIT 20
        """
        return self._run_query(query, {'max_hops': max_hops})
    
    def get_graph_summary(self) -> Dict:
        """Get current graph statistics"""
        query = """
        MATCH (n)
        WITH labels(n)[0] AS label, count(n) AS count
        RETURN collect({label: label, count: count}) AS nodes
        """
        nodes = self._run_query(query)
        
        vuln_query = """
        MATCH (v:Vulnerability)
        RETURN v.status AS status, count(v) AS count
        """
        vulns = self._run_query(vuln_query)
        
        return {
            'node_counts': {n['label']: n['count'] for n in nodes[0]['nodes']},
            'vulnerability_status': {v['status']: v['count'] for v in vulns}
        }
    
    # ==================== HELPERS ====================
    
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private range"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        first = int(parts[0])
        second = int(parts[1])
        
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        return False
```

---

## 8. Visualization Queries for Dashboard

### Real-time Attack Surface Map
```cypher
// Get full infrastructure graph for visualization
MATCH (a:Asset)-[r1:RESOLVES_TO]->(ip:IPAddress)
OPTIONAL MATCH (ip)-[r2:LISTENS_ON]->(p:Port)
OPTIONAL MATCH (p)-[r3:RUNS_SERVICE]->(s:Service)
OPTIONAL MATCH (s)-[r4:HOSTS]->(wa:WebApplication)
OPTIONAL MATCH (wa)-[r5:HAS_ENDPOINT]->(e:Endpoint)
OPTIONAL MATCH (e)-[r6:VULNERABLE_AT]->(v:Vulnerability)
RETURN *
```

### Vulnerability Heatmap Data
```cypher
MATCH (v:Vulnerability)
WHERE v.status IN ['potential', 'validated', 'exploited']
RETURN v.severity AS severity,
       v.status AS status,
       count(v) AS count
ORDER BY 
    CASE v.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END
```

### Kill Chain Progress
```cypher
MATCH (t:Technique)
WHERE EXISTS {
    MATCH (v:Vulnerability)-[:MAPS_TO]->(:Weakness)-[:EXPLOITABLE_VIA]->(t)
    WHERE v.status = 'exploited'
}
RETURN t.tactic AS phase, collect(DISTINCT t.name) AS techniques
ORDER BY 
    CASE t.tactic
        WHEN 'initial_access' THEN 1
        WHEN 'execution' THEN 2
        WHEN 'persistence' THEN 3
        WHEN 'privilege_escalation' THEN 4
        WHEN 'defense_evasion' THEN 5
        WHEN 'credential_access' THEN 6
        WHEN 'discovery' THEN 7
        WHEN 'lateral_movement' THEN 8
        WHEN 'collection' THEN 9
        WHEN 'exfiltration' THEN 10
        WHEN 'impact' THEN 11
        ELSE 12
    END
```

---

## 9. Pre-populated Reference Data

### Load CWE Hierarchy
```cypher
// Load common web vulnerabilities CWEs
CREATE (w1:Weakness {uid: randomUUID(), cwe_id: "CWE-79", name: "Cross-site Scripting (XSS)", abstraction: "base"})
CREATE (w2:Weakness {uid: randomUUID(), cwe_id: "CWE-89", name: "SQL Injection", abstraction: "base"})
CREATE (w3:Weakness {uid: randomUUID(), cwe_id: "CWE-94", name: "Code Injection", abstraction: "class"})
CREATE (w4:Weakness {uid: randomUUID(), cwe_id: "CWE-78", name: "OS Command Injection", abstraction: "base"})
CREATE (w5:Weakness {uid: randomUUID(), cwe_id: "CWE-22", name: "Path Traversal", abstraction: "base"})
CREATE (w6:Weakness {uid: randomUUID(), cwe_id: "CWE-918", name: "SSRF", abstraction: "base"})
CREATE (w7:Weakness {uid: randomUUID(), cwe_id: "CWE-639", name: "IDOR", abstraction: "base"})
CREATE (w8:Weakness {uid: randomUUID(), cwe_id: "CWE-287", name: "Improper Authentication", abstraction: "class"})
CREATE (w9:Weakness {uid: randomUUID(), cwe_id: "CWE-502", name: "Deserialization of Untrusted Data", abstraction: "base"})
CREATE (w10:Weakness {uid: randomUUID(), cwe_id: "CWE-611", name: "XXE", abstraction: "base"})
```

### Load MITRE ATT&CK Techniques
```cypher
// Initial Access techniques
CREATE (t1:Technique {uid: randomUUID(), mitre_id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial_access", platforms: ["Linux", "Windows", "macOS"]})
CREATE (t2:Technique {uid: randomUUID(), mitre_id: "T1133", name: "External Remote Services", tactic: "initial_access", platforms: ["Linux", "Windows"]})

// Execution
CREATE (t3:Technique {uid: randomUUID(), mitre_id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution", platforms: ["Linux", "Windows", "macOS"]})
CREATE (t4:Technique {uid: randomUUID(), mitre_id: "T1203", name: "Exploitation for Client Execution", tactic: "execution", platforms: ["Linux", "Windows", "macOS"]})

// Credential Access
CREATE (t5:Technique {uid: randomUUID(), mitre_id: "T1110", name: "Brute Force", tactic: "credential_access", platforms: ["Linux", "Windows", "macOS"]})
CREATE (t6:Technique {uid: randomUUID(), mitre_id: "T1552", name: "Unsecured Credentials", tactic: "credential_access", platforms: ["Linux", "Windows"]})

// Link weaknesses to techniques
MATCH (w:Weakness {cwe_id: "CWE-89"}), (t:Technique {mitre_id: "T1190"})
CREATE (w)-[:EXPLOITABLE_VIA {effectiveness: "high"}]->(t)

MATCH (w:Weakness {cwe_id: "CWE-78"}), (t:Technique {mitre_id: "T1059"})
CREATE (w)-[:EXPLOITABLE_VIA {effectiveness: "high"}]->(t)
```

---

## 10. Best Practices & Operational Guidelines

### Data Integrity
1. **Always use transactions** for multi-node updates
2. **Set timestamps** on all create/update operations
3. **Use UUIDs** for all node identifiers
4. **Encrypt sensitive data** (credentials, tokens) before storage

### Performance Optimization
1. **Create indexes** on frequently queried properties:
```cypher
CREATE INDEX asset_name FOR (a:Asset) ON (a.name);
CREATE INDEX ip_address FOR (ip:IPAddress) ON (ip.address);
CREATE INDEX endpoint_url FOR (e:Endpoint) ON (e.full_url);
CREATE INDEX vuln_status FOR (v:Vulnerability) ON (v.status);
CREATE INDEX vuln_cve FOR (v:Vulnerability) ON (v.cve_id);
```

2. **Use MERGE** instead of CREATE to prevent duplicates
3. **Batch operations** for bulk imports (UNWIND)

### Security Considerations
1. **Scope validation**: Always check `in_scope` before scanning
2. **Rate limiting**: Respect `max_requests_per_second` from RoE
3. **Evidence chain**: Link all findings to PostgreSQL evidence
4. **Audit trail**: Log all AI decisions with reasoning

### Agent Decision Flow
```
1. Query graph for current state
2. Identify gaps (unscanned assets, untested vulns)
3. Check RoE constraints
4. Select next action based on priority
5. Execute and observe
6. Update graph with results
7. Loop
```

---

## Appendix A: Quick Reference - Node Labels

| Label | Purpose | Key Properties |
|-------|---------|----------------|
| `Asset` | Target domain/system | `name`, `criticality`, `in_scope` |
| `IPAddress` | Network address | `address`, `is_public` |
| `Port` | Network port | `port_number`, `state` |
| `Service` | Running software | `product_name`, `version`, `cpe_id` |
| `WebApplication` | Web app instance | `root_url`, `has_waf`, `technologies` |
| `Endpoint` | URL/API route | `full_url`, `method`, `auth_required` |
| `Parameter` | Input parameter | `name`, `location`, `data_type` |
| `Technology` | Software component | `name`, `category`, `version` |
| `Identity` | User/account | `username`, `is_admin`, `credential_type` |
| `Session` | Auth token | `token_type`, `is_valid` |
| `Vulnerability` | Security flaw | `title`, `severity`, `status` |
| `Weakness` | CWE category | `cwe_id`, `name` |
| `Technique` | MITRE ATT&CK | `mitre_id`, `tactic` |
| `Payload` | Attack payload | `content`, `is_safe` |
| `Engagement` | Pentest project | `name`, `status`, `success_metric` |
| `RulesOfEngagement` | Constraints | `scope_includes`, `scope_excludes` |

## Appendix B: Quick Reference - Relationships

| Relationship | Description |
|--------------|-------------|
| `RESOLVES_TO` | Asset → IPAddress |
| `LISTENS_ON` | IPAddress → Port |
| `RUNS_SERVICE` | Port → Service |
| `HOSTS` | Service → WebApplication |
| `HAS_ENDPOINT` | WebApplication → Endpoint |
| `HAS_PARAMETER` | Endpoint → Parameter |
| `USES_TECHNOLOGY` | WebApplication/Service → Technology |
| `AFFECTED_BY` | Service/Technology → Vulnerability |
| `VULNERABLE_AT` | Endpoint/Parameter → Vulnerability |
| `MAPS_TO` | Vulnerability → Weakness |
| `EXPLOITABLE_VIA` | Weakness → Technique |
| `PROVIDES_ACCESS` | Vulnerability → Identity/Session |
| `CAN_ACCESS` | Identity/Session → Endpoint |
| `HAS_SESSION` | Identity → Session |
| `BELONGS_TO` | Asset → Engagement |
| `GOVERNED_BY` | Engagement → RulesOfEngagement |

---

*Document Version: 1.0*  
*Last Updated: December 2024*

