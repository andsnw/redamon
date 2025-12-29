# RedAmon - Next Steps After Reconnaissance

## Current State ✅
The recon phase produces `recon_<domain>.json` containing:
- WHOIS data
- Subdomains discovered
- DNS records
- Nmap scan results (IPs, ports, services, versions)

---

## Phase 2: Vulnerability Enrichment

### What to Build: `vuln_enricher.py`

**Purpose:** Add vulnerability data to each service detected in recon.

**Process:**
1. For each service/version in nmap results (e.g., `nginx 1.18.0`)
2. Query vulnerability databases for matching CVEs
3. Add CVE details to the JSON under each port/service

**Data Sources:**
| Source | What It Provides |
|--------|------------------|
| GVM/OpenVAS | Full vulnerability scan with CVE detection |
| NVD API | CVE lookup by product/version (CPE) |
| Vulners API | Aggregated CVE + exploit data |

**Output:** Each service in JSON gets a `vulnerabilities` array with CVE info.

---

## Phase 3: Exploit & MITRE Mapping

### What to Build: `attack_mapper.py`

**Purpose:** For each CVE, determine if exploitable and map to MITRE ATT&CK.

### Part A: CVE → Exploit Mapping

**Question answered:** "Can I actually exploit this CVE?"

| Source | Content |
|--------|---------|
| ExploitDB | PoC scripts, verified exploits |
| Metasploit | Ready-to-use modules |
| Nuclei Templates | Detection + light exploitation |
| GitHub | Research PoCs |

**Output:** Each CVE gets `exploit` object with tool/command to use.

### Part B: CVE → MITRE ATT&CK Mapping

**Question answered:** "What type of attack is this? What comes next?"

**Key MITRE Tactics (in order):**
1. **Initial Access** (T1190) - Exploit public-facing app
2. **Execution** (T1059) - Run commands/scripts
3. **Persistence** (T1053) - Maintain access (cron, services)
4. **Privilege Escalation** (T1068) - Get root/admin
5. **Credential Access** (T1003) - Dump passwords
6. **Lateral Movement** (T1021) - Move to other systems
7. **Exfiltration** (T1048) - Extract data

**Output:** Each CVE gets `mitre` object with technique ID, tactic, and suggested next techniques.

---

## Phase 4: Attack Agent

### What to Build: `attack_agent.py`

**Purpose:** Execute attack chains using enriched JSON data.

### Agent Loop

```
1. READ enriched JSON
2. SELECT best initial access vector (highest success probability)
3. EXECUTE tool/exploit
4. CHECK result (success/failure)
5. IF success → PROCEED to next MITRE technique
6. IF failure → TRY alternative vector
7. DOCUMENT evidence at each step
8. REPEAT until objectives achieved or no more vectors
```

### Attack Tools Integration

| Phase | Tools |
|-------|-------|
| Vulnerability Scan | Nuclei, GVM |
| Web Attacks | sqlmap, XSStrike, Burp |
| Exploitation | Metasploit, custom scripts |
| Post-Exploitation | LinPEAS, linux-exploit-suggester |
| Credential Access | Mimikatz, mimipenguin |
| Lateral Movement | CrackMapExec, SSH, PSExec |

### Key Design Decisions

1. **Tool-based approach** - Agent orchestrates existing tools, doesn't write exploits
2. **MITRE-guided progression** - Follows attack phases in logical order
3. **Incremental saves** - Results saved after each step (like current nmap)
4. **Failure handling** - Agent tries alternatives when attacks fail

---

## Enriched JSON Structure

After all enrichment, each IP/service in JSON will have:

```
port: 443
service: nginx
version: 1.18.0
vulnerabilities:
  - cve: CVE-2021-23017
    severity: HIGH
    exploitable: true
    exploit:
      tool: metasploit/custom
      command: "..."
    mitre:
      technique: T1190
      tactic: Initial Access
      next_steps: [T1059, T1053]

attack_surface:
  initial_access_vectors: [...]
  post_exploitation_path: [...]
```

---

## Implementation Order

| Step | Module | Dependencies |
|------|--------|--------------|
| 1 | `vuln_enricher.py` | GVM installed, NVD API |
| 2 | `attack_mapper.py` | ExploitDB API, MITRE data |
| 3 | `attack_tools.py` | Metasploit, Nuclei, sqlmap installed |
| 4 | `attack_agent.py` | All above + LLM for decisions |

---

## Key Insight

**GVM/OpenVAS = Detection only** (finds vulnerabilities)  
**Metasploit/ExploitDB = Exploitation** (actually attacks)  
**MITRE ATT&CK = Strategy** (guides attack sequence)

All three are needed for a complete automated penetration testing pipeline.

---

## Neo4j Graph Architecture

### Why Neo4j?

Attack chains are naturally graphs. Neo4j enables:
- Query attack paths in one line
- Visualize full attack surface
- Store agent reasoning as connected thoughts
- Track execution state across the chain

---

### Complete Node Schema

#### Layer 1: Recon Data (from current JSON)

| Node Type | Properties | Description |
|-----------|------------|-------------|
| **:Domain** | name, registrar, created, expires | Root target domain |
| **:Subdomain** | fqdn, discovered_by | Discovered subdomains |
| **:IP** | address, type (ipv4/ipv6), cloud_provider | Resolved IP addresses |
| **:Port** | number, protocol (tcp/udp), state | Open ports |
| **:Service** | name, product, version, cpe | Running services |
| **:OS** | name, family, accuracy | Detected operating system |
| **:SSLCert** | cn, issuer, valid_from, valid_to | SSL certificates |

#### Layer 2: Vulnerability Data

| Node Type | Properties | Description |
|-----------|------------|-------------|
| **:CVE** | id, severity, cvss, description, published | Known vulnerabilities |
| **:Weakness** | cwe_id, name, description | Weakness type (CWE) |
| **:Misconfiguration** | type, description, risk | Non-CVE security issues |

#### Layer 3: MITRE ATT&CK

| Node Type | Properties | Description |
|-----------|------------|-------------|
| **:Tactic** | id, name, description | Attack phase (TA0001-TA0043) |
| **:Technique** | id, name, description, detection | Attack method (T1xxx) |
| **:SubTechnique** | id, name, parent_technique | Specific variant (T1xxx.xxx) |
| **:Mitigation** | id, name, description | Defense measures |

#### Layer 4: Exploitation

| Node Type | Properties | Description |
|-----------|------------|-------------|
| **:Exploit** | id, name, source, type, reliability | Exploit reference |
| **:Tool** | name, type, command_template | Attack tool (sqlmap, msf, etc.) |
| **:Payload** | type, platform, description | Shellcode/payload info |

#### Layer 5: Attack Execution

| Node Type | Properties | Description |
|-----------|------------|-------------|
| **:AttackChain** | id, name, created, status, goal | Overall attack plan |
| **:AttackStep** | id, order, status, started, completed | Single step in chain |
| **:Execution** | id, command, started, ended, exit_code | Tool execution instance |
| **:Output** | stdout, stderr, parsed_results | Execution output |
| **:Evidence** | type, data, screenshot, timestamp | Proof of exploitation |
| **:Session** | id, type, access_level, established | Obtained access (shell, etc.) |

#### Layer 6: Agent Reasoning

| Node Type | Properties | Description |
|-----------|------------|-------------|
| **:AgentThought** | id, content, timestamp, confidence | Single reasoning step |
| **:Decision** | id, choice, alternatives, reasoning | Agent decision point |
| **:Observation** | id, source, data, interpretation | What agent observed |
| **:Goal** | id, description, status, priority | Attack objectives |

---

### Relationship Schema

#### Recon Relationships
```
(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)
(:Domain)-[:RESOLVES_TO]->(:IP)
(:Subdomain)-[:RESOLVES_TO]->(:IP)
(:IP)-[:HAS_PORT]->(:Port)
(:Port)-[:RUNS_SERVICE]->(:Service)
(:IP)-[:RUNS_OS]->(:OS)
(:Service)-[:HAS_CERT]->(:SSLCert)
```

#### Vulnerability Relationships
```
(:Service)-[:HAS_VULNERABILITY]->(:CVE)
(:CVE)-[:CATEGORIZED_AS]->(:Weakness)
(:Service)-[:HAS_MISCONFIGURATION]->(:Misconfiguration)
```

#### MITRE Relationships
```
(:CVE)-[:ENABLES_TECHNIQUE]->(:Technique)
(:Technique)-[:BELONGS_TO]->(:Tactic)
(:Technique)-[:HAS_SUBTECHNIQUE]->(:SubTechnique)
(:Technique)-[:LEADS_TO]->(:Technique)  // Attack progression
(:Technique)-[:MITIGATED_BY]->(:Mitigation)
```

#### Exploitation Relationships
```
(:CVE)-[:EXPLOITED_BY]->(:Exploit)
(:Exploit)-[:USES_TOOL]->(:Tool)
(:Exploit)-[:DELIVERS]->(:Payload)
(:Tool)-[:CAN_PERFORM]->(:Technique)
```

#### Attack Chain Relationships
```
(:AttackChain)-[:TARGETS]->(:Domain)
(:AttackChain)-[:HAS_GOAL]->(:Goal)
(:AttackChain)-[:CONTAINS_STEP]->(:AttackStep)
(:AttackStep)-[:NEXT_STEP]->(:AttackStep)
(:AttackStep)-[:EXECUTES]->(:Technique)
(:AttackStep)-[:TARGETS_NODE]->(:IP|:Service|:Port)
(:AttackStep)-[:USES_EXPLOIT]->(:Exploit)
(:AttackStep)-[:HAS_EXECUTION]->(:Execution)
(:Execution)-[:PRODUCED]->(:Output)
(:Execution)-[:CAPTURED]->(:Evidence)
(:Execution)-[:ESTABLISHED]->(:Session)
(:AttackStep)-[:RESULT_SUCCESS|:RESULT_FAILED]->(:AttackStep)
```

#### Agent Reasoning Relationships
```
(:AgentThought)-[:FOLLOWED_BY]->(:AgentThought)  // Chain of Thought
(:AgentThought)-[:LED_TO]->(:Decision)
(:Decision)-[:CHOSE]->(:AttackStep)
(:Decision)-[:REJECTED]->(:AttackStep)
(:Observation)-[:TRIGGERED]->(:AgentThought)
(:Output)-[:OBSERVED_AS]->(:Observation)
(:Goal)-[:ACHIEVED_BY]->(:AttackStep)
(:Goal)-[:REQUIRES]->(:Goal)  // Sub-goals
```

---

### Graph Visualization

```
                                    ┌─────────────┐
                                    │   :Goal     │
                                    │ "Get Root"  │
                                    └──────┬──────┘
                                           │ ACHIEVED_BY
                                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          :AttackChain                                     │
│                     "devergolabs.com pentest"                            │
└──────────────────────────────────────────────────────────────────────────┘
           │                        │                         │
           │ CONTAINS_STEP          │                         │
           ▼                        ▼                         ▼
    ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
    │:AttackStep 1│─NEXT────▶│:AttackStep 2│─NEXT────▶│:AttackStep 3│
    │Initial Access│          │ Execution   │          │ Priv Esc    │
    └──────┬──────┘          └──────┬──────┘          └─────────────┘
           │                        │
           │ EXECUTES               │ EXECUTES
           ▼                        ▼
    ┌─────────────┐          ┌─────────────┐
    │:Technique   │          │:Technique   │
    │   T1190     │          │   T1059     │
    └──────┬──────┘          └─────────────┘
           │
           │ ENABLED_BY
           ▼
    ┌─────────────┐     EXPLOITED_BY    ┌─────────────┐
    │    :CVE     │────────────────────▶│  :Exploit   │
    │CVE-2021-23017│                     │  EDB-49970  │
    └──────┬──────┘                     └──────┬──────┘
           │                                   │
           │ HAS_VULNERABILITY                 │ USES_TOOL
           │                                   ▼
    ┌──────┴──────┐                     ┌─────────────┐
    │  :Service   │                     │   :Tool     │
    │ nginx 1.18.0│                     │  metasploit │
    └──────┬──────┘                     └─────────────┘
           │
           │ RUNS_SERVICE
           │
    ┌──────┴──────┐
    │   :Port     │
    │    443      │
    └──────┬──────┘
           │
           │ HAS_PORT
           │
    ┌──────┴──────┐
    │    :IP      │
    │15.160.30.163│
    └──────┬──────┘
           │
           │ RESOLVES_TO
           │
    ┌──────┴──────┐
    │  :Domain    │
    │devergolabs  │
    └─────────────┘
```

---

### Agent Loop with Neo4j

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AGENT EXECUTION LOOP                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. QUERY: "Find best initial access vector"                                │
│     ─────────────────────────────────────────                               │
│     MATCH (s:Service)-[:HAS_VULNERABILITY]->(c:CVE)-[:EXPLOITED_BY]->(e)    │
│     WHERE e.reliability = 'high'                                            │
│     RETURN s, c, e ORDER BY c.cvss DESC LIMIT 1                             │
│                                                                              │
│  2. CREATE: Attack step node                                                │
│     ───────────────────────────                                             │
│     CREATE (step:AttackStep {id: uuid, order: 1, status: 'executing'})      │
│     CREATE (step)-[:EXECUTES]->(technique)                                  │
│     CREATE (step)-[:USES_EXPLOIT]->(exploit)                                │
│                                                                              │
│  3. STORE: Agent reasoning (Chain of Thought)                               │
│     ─────────────────────────────────────────                               │
│     CREATE (t:AgentThought {content: "nginx 1.18.0 has high CVSS..."})     │
│     CREATE (prev_thought)-[:FOLLOWED_BY]->(t)                               │
│     CREATE (t)-[:LED_TO]->(decision)                                        │
│                                                                              │
│  4. EXECUTE: Run the tool                                                   │
│     ─────────────────────────                                               │
│     CREATE (exec:Execution {command: "...", started: timestamp()})          │
│     CREATE (step)-[:HAS_EXECUTION]->(exec)                                  │
│                                                                              │
│  5. STORE: Output and parse results                                         │
│     ───────────────────────────────                                         │
│     CREATE (out:Output {stdout: "...", parsed: {...}})                      │
│     CREATE (exec)-[:PRODUCED]->(out)                                        │
│     CREATE (obs:Observation {interpretation: "Shell obtained"})             │
│     CREATE (out)-[:OBSERVED_AS]->(obs)                                      │
│                                                                              │
│  6. UPDATE: Step status and create session if success                       │
│     ─────────────────────────────────────────────                           │
│     MATCH (step:AttackStep {id: $id})                                       │
│     SET step.status = 'success', step.completed = timestamp()               │
│     CREATE (sess:Session {type: 'reverse_shell', access: 'user'})           │
│     CREATE (exec)-[:ESTABLISHED]->(sess)                                    │
│                                                                              │
│  7. QUERY: "What's the next technique after T1190?"                         │
│     ───────────────────────────────────────────────                         │
│     MATCH (t:Technique {id: 'T1190'})-[:LEADS_TO]->(next)                   │
│     RETURN next                                                              │
│                                                                              │
│  8. LOOP: Create next step and repeat                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Key Queries for Attack Planning

**Find all attack paths to root:**
```cypher
MATCH path = (s:Service)-[:HAS_VULNERABILITY]->(:CVE)-[:ENABLES_TECHNIQUE]->
             (t:Technique)-[:LEADS_TO*1..5]->(goal:Technique {name:'Privilege Escalation'})
RETURN path
```

**Get agent's chain of thought for a decision:**
```cypher
MATCH (d:Decision {id: $decision_id})<-[:LED_TO]-(t:AgentThought)
MATCH chain = (start:AgentThought)-[:FOLLOWED_BY*]->(t)
RETURN chain
```

**Find what worked in past attacks:**
```cypher
MATCH (step:AttackStep {status: 'success'})-[:USES_EXPLOIT]->(e:Exploit)
MATCH (step)-[:TARGETS_NODE]->(service:Service)
WHERE service.product = $product AND service.version = $version
RETURN e, count(*) as success_count ORDER BY success_count DESC
```

**Visualize full attack chain execution:**
```cypher
MATCH (chain:AttackChain {id: $chain_id})-[:CONTAINS_STEP]->(step:AttackStep)
MATCH (step)-[:HAS_EXECUTION]->(exec:Execution)-[:PRODUCED]->(out:Output)
OPTIONAL MATCH (exec)-[:ESTABLISHED]->(sess:Session)
RETURN chain, step, exec, out, sess ORDER BY step.order
```

---

### Data Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  RECON JSON ──────▶ NEO4J (Domain, IP, Port, Service nodes)                │
│       │                                                                      │
│       ▼                                                                      │
│  GVM/NVD ─────────▶ NEO4J (CVE nodes + HAS_VULNERABILITY relations)        │
│       │                                                                      │
│       ▼                                                                      │
│  MITRE ATT&CK ────▶ NEO4J (Technique, Tactic nodes + mappings)             │
│       │                                                                      │
│       ▼                                                                      │
│  ExploitDB/MSF ───▶ NEO4J (Exploit, Tool nodes + EXPLOITED_BY)             │
│       │                                                                      │
│       ▼                                                                      │
│  AGENT PLANNING ──▶ NEO4J (AttackChain, AttackStep, Goal nodes)            │
│       │                                                                      │
│       ▼                                                                      │
│  AGENT REASONING ─▶ NEO4J (AgentThought, Decision, Observation)            │
│       │                                                                      │
│       ▼                                                                      │
│  TOOL EXECUTION ──▶ NEO4J (Execution, Output, Evidence, Session)           │
│       │                                                                      │
│       ▼                                                                      │
│  FULL GRAPH ──────▶ Complete attack history with reasoning chain           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Implementation Modules

| Module | Purpose | Writes to Neo4j |
|--------|---------|-----------------|
| `neo4j_loader.py` | Load recon JSON into graph | Domain, IP, Port, Service |
| `vuln_enricher.py` | Add vulnerabilities | CVE, Weakness |
| `mitre_mapper.py` | Add MITRE mappings | Technique, Tactic |
| `exploit_mapper.py` | Add exploits | Exploit, Tool |
| `attack_planner.py` | Create attack chains | AttackChain, AttackStep, Goal |
| `attack_executor.py` | Run tools | Execution, Output, Evidence |
| `agent_brain.py` | Agent reasoning | AgentThought, Decision, Observation |

