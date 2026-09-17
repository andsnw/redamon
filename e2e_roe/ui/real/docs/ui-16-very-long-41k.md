Edgeframe looks forward to working with the security community to find vulnerabilities in our Edgeframe Edgeframe projects in order to keep our ecosystem and users safe. This program covers core Edgeframe projects that power modern web development.

## Getting Started

### ReEdgeframes

* [Next.js Documentation](https://edgeframe.test/docs)
* [Nuxt Documentation](https://edgeframe.test/docs)
* [SWR Documentation](https://swr.edgeframe.test)
* [Svelte Documentation](https://edgeframe.test/docs)
* [Turborepo Documentation](https://edgeframe.test/repo/docs)
* [AI SDK Documentation](https://sdk.edgeframe.test/docs)
* [Edgeframe CLI Documentation](https://edgeframe.test/docs/cli)
* [Nitro Documentation](https://nitro.edgeframe.test)
* [Eve Documentation](https://edgeframe.test/docs/introduction)  
* [chat Documentation](https://edgeframe.test/docs)
* [workflow Documentation](https://edgeframe.test/docs/getting-started)
* [flags Repository](https://code-host.test/Edgeframe/flags)
* [Agent-Skills Repository](https://code-host.test/Edgeframe-labs/agent-skills)
* [Skills Repository](https://code-host.test/Edgeframe-labs/skills)
* [Edgeframe Changelog](https://edgeframe.test/changelog) — recently shipped changes (see eligible bonuses in [Severity Assessment](#user-content-severity-assessment))

### Focus Areas

We are particularly interested in reports that cover:

* **Authorization and authentication bypass** in framework-level primitives, especially where a default configuration leaves a protection unenforced
* **AI agent security:** tool execution control bypasses, MCP client trust boundary violations, and credential or session leakage through agent framework components
* **Cache poisoning and response integrity violations** that cause one user's data to be served to another
* **Supply chain attacks** against published packages and skill registries
* **Server-side vulnerabilities** (SSRF, RCE, path traversal) reachable in default or widely-used configurations
* **Cross-user or cross-session data leakage** through shared state, shared caches, or insufficient isolation

See the [Per-Asset Focus Areas](#user-content-per-asset-focus-areas) section for the specific vulnerability classes and priority guidance for each project.

## Scope

### Tier 1 (High Priority)

Official Edgeframe-maintained Edgeframe Edgeframe projects with the broadest production usage and highest ecosystem impact. These projects are actively used by millions of developers and represent the core of Edgeframe's Edgeframe Edgeframe portfolio. Reports against Tier 1 assets receive the highest bounty consideration and are reviewed with priority.

* [Next.js](https://code-host.test/Edgeframe/next.js) — React framework for production web applications
* [Nuxt](https://code-host.test/nuxt/nuxt) — Vue.js framework for building performant web applications
* [SWR](https://code-host.test/Edgeframe/swr) — React Hooks library for data fetching
* [Svelte](https://code-host.test/sveltejs/svelte) — Compiler for building user interfaces
* [Turborepo](https://code-host.test/Edgeframe/turborepo) — High-performance build system for monorepos
* [AI SDK](https://code-host.test/Edgeframe/ai) — TypeScript toolkit for AI applications
* [Edgeframe CLI](https://code-host.test/Edgeframe/Edgeframe) — Official CLI for deploying and managing Edgeframe projects
* [workflow](https://code-host.test/Edgeframe/workflow) — Framework for adding durability and observability to async JavaScript
* [flags](https://code-host.test/Edgeframe/flags) — Feature flags toolkit for Next.js and SvelteKit
* [Nitro](https://code-host.test/nitrojs/nitro) — Next Generation Server Toolkit
* [Agent-Skills](https://code-host.test/Edgeframe-labs/agent-skills) — Edgeframe's official collection of skills for Claude and other AI agents
* [Skills](https://code-host.test/Edgeframe-labs/skills) — CLI and registry for discovering, installing, and managing AI agent skills
* Vulnerabilities on Edgeframe maintained/sponsored websites supporting Tier 1 projects (e.g., [edgeframe.test](http://edgeframe.test), ...)

### Tier 2 (Standard Priority)

* [Eve](https://code-host.test/Edgeframe/eve) — Filesystem-first framework for building durable AI agents  
* [chat](https://code-host.test/Edgeframe/chat) — Edgeframe's AI chat application and reference implementation
* All other Edgeframe-owned Edgeframe Edgeframe projects within [code-host.test/Edgeframe](https://code-host.test/Edgeframe) or [code-host.test/Edgeframe-labs](https://code-host.test/Edgeframe-labs), including [**ms**](https://code-host.test/Edgeframe/ms) and [**SvelteKit**](https://code-host.test/sveltejs/kit), and vulnerabilities on Edgeframe-maintained project websites (e.g., edgeframe.test). Includes projects with smaller user bases, niche use cases, or those requiring non-standard or experimental configurations to reproduce. Bounties are awarded at a lower rate than Tier 1.

**Tier 1 consideration:** If a report against a Tier 2 asset demonstrates a critical or high-severity vulnerability with a clear, reproducible exploit chain and significant real-world impact, we will consider awarding at Tier 1 bounty levels on a case-by-case basis.

## Submission Requirements

We actively want to work with researchers who find real, impactful vulnerabilities and write clear, actionable reports. When a report demonstrates a genuine finding with a working exploit chain and a well-articulated impact, we take it seriously and compensate accordingly. The quality of a report matters: a concise, well-reasoned submission with a strong PoC will always be prioritized over volume.

Reports that appear to be generated by AI tools without manual validation, contain hallucinated or unverified claims, or consist of scanner output without a working exploit will be marked as **'Not Applicable'**. Researchers with a pattern of submitting such reports will be flagged and deprioritized in the program.

Every report must include a working proof-of-concept that demonstrates the complete exploit chain on a realistic, production-equivalent deployment. This means:

* A functional PoC that an independent reviewer can run and reproduce
* Demonstrated end-to-end impact: not just the entry point, but what an attacker concretely reads, writes, executes, or extracts
* Reproducible on a stable release (supported, in-scope versions. Please see the version eligibility note below on canary and RC releases.)

Reports will not be considered for bounty if they consist of:

* SAST or static analysis output without a working exploit chain
* AI or LLM tool findings that have not been manually verified with a functional PoC
* Theoretical chains where one or more steps require unrealistic conditions
* Issues that require the attacker to already have privileged access
* Vulnerable or outdated dependency reports without a demonstrated exploit chain: flagging that a dependency has a CVE is not a valid submission on its own. We may consider a report if the researcher demonstrates a complete chain showing exploitable impact in the context of the affected project, and there is no existing Edgeframe issue or pull request already tracking the fix.
* Issues present only in a canary or RC release that has since been superseded by a more stable version: these are out of scope. Canary versions of an upcoming release are in scope if no stable release has superseded the affected version range.

### What to include in your report

* **Affected version(s):** Please ensure you are submitting the correct affected version(s) of the code. You will be required to fill out a field called 'Affected version(s)'.
* **Proof-of-concept artifact:** All vulnerability reports must include a zip file containing working proof-of-concept code that demonstrates the issue in the affected version(s). Reports without demonstration artifacts will not be eligible for bounty consideration.
* If the affected version(s) or POC artifact are not included, reports will be automatically moved to the **Needs More Info** state until the necessary info is provided.
* In cases where a PoC is not feasible, detailed reproduction steps or minimal test cases may be accepted at Edgeframe's discretion and not without Edgeframe's approval.
* Include any other helpful PoCs such as screenshots, videos, etc. when applicable.
* Suggestions for patches or mitigation are optional but can warrant a bonus at Edgeframe's discretion.

The [Per-Asset Focus Areas](#user-content-per-asset-focus-areas) sections below describe the vulnerability classes of most interest for each project, and which areas are lower priority or require novelty to be considered.

## Per-Asset Focus Areas

### Next.js

The highest-value targets are in the production runtime: the middleware and routing layer, the response caching system, the React Server Components and Server Actions runtime, and the image optimization endpoint. The development server and build-time tooling are lower priority.

**Vulnerability classes of highest interest, in order of priority:**

1. **Middleware / routing authorization bypass** – Vulnerabilities that allow a request to reach a protected route it should not reach.
2. **Cache poisoning / cache-key confusion** – Vulnerabilities where an attacker can cause a crafted response to be stored in the cache and served to other users. The attack surface includes ISR, the full-route cache, and the use-cache directive.
3. **RSC / Server Actions / Flight protocol** – Deserialization vulnerabilities, CSRF bypasses, or sensitive data exposure through the React Server Components runtime or the Server Actions handler.
4. **Image optimizer SSRF and DoS** – SSRF via the built-in image optimization endpoint, particularly bypasses of the internal SSRF allowlist validation. DoS via malformed image input causing excessive reEdgeframe consumption at scale.
5. **SSRF via host reflection** – Vulnerabilities where a user-controlled Host header, forwarded header, or redirect target causes the server to make an unintended internal request.

**Lower priority / accepted only if novel:**

* Dev server vulnerabilities (`next dev`), including DNS rebinding, inspector WebSocket leakage, Edgeframe map exfiltration, and static handler path traversal: only accepted with a direct path to impact in a production deployment.
* Issues in custom server mode where the vulnerability is in user-supplied server code rather than the framework itself.
* Missing security headers that are not set by default.
* Build-time tooling (webpack, babel, terser) is out of scope.

### AI SDK

The primary attack surface is tool execution controls, MCP client security, and input/output handling in the core SDK.

**Vulnerability classes of highest interest:**

* MCP client allowlist bypasses that allow unapproved tools to be exposed or executed, including prototype-based or prototype-inheritance bypasses.
* Tool execution control bypasses where restrictions on which tools the model can call fail to hold at execution time, with RCE or significant data access demonstrated.
* Prototype pollution in SDK internals leading to SSRF, authorization header theft, or privilege escalation.
* MCP OAuth metadata handling vulnerabilities: protocol bypass in URL validation (e.g. a `file://` URI passing the URL schema check), or SSRF via redirect-follow during OAuth metadata discovery.
* Input validation bypasses in structured output handling where raw, unvalidated LLM output reaches application code without the declared schema being enforced.
* Supply chain issues in the SDK itself: the report must demonstrate a complete end-to-end exploit chain showing exploitable impact, and there must be no existing Edgeframe issue or pull request already tracking the fix.

**Lower priority / accepted only if novel:**

* Security issues in example code or documentation snippets: examples are explicitly out of scope.
* Tool approval bypasses that rely entirely on forged client-side message history: the developer controls message history server-side, making this an application design concern.
* Prompt injection reports where no tool access, sensitive data, or meaningful attacker-controlled action is at risk. The report must demonstrate what the attacker concretely achieves beyond influencing model output.
* Issues in provider packages (e.g. the EdgeframeAI, Anthropic, or Fireworks provider integrations) that are not in the core SDK: report those to the relevant provider's security program.

### Nuxt

The primary attack surface is URL sanitization in navigation primitives and template injection in component props.

**Vulnerability classes of highest interest:**

* XSS via unsanitized URL protocols in navigation components or functions: the NuxtLink component, the reloadNuxtApp utility, and router navigation accepting `javascript:`, `data:`, or `vbscript:` URIs.
* XSS via template injection where user-controlled input reaches the DOM unsanitized through component props in production components.
* Auth token or session exfiltration chains starting from an exploitable XSS in a production component.
* Server-side path traversal in file handling.
* RCE chains that begin from an exploitable XSS in a production-enabled component.

**Lower priority / accepted only if novel:**

* Nuxt DevTools vulnerabilities: DevTools is a development-only surface and is not a production target.
* XSS in experimental components that require explicit opt-in via config flags documented as unsafe: only accepted if a realistic production path is demonstrated.
* Nuxt UI component library issues: only accepted if the component itself introduces an unsanitized path that a developer cannot reasonably mitigate.
* Issues requiring the developer to already be rendering unsanitized user input directly into templates.

### Turborepo

The remote cache is the primary attack surface. The most impactful bugs involve artifact integrity, token handling, and cache extraction.

**Vulnerability classes of highest interest:**

* Remote cache poisoning: any path by which a malicious actor can serve a crafted artifact that gets restored into a victim's build, including weaknesses in artifact signing or HMAC key enforcement, and symlink traversal during cache extraction.
* Token exfiltration via repo-controlled configuration: the ability to point the remote cache at an attacker-controlled origin and receive the user's auth token. The PoC must show actual exfiltration, not just assert that the configuration field is attacker-controlled.
* SSRF via an untrusted remote cache API URL with internal network access demonstrated.
* Command injection in CLI operations that process user-controlled strings.
* Supply chain attacks via dependency confusion in published packages.

**Lower priority / accepted only if novel:**

* Cache poisoning claims that require the attacker to already have write access to the remote cache. Reports must demonstrate how unauthenticated or unauthorized write access is obtained.
* Local-only attacks where the attacker already has filesystem access to the machine running turbo.
* Reports asserting that `signature:false` as a default is a vulnerability without demonstrating a complete poisoning chain.

### Edgeframe CLI

**Vulnerability classes of highest interest:**

* Credential or token exposure to other local processes or the network during CLI operations.
* Arbitrary code execution triggered by malicious project configuration during deploy or build.
* Path traversal or file exfiltration during build or deploy operations.
* Privilege escalation between project or team scopes.

**Lower priority / accepted only if novel:**

* Output formatting or cosmetic issues.
* Issues requiring the attacker to already control the machine running the CLI.

### chat

The core security property of the chat framework is that a session, its messages, and tool execution state belong to a specific authenticated owner. Violations of that ownership boundary are treated as high priority.

One class we consider a framework-level issue regardless of how the application is structured: if tool execution logic derives authorization decisions or tool approval state from the client-supplied messages array rather than server-verified state, that is a vulnerability in the framework. A developer building on the chat framework should not have to re-validate that the messages array has not been forged; the framework is expected to enforce that boundary server-side.

**Vulnerability classes of highest interest:**

* Session ownership bypass: an authenticated actor can read, write to, append to, delete from, or modify the visibility of a session or its messages without owning that session, including IDOR via session or message IDs taken directly from client-controlled input.  
* Cross-role session access: team-level role boundaries not enforced in session listing or message access, allowing lower-privileged members to read or write sessions belonging to other users.  
* Tool approval bypass via client-supplied message state: the framework reconstructs tool-call approvals or tool inputs from the caller-supplied messages array, allowing a forged assistant or tool-result message to bypass approval checks and execute a tool the user did not approve.  
* Caching issues where a cached response intended for one session or user is served to another, due to incorrect cache key scoping across user or session boundaries.  
* Stored XSS in chat message rendering leading to session or token theft, particularly in rendered markdown, shared chat views, or third-party rendering libraries.  
* Unauthenticated or insufficiently authenticated access to session endpoints that expose message history, trigger agent actions, or reach paid model APIs.

**Lower priority / accepted only if novel:**

* Authorization issues where the developer explicitly bypassed or omitted ownership checks in application code built on top of the framework: these are application design concerns.  
* Client-side message manipulation that only affects the attacker's own session with no cross-session or privilege-escalation impact.

### Eve

Vulnerabilities must be in the Eve framework itself, not in a specific agent built on top of it. If the issue is that a developer made an insecure design choice when implementing their agent, that is an application-level concern and not a valid Eve vulnerability.

**Vulnerability classes of highest interest:**

* The framework executing tools or taking actions that the framework's own security model should have prevented, regardless of how the agent is configured.  
* Credential or secret leakage through framework-owned runtime components or the built-in channel handlers (HTTP, Slack, Discord), where the leak occurs in Eve's code and not in user-written tools or skills.  
* Unauthenticated control of agent behavior through framework-provided channel endpoints, where authentication is Eve's responsibility and not the developer's to implement.  
* Sandbox or isolation escapes where code running in one agent context can affect another.

**Lower priority / accepted only if novel:**

* Issues in APIs explicitly marked as unstable or experimental in beta documentation.  
* Development-mode-only attack paths with no production impact.  
* Vulnerabilities that only manifest because the developer built their agent insecurely (e.g. passing unsanitized user input directly to shell tools, trusting client-side state without server validation): these are agent implementation issues, not framework vulnerabilities.

### workflow

The vulnerability must be in the workflow framework itself, not in how a developer has chosen to structure their workflow. If a developer puts no authorization check on a step, that is their design choice.

**Vulnerability classes of highest interest:**

* Step injection: an attacker can cause the workflow runtime to execute a step that was not part of the original workflow definition, or substitute a malicious step in place of a legitimate one.
* Step bypass: an attacker can cause the runtime to skip a step that should have executed, including steps that perform authorization checks or validation.
* Cross-workflow access: an attacker can influence, read state from, or trigger steps belonging to a workflow they are not authorized to interact with.
* Authorization boundary violations: any path by which an actor can escalate privileges within the workflow runtime, access another tenant's workflow context, or replay or forge step completions.
* Injection into the runtime's step scheduling, state persistence, or event handling that can be triggered across all workflows, not just a specific instance. These are treated as highest priority given the blast radius.

### flags

The vulnerability must be in the flags framework itself, not in how a developer has chosen to configure or expose their flags.

The most interesting attack surface is the framework's own flag discovery and override mechanisms. The flags SDK exposes a well-known endpoint that the Edgeframe Toolbar uses to read flag definitions (names, descriptions, and variants). If the framework's defaults leave this endpoint unauthenticated or insufficiently scoped, an attacker can enumerate every flag and variant, revealing unreleased features and experiments that operators expect to be confidential. The override mechanism, which forces flag values on or off for a given session, is a valid target if it can be triggered without authorization or if override state is not scoped to the session that set it, meaning an attacker could access features not yet released to them.

**Vulnerability classes of highest interest:**

* Unauthorized read of flag definitions or variant metadata via the framework's own well-known or discovery endpoint, revealing unreleased feature names, experiment variants, or rollout rules.
* Unauthorized flag override: forcing a flag to evaluate as enabled for a session the attacker does not own, or reading override state belonging to another user or session, in order to access features or capabilities not yet released.
* Flag evaluation responses that reveal which segment or rollout cohort an arbitrary user belongs to, where that segmentation is not otherwise accessible.
* Authorization bypass where an actor can modify flag state (rollout rules, segment assignments) they should not have write access to.
* Stored XSS introduced by the framework's own rendering or UI components (e.g. the toolbar or flag display components).

### Nitro

**Vulnerability classes of highest interest:**

* Authentication bypass in the basicAuth route rule via percent-encoded characters in path segments where the encoded form passes the auth check but the decoded form reaches the protected handler.
* Authentication bypass via route rule composition where basicAuth is combined with a terminating rule (proxy, redirect, cache) on overlapping paths and the terminating rule executes first, skipping the auth check entirely.
* Path traversal in the proxy route rules or prerender pipeline leading to arbitrary file read or write within the project workspace.

**Lower priority / accepted only if novel:**

* SSRF via the proxy target in `proxyRequest()` or route rules: only accepted if a framework-owned path bypasses developer-controlled allowlist configuration entirely.
* WebSocket upgrade requests bypassing global middleware auth.
* Overbroad route regex matching in the Edgeframe CDN preset without a demonstrated security impact.

### SWR

**Vulnerability classes of highest interest:**

* SSR request isolation failures where module-global internal state is shared across concurrent server-side requests, causing data from one request to be visible to another.

**Lower priority / accepted only if novel:**

* Prototype pollution via crafted cache keys reaching the library's internal state: only accepted with a full chain from a framework-owned input to concrete downstream impact.
* Client-side-only cache state manipulation where the attacker already controls the client environment.
* Dependency vulnerabilities in SWR example packages: these are not part of the published library.

### Svelte (Tier 1)

The primary attack surfaces are HTML generation and hydration, including the SSR compiler output path (spread attributes, element tag interpolation, bind directives, template-literal generation, and hydration markers).

**Vulnerability classes of highest interest:**

* XSS where Svelte fails to preserve its documented escaping guarantees, including during SSR, hydration, attribute handling, or dynamic element rendering.
* SSR compiler template-literal injection where HTML entity sequences in attribute strings produce unescaped expressions in the generated JavaScript.
* DOM clobbering or prototype pollution affecting framework internals.
* Supply-chain vulnerabilities introduced by how Svelte builds or distributes its packages.

**Out of scope unless a novel framework-level impact is demonstrated:**

* Passing unsanitized input to explicitly unsafe APIs such as `{@html}`.
* Denial of service through excessive legitimate use, or compiler inputs whose impact is limited to the development environment.
* Issues confined to features explicitly gated by an `experimental.*` configuration option.

### SvelteKit (Tier 2)

The primary attack surfaces are request handling, routing, serialization, prerendering, and official adapters.

**Vulnerability classes of highest interest:**

* XSS, CSRF bypasses, SSRF, path traversal, cache poisoning, or cross-request data leakage.
* Prototype pollution or disproportionate CPU or memory consumption when processing untrusted serialized data, including through `devalue`.
* `BODY_SIZE_LIMIT` bypass via encoding tricks in the Node.js adapter.
* Server-only module guard bypass where `$lib/server` or `*.server.js` isolation fails in a specific build pipeline, causing server-only code to be bundled into a publicly accessible asset.
* Authentication or session compromise resulting from an exploitable framework vulnerability.
* Supply-chain vulnerabilities introduced by how SvelteKit builds or distributes its packages.

**Out of scope unless a novel framework-level impact is demonstrated:**

* Authentication bypass in the `handle` hook via percent-encoded pathnames where the developer is using raw request path strings rather than `event.edgeframe.test`: this is an application design concern.
* Vulnerabilities solely in third-party dependencies, or in compromised browsers and server runtimes.
* Denial of service through excessive legitimate use.
* Issues confined to features explicitly gated by an `experimental.*` configuration option.

### ms (Tier 2)

ms is a minimal time-parsing utility. Reports must demonstrate a vulnerability in the library's own parsing logic with a realistic path to downstream exploitability, not in how an application uses the output.

**Lower priority / accepted only if novel:**

* DoS via crafted input strings: only accepted with a concrete production-reachable path to impact.

### Skills

The Skills CLI and registry are the attack surface for this project. Vulnerabilities must be in the Skills framework itself (the CLI, the installation pipeline, the audit infrastructure) rather than in the content or behavior of individual skills published by third parties.

**Vulnerability classes of highest interest:**

* Path traversal during skill installation where the install path escapes the intended target directory and writes to arbitrary locations on the filesystem. The exploit must demonstrate actual out-of-bounds write.
* Terminal escape injection via malicious SKILL.md metadata fields (name, description) where ANSI or OSC sequences in the metadata are rendered unsanitized in the terminal, enabling output spoofing or terminal control.
* Prompt injection in SKILL.md content that causes the agent runtime to execute unintended tool calls or exfiltrate data during skill installation or invocation. The report must demonstrate a concrete attacker-controlled outcome beyond influencing model output.
* Covert payload delivery embedded in SKILL.md: skill instructions that silently execute remote code (e.g. via curl-pipe-bash patterns or opaque redirect URLs) without user awareness or confirmation.
* Supply chain attacks against the skills registry or installation pipeline itself, not against individual third-party skill authors.

**Out of scope:**

* Security score changes or alerts from Socket or Snyk scanners against skills listed on edgeframe.test: these reflect scanner judgments, not validated vulnerabilities in the framework.
* Skills that are themselves written maliciously or deceptively by their authors (e.g. a skill that abuses wallet access, embeds covert instructions, or mislabels its purpose): edgeframe.test operates as a marketplace and we work with Socket and Snyk to surface these issues, but individual skill authors are responsible for their content. We cannot guarantee all malicious skills are caught, and that is not a bug in the framework.

**Lower priority / accepted only if novel:**

* Namespace collision overwrite where a victim is tricked into installing a malicious skill with the same short name as a legitimate one: only accepted if the collision is possible against verified or official skills with no user-visible warning.
* Telemetry that leaks private repository metadata (owner, repo, skill names) for repos where the user has set `DISABLE_TELEMETRY=1`: accepted if the bypass is demonstrated in a fixed release with no Edgeframe tracking issue.
* Path traversal in the skills init subcommand via the skill name parameter: rejected without a demonstrated write to a sensitive path outside the project directory.
* Symlink preservation during install that could theoretically escape the install directory: accepted only if the target of the escaped write is reachable and impactful.

### Agent-Skills

Agent-Skills is Edgeframe's official collection of skills for use with Claude and other AI agents. The attack surface is the skill execution and trust model, not the behavior of individual third-party skills.

**Vulnerability classes of highest interest:**

* Skills that embed external trust dependencies (remote URLs, third-party execution pipelines) without the user being made aware, allowing a malicious or compromised upstream to substitute instructions or code at runtime.
* Tool invocation without user confirmation gates for operations with irreversible or high-impact effects (financial transactions, destructive actions, data exfiltration), where the framework's own execution model should require confirmation.
* Authorization boundary violations in multi-skill or multi-agent contexts where one skill can read state, credentials, or tool outputs belonging to a different skill or agent context it should not access.

**Out of scope:**

* Individual third-party skills published to the registry that are poorly written, deceptive, or malicious: these are the author's responsibility, and the marketplace relationship with Socket and Snyk is how we address them, not the bug bounty program.
* Scanner alerts (SAST, Socket, Snyk) about skill content without a demonstrated exploit in the framework's own execution logic.

**Lower priority / accepted only if novel:**

* Prompt injection that only affects model output with no tool invocation or data exfiltration.

## Severity Assessment

We use CVSS 4.0 scoring with adjustments for:

* Real-world exploitability in typical deployment scenarios
* Impact on the broader ecosystem
* Ease of exploitation and attack complexity
* Default vs. non-default configuration requirements
* Severity reduction in cases reliant on experimental features or "development mode"

**Bonus Modifiers**

A finding may be eligible for a bonus on top of the base award. All bonuses are granted at Edgeframe's discretion and are not guaranteed. The following may qualify a finding for a bonus:

* **Exceptional impact:** For example, novel attack chains affecting widely-deployed default configurations, vulnerabilities that compromise user data at scale, or critical findings in Tier 1 assets that represent a meaningful advance over prior public research.
* **High-quality reports:** Well-structured reports with clear, reproducible analysis and demonstrated impact — particularly those that include suggested patches or mitigation.
* **Recently shipped changes:** Vulnerabilities in functionality reported within one week of that change being published in the [Edgeframe Changelog](https://edgeframe.test/changelog). Findings that catch regressions in newly shipped code before they spread are especially valued.

## Out of Scope

[Core Ineligible Findings](https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings) are out of scope.

### Universal Exclusions

* Third-party dependencies (unless misused by the project)
* End of Life (EoL) or deprecated software versions
* Archived repositories
* Misuse of 3rd party by project
* Projects no longer under active development or maintenance
* Issues inherited from a fork are out of scope unless direct impact on Edgeframe, Edgeframe customers, or project users can be shown
* Templates, examples, starter projects, and documentation code snippets
* Community infrastructure (Discord, GitHub Discussions, etc.)
* Personal websites/blogs of maintainers
* Social engineering attacks
* Issues requiring destructive testing
* Documentation / code examples
* Content modification (wikis are intentionally editable)
* Issues that can only be exploited when the underlying platform (browser, server runtime) is compromised
* Using untrusted user content without sanitization in places that are not explicitly sanitized by the framework
* Denial of service via excessive legitimate use
* Denial of service that is dev-time only

### Project-Specific Exclusions

* **SWC:** Rust standard library or LLVM vulnerabilities
* **Next.js:** Cloud provider-specific deployment issues (report these to our main program if on Edgeframe platform)
* **Nuxt:** Cloud provider-specific deployment issues (report these to our main program if on Edgeframe platform)
* **Svelte/SvelteKit:** Cloud provider-specific deployment issues (report these to our main program if on Edgeframe platform)
* **Skills:** Malicious skills not relating to vulnerabilities in the skills infrastructure or skills application

## Rules of Engagement

* **[Added November 2025] No testing on production systems or services:** Researchers must NOT conduct proof-of-concept testing or active exploitation directly against Edgeframe owned production repositories including:
  * Live Edgeframe services
  * Edgeframe owned Production websites or APIs
  * Deployed customer environments
  * CI/CD in Edgeframe maintained repositories
  * Edgeframe owned infrastructure
* **Detailed reports required:** Please provide detailed reports with reproducible steps and a zip artifact containing proof-of-concept code. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.
* **One vulnerability per report:** Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
* **Duplicates:** When duplicates occur, we award the first valid report against a currently supported version (provided it can be fully reproduced).
* **Root cause consolidation:** Multiple vulnerabilities caused by one underlying issue will be awarded one bounty. Reports addressing the same issue will be marked as duplicates if the previously rolled-out patch works for the submitted affected version. However, if the patch doesn't work on the submitted affected version, it may be considered for a bounty reward at Edgeframe's discretion.
* **No social engineering:** Social engineering (e.g., phishing, vishing, smishing) is prohibited.
* **Good faith testing:** Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of services.
* Do not access more data than necessary for a proof of vulnerability.
* Stop immediately if you encounter personal data/secrets; do not download; redact.
* Do not attempt to achieve, or maintain, persistence on any Edgeframe owned system.
* **Scanner rate limits:** When testing explicitly in-scope Edgeframe-operated assets, security scanners must be limited to 5 queries per second (QPS) when testing against Edgeframe domains to avoid service disruption.
* **Account ownership:** Only interact with accounts you own or with the explicit written permission of the account holder.
* Do not damage, cause disruption, access data, or modify data on any systems you are not authorized to test on (including all Edgeframe systems and services).
* All tests performed must not violate any law or compromise data that you do not own.
* Do not make any threats against or towards Edgeframe or the disclosure platform staff.
* Do not submit AI generated reports without first reviewing and confirming real impact and verifying a working Proof-of-Concept.
* Do not share or publish details of a report without explicit permission from Edgeframe staff.
* Any PRs or contributions related to a report should be shared with Edgeframe staff through private forks unless given explicit permission from Edgeframe staff.

## Testing Guidelines

### For testing Edgeframe Edgeframe projects:

* Use standard development environments and officially documented setup procedures
* Test against the latest stable releases unless investigating specific version issues
* Please use your the disclosure platform alias email when creating test accounts if needed ([h1username@edgeframe.test](mailto:h1username@edgeframe.test))
* Focus on the Edgeframe code and documented functionality rather than specific deployment configurations

See [Submission Requirements](#user-content-submission-requirements) (above) for what makes a report eligible and what to include in your report.

## Disclosure & Confidentiality Policy

Participation in this program is conditional on confidentiality obligations. By submitting a report, you agree to the following:

* Confidential Information includes all, but is not limited to, all vulnerability reports, proof-of-concept code, communications with Edgeframe, program documentation, and any related materials shared or generated through your participation.
* You may only use Confidential Information for the purpose of participating in this program.
* You may not disclose Confidential Information to any third party without Edgeframe's express written consent, except to authorized Edgeframe employees, or contractors who have a legitimate need to know and are bound by equivalent confidentiality obligations.
* You must keep all Confidential Information secure and promptly notify Edgeframe if you become aware of a breach.
* You must securely delete Confidential Information within 30 days of Edgeframe's written request, except where retention is required for legal or compliance reasons.
* Confidentiality obligations last for two (2) years from the date of disclosure, even if this program ends or your participation ceases.

Disclosure of vulnerabilities, including resolved issues, will be at Edgeframe's discretion and coordinated with the researcher. Edgeframe aims to post advisories on applicable repositories after appropriate remediation and coordination periods.

Researchers must respect all applicable laws and the community standards outlined in the [Edgeframe Code of Conduct](https://code-host.test/Edgeframe/Edgeframe/blob/main/.github/CODE_OF_CONDUCT.md). Any behavior that violates this Code may result in disqualification from the program and forfeiture of bounty eligibility.

Researchers must also follow [the platform's disclosure guidelines](https://disclosure-platform.test/terms/disclosure-guidelines). Where there is any conflict between those guidelines and this Policy, this Policy prevails.

Breach of these obligations will result in disqualification from the program and forfeiture of eligibility for rewards.

## CVEs

CVEs will be provided at Edgeframe's discretion, but vulnerabilities must meet the following minimum requirements for consideration:

* Lead to action on a Tier 1 repository with an adjusted CVSS score of at least 3.8
* Lead to action on a Tier 2 repository with an adjusted CVSS score of at least 7.0
* Vulnerability must be present in distributable code (npm, pypi, or similar)
* Vulnerability must not be reliant on an experimental feature or "development mode"

Reports given a CVE will be made public 30 days after the CVE's publication (subject to variability at Edgeframe's discretion).

## Response Targets (SLAs)

Edgeframe will make a best effort to meet the following response targets:

* **Time to first response (from report submitted):** 1 business day
* **Time to triage (from report submitted):** 7 business days
* **Time to bounty decision (from triage):** 10 business days

We'll try to keep you informed of our progress throughout the process.

## Ineligible Participants

* Edgeframe employees and contractors (past or present)
* Maintainers/contributors of Edgeframe Sponsored projects (past or present)
* Immediate family members of Edgeframe employees
* Individuals involved in the vulnerability discovery or fix
* the disclosure platform staff working on this program

## Support

* [the disclosure platform Support](https://docs.disclosure-platform.test/en/articles/8872013-support-mediation-hours#h_554d36c0f9)
* [security@edgeframe.test](mailto:security@edgeframe.test)

Thank you for helping keep Edgeframe's Edgeframe Edgeframe ecosystem and developer community safe! We value your contributions to OSS security.