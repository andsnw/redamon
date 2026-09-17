# Program Rules
- Do not test on production (https://test.tessellate.test). For access to the bug bounty instance, please email `bug-bounty` at our domain, and provide your the disclosure platform handle.
- Do not message support chat on https://test.tessellate.test. 
- Please provide [detailed reports](https://docs.disclosure-platform.test/en/articles/8475116-quality-reports), along with [attack scenario](https://bughunters.tessellate.test/learn/improving-your-reports/how-to-report/6379261818306560/write-down-the-attack-scenario). If the report is not detailed enough to reproduce the issue, the issue may not be marked as triaged.
- Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
- When duplicates occur, we only triage the first report received (provided that it can be fully reproduced).
- Only interact with accounts you own or with explicit permission of the account holder.

# Focus Areas
- Cross-tenancy (cross-workspace) data leakages
- Broken access controls
- AuthN/AuthZ on all interfaces - web, API, CLI, MCP, etc
- AuthZ within AI agent interfaces
- Container escapes
- Remote code execution (excluding kernel environments)
- XSS on core app domain (not in cell outputs)
- AI security impacting customer data
- Input sanitization
- [Tessellate API](https://learn.tessellate.test/docs/develop-logic/Tessellate-api/overview)

# Out-of-Scope
- [the disclosure platform Core Ineligible Findings](https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings)
- Within kernel environments (e.g. in Python or SQL cells): remote code execution, arbitrary SQL execution, or filesystem access
- JavaScript execution on cell output domains (*.tessellate.test)
- Access to product features from a different tier
- User subscription upgrade or cancel flow
- Non-security bugs, or bugs without practical impact to confidentiality, integrity, or availability

Note: The app allows you to be logged into multiple user accounts and orgs at the same time. To properly test cross-org authorization, you need to start with two separate browsers or profiles, ensure you're fully logged out on both, then on each browser log in with a different email address. Ensure that the attacker's email address isn't a member of the target org.

Thank you for helping keep Tessellate Technologies and our users safe!
