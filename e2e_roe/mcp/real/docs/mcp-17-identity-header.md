# Disclosure Policy
* Please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

# Program Rules
* Please **provide detailed reports with reproducible steps**. If the report is not detailed enough to reproduce the issue, the issue may not be marked as triaged.
* Submit **one vulnerability per report** unless you need to chain vulnerabilities to provide impact.
* When **duplicates** occur, we only triage the first report received (provided that it can be fully reproduced).
* Multiple vulnerabilities caused by one underlying issue will be treated as **one** valid report.
* Make a **good faith** effort to avoid privacy violations, destruction of data, and interruption or degradation of our service. 
* Only interact with accounts **you own** or with explicit permission of the account holder.
* **Employees and contractors may not participate.** Employees and contractors are strictly prohibited from participating in the Program, and must not share non-public information with external security researchers to circumvent this restriction.
* **Report RCE immediately; no lateral movement.** If you achieve remote code execution, stop further exploitation and submit a report right away (no pivoting, privilege escalation, persistence, or internal scanning).
* **Stop and report upon PII access.** If you encounter personal data (or credentials/session tokens that grant access to it), stop testing that vector and report immediately.
* **Do not disrupt services.** Avoid denial-of-service testing (including load testing, stress testing, traffic floods, and resource-exhaustion techniques) and any activity that could materially degrade availability.
* **Don't mass-create accounts.** Avoid creating large numbers of accounts for testing across our applications and services.
* **Do not destroy or alter data.** Do not delete, modify, corrupt, or encrypt any data you access or discover during testing.

# Test Account and Resource Creation
If your research involves creating accounts or records on our platforms, follow these rules so we can track and clean up test data.

* **Naming:** Prefix all test accounts and resources with `h1-<your-h1-username>`. For email-based signups, use `h1-<your-h1-username>@disclosure-platform.test`. Accounts that can't be tied back to a researcher may be treated as unauthorized access.
* **Disclosure:** List every account, record, or resource you created during testing in your report. Include emails, user IDs, partner IDs, or any other identifiers. Reports missing this information may be closed without review.
* **Business portals:** Our partner, supplier, and integrator portals create real business records. Be aware that signups on these portals generate production data. Keep test accounts to the minimum needed to demonstrate your finding.
* **Cleanup:** We delete test accounts and records after triage. If you need something to stay active for validation, say so in your report.

# Excluded Submission Types
* Google Maps API key disclosure
* Fingerprinting / banner disclosure on common/public services
* Public JIRA service desk URLs
* Incomplete, missing or misconfigured DMARC
* Mass content submission, account creation or spamming
* Disruption of service either through DOS attacks, exploitation of performance problems, or trying to fill up a database
* Vulnerabilities affecting users of outdated browsers or platforms.
* Social engineering
* Attacks requiring physical access to locations or properties
* Exploits against mobile applications requiring physical access to the device or that require warranty-voiding actions (e.g., rooting the device)
* Unconfirmed Reports from Automated Vulnerability Scanners
* Self-XSS / Self-Exploitation
* Leaked User Credentials (e.g. from password dumps)
* Vulnerabilities on third-party libraries without showing specific impact to the target application (e.g. a CVE with no exploit)
* Zero-day vulnerabilities in third-party software without demonstrated impact
* Missing DNSSEC
* Issues related to SSL certificates (Missing SSL/TLS or weak cipher configurations)
* IDOR/BOLA reports where the identifier is designed as a cryptographically secure bearer token (e.g., shopping cart IDs, one-time tokens). Access via possession of an unguessable token is not a vulnerability if there's no way to enumerate or predict the token without already compromising a user's session.
* Account/email enumeration via timing differences, response discrepancies, or public APIs (including but not limited to: GraphQL checkPartnerEmailNotInUse query, Firebase Identity Toolkit API, password reset endpoints)

# Test Plan
* Users are able to sign up for a free account through our website
* Please use your **hacker email alias** when testing (h1username@wanderlist.test)
* Claim credentials (when applicable) for additional testing

# Session Layer: HTTP Headers
Researchers should add headers to requests such as: 
* "X-Researcher-Research: [H1 username]"

Thank you for helping keep Wanderlist and our users safe!
