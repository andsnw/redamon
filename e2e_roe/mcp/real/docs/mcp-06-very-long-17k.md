# Instructions for creating a Growthdesk trial portal:
- Anyone may create a trial portal by navigating to: https://offers.growthdesk.test/free-trial. When signing up, please use your @disclosure-platform.test email address.
- All available functionality may be tested with the exception of email sends to email addresses you do not own. Please note, sending phishing attacks or spam from a portal will be grounds for permanent disqualification.
- With a trial account, it is possible to create an API key to send API requests. Follow [these instructions](https://developers.growthdesk.test/docs/guides/apps/authentication/intro-to-auth) for creating an API key. API requests should fall within these [API usage guidelines](https://developers.growthdesk.test/docs/guides/apps/api-usage/usage-details).
- Information about Growthdesk APIs, including example requests, is available at: https://developers.growthdesk.test/docs/api/overview

## Beta Features:
We encourage researchers to test and submit any bugs or vulnerabilities you may identify within beta features. To learn more about opting your account into beta features, check out our KB reference [here](https://knowledge.growthdesk.test/account-management/opt-your-Growthdesk-account-into-a-public-beta-feature).

---
# Special Reward and Bonus (CTF Challenge)
We created a portal with 1 contact record in the CRM. The record has 2 properties (`firstname` and a custom sensitive property called `super_secret`) that contain flags you need to obtain for this capture the flag challenge. Your task is to find permission-related vulnerabilities to bypass access controls (without any social engineering, user interaction, or brute-forcing) and read the `firstname` flag for a $15,000 USD special reward. Optionally, you may attempt to obtain the second `super_secret` flag for an additional $5,000 USD bonus, for a total of $20,000 USD potential reward.

The target domain for this challenge is `test.growthdesk.test` and the target portal ID is `46962361`. **DO NOT attempt to access other portals you don’t own.** In order to be awarded the bounty, you must:
1. Provide the property name and value of the flag(s) obtained. For example: firstname = <contact’s first name>, super_secret = <contact’s super secret info>
2. Provide detailed reproduction steps so we can successfully validate the finding.
3. Email your submission ID to the email address specified in the contact record’s `email` property with the subject `Growthdesk CTF Challenge`.

The first valid submission will be awarded the special reward. At that time, the CTF challenge will be paused while we remediate the finding and improve our defenses. Once done, we will modify the flags, make an announcement that we’re resuming the challenge, and update our bounty brief to indicate that the CTF is open again.

**_The standard Growthdesk bug bounty program rules apply. Please take the time to read the entire bounty brief before attempting this challenge._**
**_Growthdesk reserves the right to stop the CTF challenge, special reward, and bonus at any time without prior notice and reason._**

---

# Focus Areas
## Authentication flows
We highly encourage researchers to test various authentication flows including but not limited to:
- Signup (with email, Google, Apple, Microsoft)
- Login (with email, SSO, Google, Apple, Microsoft)
- MFA
- Account recovery / password reset
- OAuth

Researchers should approach these areas with a creative and critical mindset, exploring potential vulnerabilities that may lead to user account takeover and/or unauthorized access of data. Our goal is to ensure that our authentication mechanisms not only comply with industry standards but also demonstrate strong resilience against emerging threats and sophisticated attack techniques.

## High impact findings
Overall, we are most interested in critical vulnerabilities that allow access to customer CRM records and sensitive (PHI and PII) data, Growthdesk’s corporate data, and our internal network. We highly encourage researchers to look for:
- Vulnerabilities (like cross-site scripting) that may lead to user account takeover
- Cross-portal data leakage and access; i.e. if you are authenticated and authorized to access portal A, you should not be able to read/modify data in portal B, unless you have also been authorized to that portal
- Server-side code execution vulnerabilities
- Sensitive data exposure

# Ratings and Rewards
For the initial prioritization/rating of findings, this program will use the [the Common Vulnerability Scoring System (CVSS)](https://disclosure-platform.test/vulnerability-management/what-common-vulnerability-scoring-system-cvss). However, it is important to note that in some cases a vulnerability priority will be modified due to its likelihood and impact. In any instance where an issue is downgraded, a full, detailed explanation will be provided to the researcher.

To maximize your reward and minimize the payout time frame, please make sure to include the following in your report:
- An attack scenario: Provides context and demonstrates how the vulnerability can be exploited in real-world conditions.
- Clear reproduction steps: Helps ensure that the vulnerability can be consistently and reliably demonstrated.
- Recommended fix: Speeds up the mitigation process and reduces the time that the system remains exposed. Providing a practical solution also showcases the researcher’s understanding of the issue which enhances the credibility of the report.

## Critical Severity - Reward Tiers
Every finding that meets the Critical severity bar is assigned to one of the reward tiers below, based on the blast radius and demonstrated impact of the vulnerability. These tiers apply the same impact-and-likelihood logic used in our XSS Severity Guidelines. Tier assignment is based on the impact actually demonstrated in the report; theoretical or unproven escalation is rated on the impact shown. A single root cause is rewarded once.

We reserve the right to grade a finding above or below these tiers at our discretion where we deem it necessary. In any case where we do, a full, detailed explanation will be provided to the researcher. We will otherwise strive to follow these tiers in as many cases as possible, in order to be transparent about how we reward Critical findings.

| Tier | Reward | Impact | Success Conditions | Example |
|---|---|---|---|---|
| **C1 - Elevated Critical** | $5,000 to $10,000 | Compromise of Growthdesk internal systems, or automatic compromise of many organizations in a single attack. Includes remote code execution on Growthdesk systems, access to source code, internal networks, CI/CD, production databases, or infrastructure credentials. | No prior knowledge of, or access to, a target is required. The attack compromises Growthdesk's own systems or fires across organizations automatically, without victim interaction. | Server-side remote code execution on a Growthdesk-operated rendering pipeline; unauthorized access to Growthdesk source code or internal source-control; SQL injection escalated to local file read on production; or read access to a production database. |
| **C2 - Standard Critical** | $3,000 to $5,000 | Compromise of arbitrary customers or portals, executed per target or through a multi-step chain rather than automatically platform-wide. Includes cross-portal data access, arbitrary-user account takeover, and financial/payment account takeover. | Exploitable against arbitrary customers with no prior relationship, but the attack is run against each target or assembled through a chain rather than firing across the platform on its own. | Zero-click account takeover of an arbitrary Growthdesk user; cross-portal read or write access to another customer's CRM/sensitive data; takeover of a user's connected payment-processor account; or theft of OAuth authorization codes leading to account takeover. |

**For Elevated Criticals.** Please ensure you do not access or alter internal systems or data belonging to other clients. Use a minimally disruptive proof-of-concept (PoC) to demonstrate the vulnerability.
**Chained findings.** Where a report chains multiple issues to reach Critical impact, the tier reflects the impact of the full chain, not the individual components.


# In Scope Features
### Customer portal
_(1)_ The customer portal feature is in scope. However, testing on live customer portals is prohibited without explicit customer authorisation. Please set up your own instance in your test Growthdesk account. For instructions, navigate to: [https://knowledge.growthdesk.test/inbox/set-up-a-customer-portal](https://knowledge.growthdesk.test/inbox/set-up-a-customer-portal)

### Customer connected domain
_(2)_ Growthdesk Marketing and CMS customers often host content on the Growthdesk platform. Customer connected domains are in scope and CNAME'd to a subdomain like:
- groupxx.sites.growthdesk.test, where XX and YY are the numeric identifiers for the content path.

# In Scope Vulnerabilities
In general, vulnerabilities thought to be introduced by Growthdesk's hosting platform, and therefore may affect multiple Growthdesk customers, are in-scope for this program. Please report those here. Vulnerabilities that are not Growthdesk-introduced will still be investigated and will be reported to the affected customer, but they are not rewardable.

## Cross-site scripting (XSS)
XSS found while authenticated to the app are only eligible for a reward if it executes in the context of growthdesk.test. XSS found on [default system domains](https://knowledge.growthdesk.test/inbox/set-up-a-customer-portal) (eg. _hs-sites_ or _Growthdeskpagebuilder_) are only eligible for a reward if all of the below criteria are met:
1. XSS also executes on the connected domain
2. The XSS was introduced by Growthdesk

We've received XSS submissions on customer sites caused by a vulnerable HubL or JavaScript code written by the customer in the [Design Manager](https://knowledge.growthdesk.test/design-manager/a-quick-tour-of-the-design-manager). Those are not rewardable.

_We will make exceptions to these rules for any XSS submitted with an exploit that shows clear security impact to the Growthdesk platform._

### XSS Severity Guidelines

The following table outlines the internal guidelines we have established to grade the severity of Cross-Site Scripting (XSS) vulnerabilities submitted to this program. These guidelines apply only to XSS submissions that meet the in-scope eligibility criteria defined above.

We reserve the right to use our discretion to grade above or below these severity levels in cases where we deem it necessary. That said, we will strive to meet these guidelines in as many cases as possible in order to be transparent about how we assess XSS risk on this program.

| Severity | Impact | Success Conditions | Likelihood | Example |
|---|---|---|---|---|
| **Critical** | Multi-organisational — multiple accounts, not portals, are affected by a single attack. | None; any account with a portal is affected (e.g., an attack can be launched off-site from a high-traffic domain). **AND** Attacker needs no prior knowledge of the target. | Guaranteed to affect many organisations were an attack to be launched. | Stored XSS in a platform-wide UI component on `test.growthdesk.test` that fires automatically for every authenticated user without any interaction, enabling mass session hijacking across all organisations. |
| **High** | Multiple portals are affected by a single attack. | Few; very limited interaction is needed by the victim (e.g., one-click attack). **AND** Attacker needs no prior knowledge of the target. | Exploitation is possible and likely to succeed. | Stored XSS on `test.growthdesk.test` where clicking a single crafted link executes a payload in the victim's authenticated session. No prior knowledge of the victim is needed; attacker can steal session tokens and access CRM data across the victim's portals. |
| **Medium** | Multiple portals are affected by a single attack. | Pre-existing knowledge or access to targets is needed. **AND/OR** Social engineering may be necessary for a successful attack. | Exploitation is unlikely to succeed in most cases. | Stored XSS in a shared CRM asset (e.g., a record property) that fires when another user views it. Requires the attacker to have portal write access to inject the payload and social engineering to direct a target to the affected page. |
| **Low** | A single portal is compromised by the attack. | Complex conditions or extensive knowledge of the target is needed. **AND/OR** Significant social engineering is needed for a successful attack. | Exploitation is very unlikely to succeed in most cases. | Stored XSS in a portal configuration page that only fires for super admins of the same portal. Requires editor-level access, a crafted payload in a specific field, and social engineering to get an admin to navigate to the affected page. |
| **Informational** | A single portal is compromised by the attack. | Victims must effectively attack their own portal. | Exploitation has a near-zero chance of success in real conditions. | Self-XSS where a user injects a script into a field that only renders in their own authenticated session. No path to cross-user exploitation; the victim would need to paste the payload into their own portal. |

## Subdomain takeovers
Growthdesk owns thousands of subdomains. Researchers who submit a valid subdomain takeover will be rewarded at either P2 or P3 level, depending on impact.

Subdomain takeover reports are in scope only if they meet the following criteria:
- You must include proof that the subdomain is owned by Growthdesk.
- You must demonstrate proof-of-concept by hosting a simple, nonmalicious html file under the taken-over subdomain.

## Insecure direct object references (IDORs)

Cross-portal IDORs or privilege escalation issues that allow unauthorized access to sensitive data, different customer portals, or administrative functions are eligible for rewards and will be prioritized based on their impact.

For same-portal IDORs, the API layer is the relevant enforcement boundary. UI-level restrictions (e.g., a grayed-out button) do not constitute a security control. To be eligible for a reward, a report must demonstrate that the action is not blocked at the backend permission layer and results in meaningful security impact, defined as:

- Unauthorized read access to another user's sensitive data (PII, PHI, financial/billing information, credentials, or records restricted by object-level permissions)
- Unauthorized modification or deletion of another user's data with a meaningful integrity or confidentiality consequence

**Reports will be closed as Informational if:**
- The behavior is consistent with our backend permission model (e.g., in Growthdesk's engagement model, edit access implies delete access by design)
- The owning team confirms the behavior is working as designed
- The low-privileged user holds a scope that legitimately permits the action
- It's a previously accepted and documented risk (e.g., users without `User table access` can still view a list of users elsewhere in their Growthdesk account as documented [here](https://knowledge.growthdesk.test/user-management/Growthdesk-user-permissions-guide))

**Note:** If modifying another user's settings could result in account takeover, data exposure, or loss of account access, the report may still be eligible.

**Higher Priority IDORs** (eligible for standard rewards):

- Cross-portal data access or leakage
- Access to [sensitive properties](https://knowledge.growthdesk.test/properties/store-health-data#create-phi-properties) or PHI/PII data within the same portal
- Financial, billing, or payment information access within the same portal
- Privilege escalation to Super Admin functions within the same portal
- User account takeover capabilities within the same portal

**Lower Priority / Informational IDORs** (may be closed without reward):

- Basic CRUD operations on non-sensitive objects within the same portal
- Sharing / permission modifications on non-sensitive content within the same portal
- Feature or setting toggles within the same portal without demonstrated security impact

**Note:** We reserve the right to mark authorization bypass issues as informational when they involve low-impact administrative functions, even if they represent a technical violation of intended permissions. This allows our team to focus resources on higher-impact security issues while still acknowledging valid findings.

---
# Out Of Scope Vulnerabilities:
The following submission types are excluded from the bounty and therefore not rewardable:
- Reports related to the rate limits applied to an API endpoint
- Login or Forgot Password page brute force
- Denial of service attacks
- Perceived excessive volumes of sent email (e.g., mail flooding)
- Race condition bugs that bypass subscription limits
- Social-engineering of any kind against Growthdesk employees or its users
- Vulnerable libraries without a working proof-of-concept
- Clickjacking
- Absent or misconfigured HTTP headers
- Missing best-practice bugs that don't pose a direct/immediate risk to our company or our users (e.g. missing certificate authority authorization)
- XSS that don't execute in the context of *.growthdesk.test or customer connected domains, and instead only executes on preview domains like growthdesk.test, growthdesk.test, growthdesk.test, cdn.growthdesk.test, and similar domains. These domains are intentionally designed to host untrusted user-supplied data.

---
# Important Notice:
Participating community members agree that they have appropriate rights for Growthdesk to use Community Member Data as contemplated in this Program Policy and such use of Community Member Data by Growthdesk will not infringe, misappropriate, or violate a third party's intellectual property rights, or rights of publicity or privacy.