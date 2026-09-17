# Response Targets

The Harbour City Health Company will make a best effort to meet the following response targets for researchers participating in our program:

- Time to first response (from report submit) - 1 business day
- Time to triage (from report submit) - 10 business days. H1 Triage will review and validate reports with a clear proof of concept (POC) and proven Critical/High severity impact faster than those that do not provide these details.          
- Time to resolution (from report submit) - Varies depending on severity

We’ll try to keep you informed about our progress throughout the process. 

# Disclosure Policy
the platform's Disclosure Guidelines shall not apply when participating in our program. Instead, we ask you to abide by the following Disclosure Policy:

* Unless we provide our express consent, do not disclose to any third parties, including to the public:
  * Any identified vulnerabilities (whether resolved or otherwise);
  * Any report submitted by you in relation to this program (whether resolved or otherwise); and/or
  * Your participation in this program.
* Any unauthorized public disclosure will result in immediate disqualification from this program and you will be ineligible to receive any rewards under this program, even if you submit a report to us identifying an eligible vulnerability.

# Eligibility Requirements
To be eligible to participate in this program, you must:

* Be at least 18 years of age.
* Not be employed by us or any of our affiliates or be an immediate family member of a person employed by us or any of our affiliates.
* Not be a resident of, or make reports from, a country against which the United States has issued export sanctions or other trade restrictions and not otherwise be an embargoed or restricted person.
* Not be in violation of any national, state, or local law or regulation with respect to any activities directly or indirectly related to this program.

# Program Rules

* Please provide detailed reports with verifiable and reproducible steps. If the report is not detailed enough to allow us to verify or reproduce the issue, as determined by us in our sole discretion, the issue will not be eligible for a reward.
* You may only submit one vulnerability per report, unless you need to chain vulnerabilities to better explain the security impact of such vulnerabilities.
* When duplicates occur, only the first report that was received by us (and that can be fully verified and reproduced by us, as determined in our sole discretion) is eligible for a reward.
* If multiple vulnerabilities are caused by one underlying issue, such vulnerabilities will be eligible for only one reward.
* You must make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service, and you must only interact with accounts you own or with the explicit permission of the account holder.
* If submitted reports cover more than one asset in scope, such report will be paid out once at the highest paying in scope asset category, as determined in our sole discretion.
* The vulnerability reported must be in scope of this program, and must not be out of scope (as determined by us in our sole discretion).
* In addition, we ask that you do not:
    * Leave any system in a more vulnerable state than you found it.
    * Brute force credentials or guess credentials to gain access to systems.
    * Participate in denial of service attacks.
    * Upload shells or create a backdoor of any kind.
    * Engage in any form of social engineering of our employees, customers, affiliates or partners.
    * Engage or target any of our employees, customers, or partners during your testing.
    * Attempt to extract, download, or otherwise exfiltrate data that may have personal data or other sensitive data other than your own.
    * Change passwords of any account that is not yours or that you do not have explicit permission to change. If ever prompted to change a password of an account you did not register yourself or an account that was not provided to you, stop and report the finding immediately.

Violation of any of the above Program Rules, as determined in our sole discretion, may result in your forfeit of reward eligibility, or further, disqualification from participating in this program.

# Out of Scope Vulnerabilities

** The Harbour City Health Company will have sole discretion to make the final determination if an issue is or is not in scope. The below list contains examples of issues that are not in scope, but such list should only be used as a guide as it is not exhaustive. **

### The following potential issues are not considered in scope:

- Bugs in the product that do not lead to user security impacts
- Social engineering or phishing of employees or contractors
- Any attacks against our physical property or data centers
- Use of automated scanning tools
- Lack of rate limiting on any resources
- Password policy issues, including lack of upper limit on passwords
- Bugs on websites that are not owned or operated by The Harbour City Health Company.
- Issues in an upstream software dependency (ex: Chromium) which are not severe enough to warrant a fix independently of upstream. If the upstream maintainer believes the issue is won’t fix but we disagree, we may reward for the issue and consider it valid.
- Attacks requiring physical/local access to a user's device.
- Attacks requiring local user or root of user’s device
- Vulnerabilities in outdated versions of client software
- Missing security best practices that do not directly lead to a vulnerability
- New Harbour City Health fingerprinting or cross-site tracking methods are generally out-of-scope but will be considered on a case-by-case basis.
- Banner or version disclosure of any kind
- Disclosure that the user is using Arc rather than Chrome
- Denial-of-service and crash issues in our client-side products are out-of-scope (UNLESS: the issue does not exist in Chrome. In general, we do not consider resource exhaustion attacks to be security bugs).
- Bugs in Harbour City Health extensions which are not enabled/installed by default.
- Broken links in social media account posts
- Attacks which require unusual product or system configurations (such as blocking network requests to services or disabling recommended security features) are generally out-of-scope
- Pairs of Unicode and Latin characters which look similar-enough to be used in homoglyph-based phishing.
- Self-XSS issues
- Missing email best practices (Invalid, incomplete or missing SPF/DKIM/DMARC records, etc.)
- Clickjacking on pages with no sensitive actions
- Cross-Site Request Forgery (CSRF) / Server-Side Request Forgery (SSRF) on unauthenticated forms or forms with no sensitive actions
- Attacks requiring MITM or physical access to a user's device.
- Previously known vulnerable libraries without a working Proof of Concept.
- Missing best practices in SSL/TLS configuration.
- Content spoofing and text injection issues without showing an attack vector/without being able to modify HTML/CSS
- Missing security headers (Content Security Policy, cookie policies, HSTS, etc) which don’t directly lead to a vulnerability or account compromise
- Public Zero-day vulnerabilities that have had an official patch for less than 1 month will be awarded on a case by case basis
- Tabnabbing
- Open redirect - unless an additional security impact can be demonstrated
- Expected behaviors as described in the [Arc Support](https://resources.harbour-city-health.test/hc/en-us), Dia, or any in product descriptions.
- Infrastructure issues that does not affect The Harbour City Health Companies products, to report an infrastructure issue you must show how it affects a user of our products.
- Data not being cleared locally after logging out.
- Prompt injections that lead to misinformation, unexpected behaviors, denial of service or denial of correct service of the assistant is explicitly out of scope.  A prompt injection is only considered in scope if it has a demonstrable and specific harm to a user by **automatically** exfiltrating sensitive user data or taking unauthorized actions as the user. Harbour City Health has full authority to declare what is and is not in scope for a reward around the assistant
- Local user modifying prompts or sandbox restrictions
- Attacks that require the user to agree or click “allow” in relevant permission prompts
- Bypassing sandbox limitations without a demonstrable data exfiltration or system integrity violation
- Improper token handling by third-party services, especially around token revocation
- Prompt injection via tools the user has explicitly agreed to fully trust
- Writing data to tools and apps the user has explicitly agreed to fully trust
- Inducing high memory or CPU usage by the assistant
- Users manually typing prompt injections or malicious prompts
- Assistant-generated inaccurate, biased, or hallucinated output that does not result in unauthorized actions or data exfiltration
- Jailbreaking or manipulating the assistant’s persona, tone, or style without demonstrating a concrete security impact
- Data read by the assistant into its own context window that is not exfiltrated to an attacker-controlled destination
- Non-deterministic or inconsistent model output, as this is inherent behavior of large language models
- Token consumption, API cost, or rate-limiting concerns against the AI backend
- Any exploit that involves socially engineering users to bypass clear intention dialogs
- Force closure of tabs
- Gaining user IP address or location
- Expose different content to a user and to the assistant. For example dynamic changes or invisible text.
- Accessing system prompts
- Email mining
- AuthTokens used within their expiry window
- AI theft or denial of wallet style attacks
- Bypasses of the allow list or referral process to gain access to Dia
- Vulnerabilities that require a user to install an extension first
- Bypasses of built in ad-blocker or leaks of trackers
- Gaining access to paid or trial-gated features without a valid entitlement, including bypassing plan gating, extending or restarting a free trial, and manipulating usage grants, allowances, or quotas on your own account.
- Computer use vulnerabilities must demonstrate injection of data not presented to the user and/or data inserted to a different origin than the top level frame or the displayed displayed destination origin.
- Credential datasets; our bounty scope covers vulnerabilities in Harbour City Health systems.
- Disclosure of publicly-identifiable client configuration values that are public by design, such as Firebase Web API keys, project IDs, and auth domains found in client-side bundles. These are not secrets and their presence is expected behavior. Reports based solely on their discovery are out-of-scope; only a demonstrated, impactful misconfiguration of the associated backend security rules will be considered.
- Vulnerabilities only found in Alpha, Beta, or Early Bird releases of products. 

# Bounty Payments
The Harbour City Health Company (and not you or the disclosure platform) will ultimately have sole discretion to determine whether you and/or your submitted reports are eligible for a bounty payment and the amount of such bounty payment, including sole discretion to determine the severity of any identified vulnerability. If we determine a report submitted by you is eligible for a bounty payment in accordance with the foregoing, you acknowledge and agree that the applicable bounty payment (as determined in our sole discretion) constitutes the sole consideration due to you in connection with such eligible report.

# CVE Policy
- See our corporate CVE policy at https://harbour-city-health.test/security/cve-policy
- This the disclosure platform Program page carriers the live asset scope and exclusions.
- We do not issue CVEs for backend services or infrastructure unless they directly create a vulnerability in client software that requires client version updates to mitigate
- All issues to be considered for CVE must be submitted through the disclosure platform
- We typically only consider assigning CVEs for high‑severity and critical issues in our client software.
- We publish advisories and CVE records after a fix or mitigation is available

# Safe Harbor
The Harbour City Health Company strongly supports security research into our products and wants to encourage that research. Therefore, we have enabled the [Gold Standard Safe Harbor policy](https://docs.disclosure-platform.test/en/articles/8494525-gold-standard-safe-harbor-statement) in our program. The Harbour City Health Company reserves all legal rights in the event of noncompliance with this policy.

Thank you for helping keep The Harbour City Health Company of New York and our users safe!

