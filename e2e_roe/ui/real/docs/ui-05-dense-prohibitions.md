# Overview 
At Bazaarly, we prioritise security and value responsible disclosure. If you identify a security issue in our website or apps, we encourage you to report it to us responsibly. Our team is committed to resolving issues promptly and requests that you allow us time to address them before any public disclosure. Please share a detailed description and reproduction steps. We trust the security community to help protect our users' data and privacy.

# Disclosure Policy
- This program follows a coordinated vulnerability disclosure process. By participating in this program, you agree not to publicly disclose or threaten to disclose or take any action which may adversely affect Bazaarly by using any vulnerability or related information, including technical details, proof-of-concepts, screenshots, or exploit code, on any public platform.
- Public platforms include, but are not limited to, blogs, forums, social media, conference presentations, vulnerability databases, or other publicly accessible channels. Researchers are not permitted to disclose, discuss, or reference any vulnerability or report without Bazaarly’s explicit written consent, including in anonymized or aggregated form.
- Researchers are not permitted to sell, license, transfer, auction, or otherwise disclose vulnerability information to any third party, vulnerability broker, data aggregator, or exploit marketplace, whether before or after reporting to Bazaarly.
Failure to follow this policy may result in removal from the program, forfeiture of any pending rewards, and loss of eligibility for future participation or if deemed fit by Bazaarly legal recovery, legal action in accordance with applicable law.
- You must follow the timelines prescribed by Bazaarly to make reporting under programs forming part of this policy.


# Bazaarly Account Signup Instructions:
- Researchers with Indian phone numbers can sign up/login via OTP.
- Must avoid creating multiple accounts or generating spam accounts.
- Any misuse, abuse or fraudulent activity shall render the researcher disqualified and liable 


# Test Plan & Credentials
- Include the following HTTP header in all test requests:
X-Researcher: <h1-username>  (replace <h1-username> with your actual the disclosure platform username)
- You can sign up for a free account through our website if needed
- Use your the disclosure platform email alias when registering: h1username@bazaarly.test

- **Supplier Panel (Asset: supplier.bazaarly.test)**
  - Username 1: `Bazaarlytestsupplier01@bazaarly.test `
  - Username 2: `Bazaarlytestsupplier02@bazaarly.test `
  - Password (both accounts): `the disclosure platform@123$`

- **Consumer & Mobile Apps (Bazaarly Web, Bazaarly Android App, Bazaarly iOS App, Valmo Mobile App)**
  - Mobile Number 1: `6666666661`
  - Mobile Number 2: `6666666662`
  - OTP (both numbers): `999999`

**Note:** If login fails after entering the OTP, tap Resend after the timeout and enter the same OTP again


## Important Notes
- Testing rate limits on the order flow is not allowed
- Any orders placed using these test accounts will be canceled within 24 hours
- Do not perform real financial transactions
- Do not access, change, download, or misuse real user data
- Do not change passwords, emails, or account or security settings
- Do not lock, suspend, or try to gain extra privileges on the accounts
- Do not share test credentials with anyone
- Use the accounts only for their intended purpose and permissions
- Stay within the defined scope and avoid impacting live users or production systems
- Let the security team know if the credentials stop working
- Include clear steps to reproduce, affected assets, and a proof of concept in your reports
- Any misuse of credentials or systems may lead to disqualification of reports and removal from the program


# Out-of-Scope Assets
- Any asset, domain, IP, application, or service that is not listed in the In-Scope section
- Third-party or vendor-managed systems, such as payment providers, analytics tools, or customer support platforms
- Internal systems, admin panels, employee-only tools, and staging or development environments, unless they are clearly marked as in scope


# Report Eligibility
- Only the first valid and complete report of an issue will be eligible for a bounty subject to timely submission by the research if the Bazaarly prescribes a timeline.
- Please submit one issue per report, unless you need to chain multiple steps to show real impact.
- If multiple findings come from the same root cause, they will be treated as a single issue and rewarded once (if applicable).
- Similar issues across different endpoints in the same application may be marked as duplicates, unless we decide otherwise.
- Reports should be clear and easy to reproduce, and include:
  - Step-by-step instructions
  - Screenshots, videos, or other proof of impact
  - Test account details or sample payloads, where relevant
(See the disclosure platform’s quality guidelines: https://docs.disclosure-platform.test/hackers/quality-reports.html)
- Current and former Bazaarly employees, contractors, or anyone with internal system access are not eligible to take part.
- Issues we have already found internally, or that have already been reported by someone else, are not eligible for a reward.
- Recently published CVEs will not be considered valid submissions under this program until a 30-day cool-off period has elapsed from the date of publication.
- Reports based only on automated scan results without a clear security impact or working proof of concept may be treated as informational.
- Spam, test, or non-actionable reports may be closed without further review.
- Please follow responsible disclosure practices and do not publicly share any findings until we’ve had a chance to review and fix them.
- Any vulnerability reported on out-of-scope assets will be closed as Not Applicable. Repeated violations will result in the report being closed as Spam and may lead to a ban from the program.


# Program Rules
- Use only your own accounts or the test accounts we provide when testing. Do not access or attempt to test against real user accounts or accounts you do not own or have permission to use.
- Do not exploit vulnerabilities in a way that could harm our products, customers, data, or day-to-day business operations.
- Avoid privacy violations, service disruptions, and any actions that could delete, corrupt, or expose data.
- Do not use automated tools or scanners that could affect production systems or platform stability.
- Malware, social engineering, and abuse activities are not allowed. This includes phishing, vishing, smishing and denial-of-service attacks.
- Subsidiaries, parent companies, and affiliates are out of scope unless we clearly state otherwise.
- Reports related to outdated or unsupported software versions may be placed under a 60-day blackout period to allow time for internal patching and will not be eligible for rewards during that period.
- All communication must stay on the disclosure platform. Reaching out directly to customer support, employees, or partners about a vulnerability may lead to disqualification.
- Any threats, extortion attempts, or pressure tactics will result in removal from the program.
- Keep all vulnerability details confidential. Do not publicly share any findings until we’ve reviewed and fixed the issue and approved disclosure.
- Do not collect, store, or keep copies of any user or system data beyond what is strictly needed to demonstrate the issue. Delete any such data after reporting.
- Any exploitation or misuse of a vulnerability beyond what is needed to prove impact may lead to automatic disqualification.
- Automated data scraping, model inference attacks, training data extraction, prompt injection, or attempts to reverse-engineer algorithms or recommendation systems are prohibited unless explicitly authorized in writing.
- Do not share vulnerability details with third parties.
- If you discover a critical issue that provides system-level or administrative access, stop testing and notify us right away.
- Test only the services and products listed as in scope, and only for eligible vulnerability types.
- Do not take part in anything illegal, unethical, or that violates applicable laws or regulations.
- Participation in this program does not grant access to Bazaarly systems beyond what is publicly available or explicitly provided for testing.
- We may ask for basic identity or payment details if needed to process a bounty, in line with legal and compliance requirements.
- Breaking these rules may result in report closure, disqualification from the program, or other actions at our discretion.
- By submitting a report, you grant Bazaarly a non-exclusive, worldwide, perpetual, and royalty-free right to review, assess, and use your submission to analyze, fix and improve the security of our systems.


# Out of Scope
- Reports based on automated scanners or tools that could disrupt or impact production systems
- Username/Email enumeration through signup, login, account recovery flows or any such similar flows
- Brute-force or rate-limiting issues
- Clickjacking
- Cache deception (temporarily out of scope until further notice)
- Cache poisoning without a valid a POC (i.e. replicated on different IPs/user sessions)
- CSRF on unauthenticated, login, or logout actions
- Self-XSS, content spoofing, or text injection without clear security impact
- Open redirects unless they can be chained with a real, impactful exploit
- Stack traces, directory listings, or path disclosures without demonstrated risk
- Network-level DoS or DDoS attacks
- Best-practice or hardening issues only, such as:
  - Missing security headers, HSTS, or cookie flags
  - SSL/TLS configuration warnings
- Reports generated only by automated tools without a working proof of concept
- Issues affecting outdated app versions, unsupported browsers, or deprecated platforms
- Missing certificate pinning, root/jailbreak detection, or code obfuscation
- Sensitive data in URLs or request bodies when the traffic is protected by TLS
- OAuth or app secrets found in APKs without demonstrated impact
- User data stored unencrypted on a device file system without clear risk
- Lack of binary protections (such as anti-debugging), or issues that require a rooted or jailbroken device to exploit
- Vulnerabilities that require physical access to a user’s device
- SPF, DKIM, or DMARC issues without proven email spoofing to major email providers
- Known vulnerable libraries or CVEs without a valid proof of concept or with low to medium impact
- Employee credential leaks unless direct organizational impact is clearly demonstrated (subject to security team review)
- Credentials sourced from personal repositories, the dark web, or public breach databases (such as Have I Been Pwned) unless real impact is shown
- Document or file exposures, unless they are clearly critical
- Cloud storage or bucket leaks, unless business critical data is exposed
- Theoretical or purely speculative vulnerabilities without demonstrated impact
- Service fingerprinting or banner disclosure on public-facing services
- Publicly known files or directories (for example, robots.txt or readme files)
- Subdomain takeover claims without a valid, working proof of concept
- Google Maps API key exposure without demonstrated abuse
- Tab-nabbing and Task Hijacking in mobile applications
- Weak password policy findings without a clear, exploitable path
- SSRF pingback connections, also referred to as out-of-band attacks, without a proper exploit PoC, will be marked as Informational
- CORS misconfiguration without significant impact
- Cross-Origin-Opener without significant impact
- Collection ID enumeration in affiliate panel
- Account Deletion issue in Bazaarly Android, iOS and Web apps.


# Additional Out-of-Scope for Supplier / Seller Panel
- IDOR, SSRF, or file upload issues with limited or no demonstrated security impact
- Publicly accessible cloud storage buckets without exposed business critical data
- MFA or 2FA not being enabled on the application
- Missing rate limiting on its own, without proof of abuse or exploitation
- Credentials sourced from the dark web or public leak sites (will be closed as Not Applicable)
- Cache-related issues without real-world impact


# Known Issues (Will Be Closed as Duplicates)
- HTML injection in the ticketing module on supplier.bazaarly.test 
- Account deletion issues that lead to first-order discount misuse across Bazaarly Web, Android, and iOS apps
- Stored XSS via file upload on supplier.bazaarly.test 
- Bank details update OTP bypass on supplier.bazaarly.test 
- My Bank & UPI details OTP bypass on Bazaarly mobile apps


# Safe Harbor
- If you follow this policy and test in good faith, Bazaarly considers your research to be authorized and will not pursue legal action for activities performed within scope.
- We encourage responsible disclosure through this program and will make a good-faith effort to protect researchers who follow our rules, even if testing involves bypassing certain technical controls on in-scope assets.
- This protection applies only to Bazaarly systems listed as in scope and does not extend to any third-party services or infrastructure.
- If you are unsure whether a specific action is allowed or falls within scope, please reach out to us before proceeding. We’re happy to clarify.
- In cases where your testing follows this program but conflicts with other site policies, we may allow limited exceptions under this safe harbor, at our discretion.
- We cannot authorize testing on third-party systems, and we cannot prevent a third party from taking legal action if you test their infrastructure. We do not act on behalf of other organizations.
- We are not responsible for any claims, legal actions, or liabilities that may arise from testing against third-party systems.
- You are expected to follow all applicable laws and avoid disrupting services or accessing data beyond what is needed to demonstrate a security issue.
- If you plan to take any action that is not clearly covered by this policy, contact us first at security@bazaarly.test  Letting us know in advance is an important factor in how we assess good-faith testing.
- Safe Harbor protections are conditional and may be revoked if it is determined that a researcher:
  - Acted in bad faith
  - Exceeded the minimum level of exploitation required to demonstrate impact
  - Violated confidentiality obligations
  - Attempted to coerce, pressure, or influence remediation or disclosure timelines

# Compliance & Governing Law
Participation in this program is prohibited where restricted by applicable export control laws, sanctions regulations, or trade compliance requirements. Researchers represent that they are not located in, or acting on behalf of, any sanctioned jurisdiction or entity.

This policy shall be governed by and construed in accordance with the laws of India. Any disputes arising under or in connection with this policy shall be subject to the exclusive jurisdiction of the courts of Bangalore, Karnataka.

Thank you for helping keep Bazaarly and our users secure