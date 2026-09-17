Fetchly welcomes the contributions of security researchers to help keep our consumers, Dashers, and merchants safe. Our Bug Bounty Program focuses on identifying vulnerabilities that could meaningfully impact the confidentiality, integrity, or availability of Fetchly systems or user data.

We evaluate submissions based on their demonstrated **security impact**, not just vulnerability class or affected domain. Reports without clear security relevance may be considered out of scope. By submitting a report you agree that you have read and are bound by the terms set forth below as well as any other Fetchly terms and conditions.

---

## General Terms

---

* **No disruptive testing**: Our mission is to connect consumers, Dashers, and merchants. Your testing should not disrupt this mission. Do not destroy data, degrade or interrupt our service, or leave a system or our users in more vulnerable states than you found them. Brute forcing credentials, performing denial of service (DoS) attacks or tests, or changing passwords of accounts that are not yours or which you don't have permission to change are all prohibited  
* **Respect our users' privacy**: We respect our users' privacy and expect you to do so too. Only use or interact with Fetchly accounts you own or with explicit permission from the account holder. If you encounter our users' information during the course of your research: (1) stop at that point in your testing where you have adequate proof for your submission and (2) submit your report or disclosure at that point so Fetchly can investigate further. Any actions taken beyond that point are not authorized. Do not save, copy, store, transfer, disclose, or retain any user information.  
* **Patience and cooperation:** We value the reports we receive and may have questions for you or seek clarification regarding your submission. It may take some time for us to remediate confirmed findings as we perform root cause analyses. Please be respectful and patient, and we will do likewise.  
* **No public disclosure:** Public disclosure of vulnerabilities is not permitted unless explicitly approved by Fetchly.  
* **No scanners:** Do not run automated security scanners against our systems.  
* **No pivoting**: Report your findings as soon as you've discovered them. Do not attempt to pivot or extend the severity of observed security weaknesses, unless it is chained with another vulnerability to show impact.  
* **No stockpiling**: If you're aware of variants of the bug or vulnerability you're reporting, then report all variants all at once.  
* **No writes to AWS**: Do not conduct any testing of our AWS configuration that requires you to submit API changes that "write", "create", "delete", or "change" data or configuration.
* **Third-party systems out of scope:** Vulnerabilities in third-party services, platforms, or software not owned or operated by Fetchly are out of scope, even if they integrate with Fetchly systems or appear within our applications.

---

## Eligibility to Participate

---

To be eligible to participate in our Bug Bounty Program, you must:

* Be at least 18 years of age if you test using a Fetchly account  
* Not be employed by Fetchly or any of its affiliates or contractors, or be an immediate family member of a person employed by Fetchly or any of its affiliates or contractors  
* Not be a resident of, or submit a report or disclosure from a country against which the United States or any other country in which Fetchly operates has issued export sanctions or other trade restrictions;  
* Not be in violation of any national, state, or local law or regulation with respect to any activities directly or indirectly related to Fetchly's Bug Bounty Program.

If you do not meet the eligibility requirements above, breach any of the terms or rules herein or any other agreements you have with Fetchly or its affiliates, or we determine that your participation in the Bug Bounty Program could adversely impact Fetchly, our affiliates or any of our users, employees or agents, Fetchly, in its sole discretion, may remove you from the Bug Bounty Program and disqualify you from receiving any benefit of the Bug Bounty Program.

---

## Understanding Our Platform

---

The Fetchly platform provides a **web interface for consumers** and **dedicated mobile applications** for consumers, dashers, and merchants on both **iOS and Android**.

Originally built as a **Python/Django monolith**, Fetchly has evolved into a **microservices-based architecture** leveraging multiple languages, including **Kotlin**, **Go**, and **Java**, across various services. The consumer-facing web front-end is developed using **React.js** and **HTML**, delivering a responsive and accessible user experience.

- [https://fetchly.test/2020/12/02/how-Fetchly-transitioned-from-a-monolith-to-microservices/](https://fetchly.test/2020/12/02/how-Fetchly-transitioned-from-a-monolith-to-microservices/)

---

## Testing Instructions 

---

To help us identify your security testing activity, please follow the below instructions and inject the following header for all testing:

|**Header Format** |
| ----------------------------------------- |
| X-Bug-Bounty: <your-Researcher-handle> |

### How to set up your Consumer Account

1. Go to https://www.fetchly.test/ 
2. Click the Sign Up button and create a Fetchly account using your disclosure-platform.test email address.
3. If you want to create multiple test accounts, please use the "plus addressing" format with your the disclosure platform email as such: 
`<your-Researcher-handle>+1@fetchly.test`

---

## Vulnerabilities We Prioritize

---

We prioritize reports that demonstrate a clear risk to the security or integrity of Fetchly users, systems, or data. The following categories are of particular importance to us, but not exhaustive:

**1\. Authentication & Authorization**

* Flaws that allow unauthorized actions or account takeovers without user interaction (e.g., authentication bypasses or session hijacking).  
* Authorization issues that expose or modify data belonging to other users or roles.

**2\. Code Execution & Injection**

* Remote code execution (RCE), command injection, or database query injection (SQL/NoSQL).  
* Cross-Site Scripting (XSS) or any injection vulnerabilities that result in arbitrary code execution in the browser (DOM-based or otherwise).

**3\. Platform & Infrastructure Security**

* Exposure of credentials, API keys, or other secrets for internal systems or infrastructure (e.g., in GitHub repositories, DockerHub images, or other public assets).  
* Open redirects or other flaws that can facilitate phishing or redirect attacks.

---

## Vulnerabilities Excluded

---

The following kinds of vulnerabilities on our platform are **excluded** from this program. Please refrain from reporting and including them in your tests.

| Category | Exclusion details |
| :---- | :---- |
| **Role-Based Access Control (RBAC) / Permissions Without Risk** | Findings where user roles (e.g., dasher vs. consumer vs. merchant) are restricted by business design and do not lead to a security risk or exposure of customer/PII are excluded. For example, a dasher not being able to access certain merchant-only dashboards is expected behavior. |
| **Leaked User Credentials from External Sources** | Reports of leaked credentials from third-party breaches, password dumps, or OSINT scraping (GitHub, paste sites, etc.) are accepted for awareness but not eligible for bounties. Bounties only apply if the leak originates from Fetchly-owned systems. |
| **Information Disclosure Without Exploitability** | Findings such as API version banners, verbose error messages in order flows, or generic stack traces that do not lead to access to sensitive data are out of scope. |
| **Open Redirects Without Escalation** | Redirects (e.g., in referral links or promotions) that cannot be leveraged into phishing, account takeover, or token leakage are excluded. |
| **Missing or Misconfigured Security Headers** | Absence of headers like HttpOnly, Secure, X-Frame-Options, or CSP in consumer-facing pages is not eligible unless a demonstrable exploit (e.g., XSS, clickjacking on payment/checkout) is shown. |
| **Self-XSS / Self-DoS** | Bugs that only impact the reporter's own account/session, such as injecting JavaScript into your own profile description or locally exhausting API quota, are excluded. |
| **CSRF / Clickjacking Without Sensitive Action** | Reports involving CSRF/clickjacking on non-critical functions (e.g., liking a restaurant, updating a delivery note) are excluded. Eligible examples would include payment method changes, dasher payout settings, or password resets. |
| **Low-Impact Mobile Findings** | Reports of missing certificate pinning, jailbreak/root detection, or insecure local storage that don't lead to account compromise, data theft, or fraud are excluded. |
| **Rate Limiting / Brute Force Without Impact** | Generic findings of missing rate limits, username/email enumeration during signup/login, or brute force attempts that don't result in credential compromise, payment fraud, or order manipulation are |

---

## Report Submissions and Quality

---

High-quality submissions help Fetchly's security team reproduce, validate, and fix issues efficiently. Reports that include complete, actionable information allow us to assess severity faster and reward accordingly.

To help ensure your report is triaged quickly and accurately:

* **Confirm scope first:** Review our Scope section before submitting to make sure the asset and vulnerability type are in scope for this program.

* **Be clear and reproducible:** Provide detailed steps to reproduce the issue, including request/response samples, screenshots, or short screen recordings where applicable.

* **Explain the impact:** Describe how the vulnerability could affect Fetchly users, data, or systems. Our bounty payouts are based on demonstrated security impact, so please provide sufficient evidence to support severity.

* **Provide full context:** Include relevant account types, environment details, and any preconditions needed to reproduce the issue.

* **Submit complete reports:** Standalone videos or incomplete PoCs will not be accepted. Video proof-of-concepts are welcome **only** when accompanied by a clear, written report.

* **Focus on verifiable findings:** Issues must be reproducible and demonstrate a measurable security impact to qualify for bounty consideration.

* **Avoid duplicates:** Known vulnerabilities, or reports that stem from the same root cause as prior findings, will be marked as duplicates and ineligible for reward.

* **When in doubt, submit responsibly:** If you're unsure of full impact but believe the finding is noteworthy, submit a detailed and responsible report. Our team will evaluate it for potential security implications.

---

## Other Notes

---

Please note that many of these web application and API endpoints are deployed from the *same underlying codebase*.  If the same vulnerability affects more than one domain, **please file a single report.**  For example, reporting a web application vulnerability on our staging site that's identical to a vulnerability report on our production site will be considered a duplicate and will not receive a reward since any fix would be deployed to both as part of our normal release cycle.
