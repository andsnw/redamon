##** Non-Compliance**

Public disclosure of the submission details of any identified or alleged security vulnerability without express written authorisation from Rupaya Pay will deem the submission noncompliant with this policy.

* As this is a private program, please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

Furthermore, to remain compliant, you are prohibited from:

- Accessing, downloading, or modifying data residing in an account that does not belong to you
- Executing or attempting to execute any “Denial of Service” attack
- Posting, transmitting, uploading, linking to, sending, or storing any malicious software
- Testing in a manner that would result in the sending of unsolicited or unauthorised junk mail, spam, pyramid schemes, or other forms of unsolicited messages
- Testing in a manner that would degrade the operation of any Rupaya Pay systems
- Testing third-party applications, websites, or services that integrate with or link to Rupaya Pay systems

---

##** Program Terms & Conditions**

The Program applies to security vulnerabilities found within Rupaya Pay’s Environment, including, but not limited to, Rupaya Pay’s websites, APIs, and mobile applications. We recognise security researchers who help us keep users safe by reporting vulnerabilities in our services. The recognition for these reports is entirely at Rupaya Pay’s discretion and is determined based on factors such as Severity, Likelihood, and Business Impact of the reported finding.

Typically, in-scope submissions will include high-impact vulnerabilities. However, any vulnerability that could realistically place our customers’ security or their data at significant risk is in scope and might be rewarded. Vulnerabilities that directly or indirectly affect the confidentiality or integrity of user data or privacy are prime candidates for a reward. Some characteristics that are considered when “qualifying” vulnerabilities affect the following aspects:

- Directly or indirectly affect the confidentiality or integrity of user data or privacy;
- Compromise the integrity of the system;
- Enable unauthorised access to significant data or resources;
- Enable the running of unauthorised code;
- Increase privileges or access beyond that which is intended;
- Interfere with or bypass security controls or mechanisms;
- Are exploitable (i.e. not purely theoretical);
- Can be launched remotely; and
- Could cause damage to a user’s system

###**To be eligible for the Bug Bounty Program, you MUST meet the following requirements:**

- Adhere to Rupaya Pay Responsible Disclosure Policy
- Your report must describe a security vulnerability involving and/or affecting one of the products or services listed under “Scope”.
- We expressly exclude certain types of security findings; these are listed under “Program Exclusions”.
- If you inadvertently cause a privacy violation or disruption (such as accessing account data, service configurations, or other confidential information) while investigating a vulnerability, make sure that you disclose this in your report.

###**In addition, you MUST NOT:**

- Be in violation of any national, state, or local law or regulation;
- Be employed by Rupaya Pay Limited (Formerly known as ‘Rupaya Pay Private Limited’) or its subsidiaries;
- Be an immediate family member of a person employed by Rupaya Pay Limited (Formerly known as ‘Rupaya Pay Private Limited’), or its subsidiaries or affiliates.

---

## Our commitment

If you identify a valid security vulnerability in compliance with this Responsible Disclosure Policy, Rupaya Pay commits to:

- Working with you to understand and validate the issue
- Addressing the risk (if deemed appropriate by Rupaya Pay)
- Rupaya Pay Security Team will investigate and respond to all valid reports. Our TAT for a new report is usually 3-5 business days; however, we prioritise investigations based on risk and other factors.
- In the event of duplicate reports, we recognise the first person (or submitter) of a qualifying security vulnerability. (Rupaya Pay determines duplicates and may not share details of the other reports.)
- Note that the use of Rupaya Pay services, including for the purposes of this program, is subject to Rupaya Pay’s Terms and Policies. We may retain any communications about security vulnerabilities that you report for as long as we deem necessary for program purposes, and we may cancel or modify this program at any time.

---

## How to Report a Vulnerability?

Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.

- Please submit the vulnerability report form with the necessary details to recreate the vulnerability scenario. This may include screenshots, videos or simple text instructions.
- Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
- When duplicates occur, we only award the first report that was received (provided that it can be fully reproduced).
- Only interact with accounts you own or with the explicit permission of the account holder.
- If the reported finding (vulnerability) can potentially extract information about our customers or systems or impair our system’s ability to function normally, please refrain from exploiting it. We must consider your disclosure a responsible one.
- While we appreciate the input of Whitehat hackers, we may pursue legal recourse if the identified vulnerabilities are exploited for unlawful gains, access to restricted customer or system information, or impairment of our systems.

---

##** Testing Guidelines**

To accommodate security researchers based outside of India or those without an active Indian phone number:

- Temporary Indian Numbers: You are permitted to use free, publicly available external websites/services that provide temporary or virtual Indian phone numbers for OTP/login requirements strictly for the purpose of security testing.

- Account Ownership: When submitting your Proof of Concept (PoC), please clearly note the temporary phone number used during your testing so our team can accurately validate and map the activity.

---

## Qualifying Vulnerabilities

Any design or implementation issue that is reproducible and substantially affects the security of Rupaya Pay customers is likely part of the scope of the program. The Vulnerability Rating Taxonomy is the baseline guide used for classifying technical severity. Common examples include:

* Injection vulnerabilities, including SQL and XML injection
* Cross-Site Scripting (XSS)
* Cross-Site Request Forgery (CSRF)
* Server-side or Remote Code Execution (RCE)
* Authentication/Authorisation flaws, including IDOR and authentication bypass
* Domain take-over vulnerabilities
* Account Takeover (while testing, use a test account for PoC)
* Directory Traversal
* Sensitive Information Disclosure that can affect Rupaya Pay’s customers, merchants, and/or overall Rupaya Pay brand
* Significant security misconfiguration with a verifiable/exploitable vulnerability (must be having PoC)
* Sensitive/Internal Credentials disclosed by Rupaya Pay or its employees posing a valid/verifiable risk to an in-scope asset (subject to investigation/authenticity of data).

---

## Program Exclusions – Out Of Scope Vulnerabilities

### **1. the disclosure platform Core Ineligible Findings**

Rupaya Pay strictly adheres to the disclosure platform’s default platform exclusions. The following common findings are automatically deemed out of scope and will be closed as **Not Applicable (N/A)**:

* Self-XSS or any self-exploitation mechanics.
* Standard Denial of Service (DoS/DDoS) exploits or traffic-flooding tests.
* Open Redirects (unless an immediate, high-severity downstream impact is proven).
* Missing cookie flags (`Secure`/`HttpOnly`) on non-session/non-sensitive cookies.
* Email authentication omissions (missing or weak SPF, DKIM, or DMARC records).
* Standard content spoofing, text injection, and basic CSS/HTML text manipulations.
* Technical version disclosures, banner identifications, and descriptive error messages (e.g., stack traces).
* Clickjacking on pre-authenticated or non-sensitive pages lacking `X-Frame-Options`.
* General SSL/TLS best-practice recommendations (e.g., weak ciphers, old TLS versions).
* Vulnerabilities requiring highly extensive, unrealistic, or complex user interactions.
* Vulnerabilities exclusively affecting end-of-life (EOL) or unpatched browsers and operating systems.

---

### **2. General Program & Triage Exclusions**

* **AI tools** may be used for drafting or tooling, but the vulnerability discovery, reproduction, and analysis must be independently validated by the researcher.
* Reports that are clearly **auto-generated**, **templated**, or **submitted without meaningful human verification** may be closed as **Not Applicable** or **Spam**, at Rupaya Pay's discretion.
* **Low-Context & Automated Submissions:** Reports generated entirely by automated scanners, AI-generated text, raw Threat Intelligence data, or generic "Advisory/Informational" reports lacking distinct Rupaya Pay context or hands-on testing.
* **Non-Security Defects:** Functional, layout, workflow, logical, or feature bugs that do not pose a direct risk to confidentiality, integrity, or availability.
* **Grace Period Restrictions:** Publicly disclosed CVEs and 0-days reported within **90 days** of their public release.
* Vulnerabilities discovered in assets of newly acquired companies within **90 days** of the official public announcement.
* **Mass submissions of similar vulnerability patterns** across multiple endpoints without individual validation.
* Researchers must **disclose any use of AI tools** in vulnerability discovery, testing, or report writing.
* **Regardless of AI assistance**, reports must demonstrate genuine human analysis, understanding, and validation of the vulnerability in our specific context.
* **Third-Party Integrations:** Security flaws in third-party applications or external tools built on top of the Rupaya Pay API (these must be reported directly to the respective vendor).

---

### ** 3. Web & Infrastructure Exclusions**

* **Authentication & CSRF:** Login/Logout CSRF, or any CSRF-able actions that do not require an established session or prior authentication to execute.
* **Infrastructure Noise:** Open ports or standard HTTP methods (`TRACE`, `OPTIONS`) reported without a functioning Proof of Concept (PoC) demonstrating a direct security exploit.
* **Information Leaks:** Full-path disclosure across any Rupaya Pay application, server, or digital asset.
* **Subdomain Validation:** Subdomain takeovers submitted without clear, verifiable evidence of successful takeover/control.
* **Phishing & UI Ambiguity:** IDN homograph attacks, Right-to-Left (RTL) language ambiguity, and hyperlink injection within out-bound system emails.
* **Policy Configurations:** Hardening opinions regarding application-wide password complexity or resets.
* **Hardening Headers:** Submissions concerning missing or default security headers—such as HSTS, X-Content-Type-Options, X-XSS-Protection, or custom CSP rules (excluding scenarios where a bypass of `nosniff` directly yields a high-impact exploit).
* **Sentry Instances** : Exposed or publicly accessible Sentry instances that lack actionable exploitability, internal data exposure, or functional security impact.

---

### **4. Rupaya Pay Mobile App-Specific Exclusions**

* **Compromised Environments:** Any client-side exploit that inherently requires a **rooted, jailbroken, or modified device**, or relies on a Man-in-the-Middle (MITM) architecture / physical access to an unlocked target device.
* **Card Verification Controls (CVV):** Reports focusing on the app's lack of CVV verification for credit/debit cards (this mechanism is entirely validated and controlled by the card-issuing bank, outside of Rupaya Pay’s reach).
* **Enumeration & Low-Risk Data:** Username/account enumeration via server responses, and the local storage or exposure of non-sensitive data within the device filesystem.
* **UI & Dependencies:** Tapjacking vulnerabilities, and unpatched CVEs in third-party libraries unless a functional PoC demonstrates an explicit, actionable exploit path targeting the Rupaya Pay application itself.

## **Reports not Eligible for Recognition**

All **out-of-scope assets** and vulnerabilities mentioned above are NOT eligible for recognition/rewards. Multiple reports of the same bug on different endpoints will be closed as duplicates if they require one fix.

---

## Reporting a security finding

We encourage security researchers to share the details of any suspected vulnerabilities with the Rupaya Pay Security Engineering Team by using the submission form on this page. Rupaya Pay will review the submission to determine if the finding is valid and has not been previously reported. At Rupaya Pay’s discretion, you may be eligible for monetary compensation for your efforts. Employees of Rupaya Pay or Rupaya Pay subsidiaries and vendors currently working with Rupaya Pay are not eligible for financial compensation. If you belong to any of the listed categories, you must specify that in your report. We require security researchers to include detailed information with steps for us to reproduce the vulnerability.

Thank you for helping to keep Rupaya Pay secure!
