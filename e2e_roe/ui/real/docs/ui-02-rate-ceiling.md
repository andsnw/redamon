# **DO NOT** submit ANY forms within ANY Skybridge Connect systems.
📜 The Rules of Engagement: Our VDP Guidelines
Welcome, researchers! To ensure a productive and positive partnership, we've established the following guidelines for our Vulnerability Disclosure Program. We ask that you read and adhere to these rules throughout your testing.

✈️ Our Core Principles: Your Code of Conduct
Your trust is essential to us. We expect all researchers to act in good faith and uphold the highest ethical standards.

# **Testing Window:** Please limit all research and testing from Monday 2PM GMT to Friday 11PM GMT

Rule	Description
* Act in Good Faith	Your activities should be focused on finding and reporting vulnerabilities, not disrupting, damaging, or harming Skybridge Connect, our systems, our data, or our users.
* Protect Our Data	Exfiltrating or copying any data is strictly prohibited. Your testing should be limited to verifying the existence of a vulnerability.
* Respect User Privacy	You must not access, modify, or compromise the data or privacy of our customers or employees. Only interact with accounts you own or for which you have explicit, documented permission.

🔧 Technical Guidelines for Testing
To ensure the stability of our services, please follow these technical rules.

* **Identify Yourself:** Please add a custom HTTP header to all your testing traffic. This helps our team distinguish your research from malicious activity.

*   **Header:** X-Researcher-Research: [Your-H1-Username]

* **Responsible Automated Scanning:** Automated scanning is welcome, but it must be throttled to a reasonable rate to avoid impacting our services. As a guideline, please limit requests to 10 requests per second. Excessive scanning may lead to your IP being blocked.

# **DO NOT** submit ANY forms within ANY Skybridge Connect systems.

📝 Reporting & Disclosure: How to Work With Us
Clear communication is key to a successful VDP.

* **Prompt & Detailed Reports:** Report any potential vulnerability to us promptly through the disclosure platform. High-quality reports are essential for our team to validate and fix issues. 

Your report must include:
* **Detailed, Reproducible Steps:** If we cannot reproduce the issue, we cannot triage it.
* **One Vulnerability Per Report:** Please submit a single, distinct vulnerability in each report. The only exception is when chaining vulnerabilities is necessary to demonstrate impact.
* **First-to-Find:** We operate on a first-come, first-served basis. When duplicate vulnerabilities are reported, we will only award the first reproducible report received.
* **Confidentiality & Disclosure:** To protect our users, please do not discuss this program or any vulnerabilities (even resolved ones) outside of the disclosure platform without our express written consent. Always follow the platform's disclosure guidelines.

🎯 Target-Rich Environment: Qualifying Vulnerabilities
We are most interested in vulnerabilities that have a clear and demonstrable security impact. We encourage creative and impactful findings. 

Examples include:

**Web & Application Security:**	
* Cross-Site Scripting (XSS)
* Cross-Site Request Forgery (CSRF)
* Insecure Direct Object References (IDOR)
* Open Redirects (with demonstrated impact)

**Authentication & Access Control:**	
* Authentication or Authorization Bypasses
* Privilege Escalation
* Directory Traversal

**Data & Injection:** 
* Flaws	Injection Vulnerabilities (e.g., SQL, LDAP, XML, command)
* Server-Side Code Execution (RCE)

**Information & Configuration:**	
* Information Disclosure (with proven, real-world impact)
* Security Misconfigurations that expose sensitive data or enable a realistic attack scenario


⛔ Out of Scope: What Not to Report
The following findings are considered out of scope. Reports for these issues will not be accepted.

Reports Lacking Evidence:
* Vulnerabilities without clear, reproducible steps or a working proof-of-concept (PoC).
* Subdomain takeovers without a complete PoC.

Non-Actionable or Third-Party Issues:
* Flaws in networking protocols, industry standards, or third-party software not controlled by Skybridge Connect.
* Issues related to code, infrastructure, or services not owned or operated by Skybridge Connect.

Unrealistic Scenarios:
* Vulnerabilities requiring highly unlikely user interaction (e.g., a user manually pasting an XSS payload into their own browser).
* Vulnerabilities that require physical access to a device, hardware modification, or social engineering.

Prohibited Targets & Actions:

**DO NOT** target onboard aircraft systems or avionics.
**DO NOT** target internal corporate IT systems or employee-only portals.
**DO NOT** perform Denial of Service (DoS) or resource exhaustion attacks.
**DO NOT** engage in social engineering of Skybridge Connect staff, contractors, or customers.
**DO NOT** attempt to create accounts within ANY Skybridge Connect systems.
**DO NOT** submit ANY forms within ANY Skybridge Connect systems.

Thank you for your partnership in helping keep Skybridge Connect and our users safe! We look forward to your contributions.