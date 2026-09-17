#Program Details

We appreciate the efforts of independent security researchers who help us improve the security of our systems.
If you believe you have discovered a security vulnerability in an in-scope asset, please submit a report with sufficient detail for our team to reproduce and validate the issue.
We are committed to reviewing all legitimate submissions and working with researchers to understand, triage, and remediate confirmed vulnerabilities.
Good luck, and happy hunting!

#Severity Assessment
Refractive Labs follows the platform's severity rating methodology when evaluating reported vulnerabilities.
Please note that severity may be adjusted based on factors such as:

* Exploitability
* Business impact
* Data sensitivity
* Required privileges
* Environmental controls
* Real-world risk

The final severity determination rests with the Refractive Labs Security Team.

#Testing Guidelines

* If account registration is required, please use your @disclosure-platform.test email alias whenever possible.
* Only test against assets explicitly listed as in scope.
* If you identify a vulnerability that provides access to sensitive data, internal systems, or privileged functionality, do not proceed beyond what is necessary to demonstrate impact.
* Avoid actions that may negatively affect the availability, integrity, or performance of our systems.
* If using automated scanning tools, include your the disclosure platform username in requests whenever feasible using a custom header:
X-Researcher: your_username

#Reporting Guidelines
To help us investigate efficiently, please ensure your report contains:

* Clear description of the issue
* Affected asset(s)
* Reproduction steps
* Proof of Concept (PoC)
* Relevant screenshots, logs, or evidence
* Impact assessment

Additional guidelines:

* Submit one vulnerability per report unless multiple issues must be chained together to demonstrate impact.
* Multiple vulnerabilities resulting from a single underlying root cause may be treated as one issue.
* Duplicate reports will generally be closed in favor of the first reproducible submission.
* Researchers may be requested to assist with validation or remediation verification activities.


#Rules of Engagement
By participating in this program, you agree to:

* Keep all findings and communications confidential.
* Not disclose vulnerabilities to any third party without prior written authorization.
* Not access, modify, destroy, or exfiltrate data that does not belong to you.
* Not disrupt, degrade, or impair Refractive Labs services or business operations.
* Not conduct social engineering, phishing, spam, physical security testing, DoS, or DDoS attacks.
* Not intentionally compromise the privacy, security, intellectual property, or commercial interests of Refractive Labs, its brands, employees, partners, or customers.
* Destroy vulnerability-related artefacts once the report has been resolved and closed.

Failure to comply with these rules may result in report ineligibility and removal from the program.

#Program Exclusions – Out of Scope Vulnerabilities

* Refractive Labs adheres to the platform's Core Ineligible Findings policy.

* Additionally Out of Scope- 

CAPTCHA-related issues
Missing rate-limiting or account lockout mechanisms
Open redirects without demonstrated security impact
Self-XSS
Host Header Injection without demonstrated impact
Clickjacking without demonstrated impact
Missing HTTP security headers
Missing cookie attributes
Banner or version disclosure
SPF, DKIM, or DMARC findings
SSL/TLS best-practice issues
OPTIONS / TRACE methods enabled
Error messages that do not expose sensitive information
Login or Logout CSRF
CSV Injection without demonstrated impact
Content spoofing or text injection without demonstrated security impact
Third-party vulnerabilities that do not affect Refractive Labs-owned assets
Vulnerabilities requiring physical access to a device
Vulnerabilities requiring outdated browsers or operating systems
Vulnerabilities requiring Man-in-the-Middle attacks
Social engineering, phishing, spam, DoS, or DDoS attacks
Issues that require unlikely or unrealistic user interaction

Refractive Labs reserves the right to determine the final validity, impact, and eligibility of all reported vulnerabilities.

#Safe Harbor
When conducting vulnerability research in accordance with this policy, we consider such activity to be authorized and conducted in good faith for the purpose of improving the security of our systems and services.
Refractive Labs will not pursue legal action against researchers who:

* Follow this policy
* Act in good faith
* Avoid privacy violations, service disruption, and data destruction
* Promptly report discovered vulnerabilities
* Comply with applicable laws and regulations

If you are uncertain whether a particular testing activity is permitted under this policy, please contact us through the disclosure platform before proceeding.

Thank you for helping improve the security of Refractive Labs and its portfolio of brands.