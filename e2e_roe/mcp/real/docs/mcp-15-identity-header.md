Southbank Financial looks forward to working with the security community to find vulnerabilities in order to keep our businesses and customers safe.

# Disclosure Policy
* Please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

# Program Rules
* If you happen to identify a security vulnerability on a target that is not in scope, but it demonstrably belongs to Southbank Financial, please submit the report for review
* Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue may not be marked as triaged.
* Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
* When duplicates occur, we only triage the first report received (provided that it can be fully reproduced).
* Only interact with accounts you own or with the explicit permission of the account holder.

# Session Layer: HTTP Headers
Researchers should add headers to requests such as: 
* “X-Researcher-Research: [H1 username]”

#Focus Areas
* Cross Site Scripting (XSS)
* Cross Site Request Forgery (CSRF)
* Insecure direct object references
* Injection Vulnerabilities
* Authentication Vulnerabilities
* Server-side Code Execution
* Privilege Escalation
* Significant Security Misconfiguration (when not caused by user)
* Any out of the box issues which could lead to compromise or leakage of data and directly affect the confidentiality or integrity of user data of which affects user privacy.
Out of Scope
*All vulnerabilities discovered and reported on other targets (including subdomains) will be accepted. These submissions will be marked; Not Applicable; to prevent negative ratings. 

#Prohibited Testing
*Do NOT conduct non-technical attacks such as social engineering, phishing or unauthorized access to infrastructure are not allowed.
*Do NOT test the physical security of Southbank Financial offices, employees, equipment, etc.
*Do NOT perform any attack that could harm our services (E.g.: DDoS/Spam)
*Do NOT attack, in any way, our end users, or engage in trade of stolen user credentials.
*Do NOT use automated scanners and tools to find vulnerabilities are strictly not allowed.
*Do NOT Perform automated/scripted testing of web forms, especially Contact Us forms that are designed for customers to contact our support team.
*You may investigate or target vulnerabilities against your own or test accounts, but testing must not disrupt or compromise any data or data access that is not yours.

# Vulnerability Program Exclusions
*Pivoting, scanning, and vulnerability exploitation.
*Exfiltration of data from Southbank Financial systems.
*Email spoofing
*Missing or incorrect SPF/DMARC/DKIM records of any kind
*Descriptive error messages (e.g. Stack Traces, application or server errors).
*Fingerprinting / banner disclosure on common/public services.
*Clickjacking and issues only exploitable through clickjacking.
*Login/Logout/Unauthenticated/low-impact/anonymous user CSRF.
*Presence of application or web browser ‘autocomplete’ or ‘save password’ functionality.
*Lack of Secure/HTTPOnly flags on non-sensitive Cookies.
*Lack of Security Speedbump when leaving the site.
*Weak Captcha / Captcha Bypass
*Forgot Password page brute force and account lockout not enforced.
*Username / email enumeration via Login Page or Forgot Password error message
*Any missing HTTP security headers
*SSL Issues, e.g.
*SSL Attacks such as BEAST, BREACH, Renegotiation attack
*SSL Forward secrecy not enabled
*SSL weak / insecure cipher suites
*Vulnerabilities affecting users of outdated browsers

Thank you for helping keep Southbank Financial and our users safe!
