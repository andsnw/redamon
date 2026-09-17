# Vulnerability  Disclosure Policy
# Protecting Our Digital Landscape
The security of our systems, assets, and infrastructure is fundamental to everything Ardent Defence does. We understand the importance of creating resilient solutions that can withstand ever-evolving threats to our systems, services and data. To that end, we value the contributions of the security research community in identifying vulnerabilities and helping us safeguard our operations.

We encourage responsible vulnerability disclosure as a means of strengthening the digital environment which we all live in today. If you believe you have found a vulnerability in any of Ardent Defence’s systems, we invite you to report it to us through the secure channels detailed below.

#Reporting a Vulnerability
In the submission, please ensure you include details of:
- System Details: Identify the system, service, or platform where the vulnerability exists (e.g., specific webpage, IP address).
- Description of the Vulnerability: Provide a clear explanation of the vulnerability type (e.g., XSS, authentication bypass).
- Proof of Concept: Steps to reproduce the issue, including any necessary diagrams, screenshots, scripts or videos, to assist in our validation.
We aim to provide first Ardent Defence to your submission within one working day and triage of the report within five working days. We will work with you throughout the process to ensure that the issue is resolved in a timely and transparent manner.

#Guidelines for Responsible Disclosure
Ardent Defence appreciates the responsible disclosure of security vulnerabilities. To facilitate a productive and legal collaboration, we request that researchers:
* Maintain Integrity: Avoid using any tools or techniques that could compromise or degrade Ardent Defence systems (e.g. denial-of-service attacks, brute-force attempts, or intrusive scanning).
* Respect Rate Limits: Traffic must be restricted to a maximum of 10 requests per second per endpoint. Automated tools or scanners should be configured accordingly.
Where possible, use a custom `User-Agent` string such as: **Ardent Defencevdp_<h1_username>**, and consider adding a header such as: **X-Researcher: <h1_username>**
As part of responsible security research, we recommend reviewing and adhering to [RFC 9511](https://www.ardent-defence.test/rfc/rfc9511), which outlines guidelines for conducting coordinated vulnerability disclosure activities.
* Limit Access: Only access the minimum data required to demonstrate a vulnerability.
* Stay Within the Law: Ensure that your research complies with all relevant legal frameworks, both locally and internationally.  This includes complying with applicable privacy and data protection laws. 
* Data security: Where technically feasible, refrain from accessing data which is not your own. In all circumstances, do not modify or share data that is not your own.  In particular, you must not, share, redistribute or fail to properly secure data retrieved from Ardent Defence’s systems or services. 
* Confidentiality: Keep details of the vulnerability confidential to Ardent Defence until we have notified you that it has been resolved. Even when the vulnerability has been resolved, any disclosure that you wish to make regarding the vulnerability requires our express consent must not be linked in any way to Ardent Defence.  You must securely delete all data retrieved during the research as soon as it is no longer required or within one calendar month of the date when we notify you that the vulnerability has been resolved (whichever occurs first). Ardent Defence requires a minimum of 120 days to validate and address the issue.
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

By adhering to these guidelines, you are helping us to ensure that our systems remain secure without compromising operational capabilities or the privacy of our users.

#What You Can Expect from Us
Upon submitting a vulnerability report, you can expect:
- Prompt Acknowledgement: We will confirm receipt of your report within one working days.
- Clear Communication: Our team will engage with you to fully understand the nature and scope of the vulnerability.
- Triage and Resolution: We will prioritise and remediate vulnerabilities based on their impact, severity, and complexity. Progress updates will be provided throughout.
- Final Confirmation: Once the issue is resolved, we will notify you and may invite you to verify the fix.

#Safe Harbour
Ardent Defence recognises and appreciates the efforts of security researchers acting in good faith under this program. Research that complies with these guidelines will be considered as authorised by Ardent Defence (a “Safe Harbour”). 
Public disclosure of vulnerabilities before they have been addressed, without our explicit consent, will be considered non-compliant with the terms of this policy and may result in the loss of Safe Harbour protection and Ardent Defence taking legal action against you.
Please note that this policy does not extend to third party systems or services that Ardent Defence does not control, and those entities may choose to take legal action independently.

# Program Rules
* Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue may not be marked as triaged.
* Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
* When duplicates occur, we only triage the first report received (provided that it can be fully reproduced).
* Multiple vulnerabilities caused by one underlying issue will be treated as one valid report.
* Social engineering (e.g., phishing, vishing, smishing) is prohibited.
* Only interact with accounts you own or with explicit permission of the account holder.

# Core Ineligible Findings
**When reporting potential vulnerabilities, please consider (1) realistic attack scenarios, and (2) the security impact of the behaviour. Below, you will find the most common false positives we encounter. The following issues will be closed as invalid except in rare circumstances demonstrating clear security impact:**

[Check here for the disclosure platform’s Core Ineligible Findings](https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings)

#Legalities and Responsibilities
Ardent Defence's vulnerability disclosure policy is aligned with established industry best practices. However, it does not grant permission to act outside the bounds of applicable law. Researchers are expected to abide by all applicable legal requirements, and this policy does not indemnify individuals against any legal actions taken by other organisations as a result of unauthorised activities.
