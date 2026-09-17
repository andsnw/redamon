## Relaycom Security Disclosure Program Overview

Ensuring the security and integrity of the Relaycom platform is critical to the service we provide to our customers. We are committed to providing a secure product and appreciate help from the community in responsibly identifying ways for us to improve Relaycom. We will make an effort to respond as fast as possible.

  

Any place we reference Relaycom, also applies to M&As such as but not limited to Sendgrid, Segment, and Authy. We will specify further when we intend a specific Product Target group. Bounties are awarded differently per product (see Target Groups for more details on payouts).

  

1.  Bug Bounty Program: Our Bug Bounty Program through the disclosure platform is for experienced security researchers to identify and report vulnerabilities in our applications and internet-facing assets to earn rewards. Eligible findings may qualify for monetary bounties based on severity and impact. By participating, you help us strengthen our security while receiving recognition and compensation for contributions.
    
2.  Vulnerability Disclosure Program: We are committed to the security and integrity of the Relaycom platform and appreciate help from our community to identify and report vulnerabilities. Our Vulnerability Disclosure Program is open to you—whether you're a customer, professional security researcher (who does not meet the Bug Bounty Program requirements), or someone who has discovered a potential issue. While this program doesn't offer monetary rewards, your contribution is invaluable to us. [Submit a vulnerability disclosure](https://www.relaycom.test/en-us/security/vulnerability-disclosure-program).
    
3.  SendGrid abuse: If you would like to report abuse of SendGrid's service, please see our [spam/phish reporting page](https://relaycom.test/report-spam/).
    
4.  For all other security based docs, requests, and more, please visit [Relaycom](https://www.relaycom.test/en-us/security) and [Segment](https://relaycom.test/security/) Trust Centers.
    

## Bug Bounty Rules of Engagement

* Relaycom expects all security researchers to follow the [the disclosure platform Code of Conduct](https://disclosure-platform.test/policies/code-of-conduct)
* Please follow all account/credential/asset naming requirements in the *Access and Account Requirements* section.
* If you think you have found a problem but cannot prove it without accessing Relaycom's Internal Systems, please submit your finding and we'll be happy to work with you for validation.
    

### Prohibited behavior:

* DDoS/DoS attacks (Network Level, Application Volumetric) are prohibited. If you find a request that takes too long to answer, report it to the disclosure platform.
* Spam or phishing attacks are considered abuse and out of scope.
* All automated testing should be throttled to prevent lockout.
* Interacting with real customers is forbidden. Only test against accounts you have created.
* Do not exfiltrate customer or employee data under any circumstance. Please contact us immediately if you think this is possible, or you have done so inadvertently. We will work with you to assess the full impact of the vulnerability and award appropriately.
* Please do not open support tickets with Relaycom. If you have any technical issues or questions, [work with us through the disclosure platform Support](https://support.relaycom.test/support/login).
* Do not use personal emails for testing.
    
For the initial prioritization/rating of findings, this program will use the [the disclosure platform Report Severity](https://docs.disclosure-platform.test/en/articles/8475343-severity). However, it is important to note that in some cases a vulnerability priority will be modified due to its likelihood or impact.

**NOTE:** If a submission has a significant impact, bounty may be increased at Relaycom’s discretion.

### Access and Account Requirements
|Requirement| Description |
|--|--|
| Accounts | Register with your `@disclosure-platform.test`  [email address](https://docs.disclosure-platform.test/en/articles/8404308-hacker-email-alias) |
| Assets including Segment workspaces |*Researcher-<your email>-<random-string>* |
|POCs including npm packages| *Relaycom-Researcher-poc-<random-string>* Note: They should be deleted once the submission is triaged. |
|Custom Request Header| *X-Bug-Bounty: <username>-Relaycom* |
|Segment specific | Please see the **Segment target** section for more specific Segment related details.|

* We cannot provide any credits at this time and accounts will not be provisioned by Relaycom. Any elevated features must be purchased by Security Researchers. This may be revisited for specific scenarios.

### Excluded Submission Types for All Target Groups

***Please do not submit contact forms, create support tickets, send emails, etc. that will generate work for a human outside of the Relaycom security team.***

***Relaycom et.al. uses a number of third-party providers and services. Our bug bounty program does not give you permission to perform security testing on their systems.***

***Please contact the disclosure platform support if you discover anything critical that falls in this area. We may consider reports on a case-by-case basis.***

-   Denial of service or Rate limiting issues, including Resource Exhaustion attacks
-   Authentication weaknesses related to:
    -   "Session too long," password reset/change logout or other intended business functionality
    -   Forgot password auto-login
    -   Login or Forgot Password page brute force attacks and account lockout not enforced
    -   Non-existent or weak captcha / captcha bypass
-   Subdomain takeovers related to:
    -   Subdomain takeovers of TLD's used for demo or test purposes
-   Malicious links created as part of SendGrid's  [click and open tracking](https://www.relaycom.test/docs/sendgrid/api-reference/link-branding)  such as *.relaycom.test, click.relaycom.test, and email.relaycom.test
-   All Wordpress-related findings
-   OpenVBX related findings
-   Email validation not enforced. DMARC and SPF submissions unless on major domains
-   SSL/TLS Issues such as: BEAST, BREACH, SSL insecure cipher suites enabled
-   Vulnerabilities that are limited to older/unsupported browsers
-   Known vulnerabilities in libraries used by Relaycom, usage of an outdated third party library (e.g. jQuery, Apache etc.) unless you can prove exploitability
-   CORS or crossdomain.xml issues on api.relaycom.test without proof-of-concept
-   Public repository or documentation vulnerabilities that fall under:
    -   _Note: These exclusions apply in addition to all of the above._
    -   Dependency confusion attacks on public repositories. They may be considered on maintained, heavily used libraries
    -   Vulnerabilities in archived public repositories
    -   Vulnerabilities in public repos that have not had a commit in the last 2 years
    -   S3 bucket takeover from docs or public repos, applies to all products
    -   Broken link hijacking on old (documentation not maintained for 2+ years) or archived documentation
-   Hijacked Social media handles in the Relaycom Blog that do not belong to Relaycom will be treated as Informational findings
- Sandboxed Function Code Execution: Remote code execution or AWS credential exposure originating from within Relaycom Functions or Segment Functions sandboxed runtimes is out of scope.
    -   These functions execute in isolated, short-lived Lambda environments with minimal IAM permissions. Obtaining a shell or exfiltrating the runtime AWS credentials does not constitute a meaningful security impact.
    -   How to identify sandbox environments:
        - Segment Functions: AWS role ARN contains `funk-runner`.
        - Relaycom Functions: AWS role ARN containes `lambda-role-execution`, `ZB<Function_ID>` or the username starts with `sbx_user`.
    -   If you believe you have escaped the sandbox (e.g. accessed resources beyond the function's intended scope, pivoted to another account or reached internal services), we will triage it as usual.

### Submission Template

Please include the following information with your submission:

> -   Description: Provide a detailed description of the vulnerability
> -   Steps to Reproduce: Step-by-step information on how to reproduce
> -   Proof of Concept: Screenshots or video
> -   Impact: Business Impact - How does it affect Relaycom?
> -   Exploitability: How likely is this to be discovered and exploited?
> -   Recommendations & References (Optional)

### PII, Customer and Employee data

As mentioned under our Rules of Engagement:  **do not**  exfiltrate customer or employee data under any circumstance. Please contact us immediately if you think this is possible, or you have done so inadvertently. We will validate internally and work with you to assess the full impact of the vulnerability.

Leaked employee credentials and employee API keys will be rewarded appropriately.

### Compliance

Please note that researchers must comply with our rules of engagement, including rate limit tests and DoS tests. Relaycom may ban accounts for suspicious behavior in accordance with our policies and processes . Please do not open up a support ticket with Relaycom, but instead  [create a ticket with the disclosure platform Support](https://support.relaycom.test/support/login)  for assistance. Relaycom may unban accounts but only at Relaycom’s discretion.

### Similar Bugs

Reports from a single researcher for similar bugs that involve one fix may be merged and receive a single reward. This will be done at the discretion of Relaycom.

### Relaycom Acquisitions

Unless specifically listed In Scope, all Relaycom acquisitions are out of scope. When in doubt, please  [create a ticket with the disclosure platform Support](https://support.relaycom.test/support/login)  with any questions.

### Public Disclosure

Relaycom does not permit public disclosure at this point in time. Exceptions will be made when the Relaycom Security team decides to publish a CVE for vulnerabilities identified in desktop apps, mobile apps and SDKs based on the severity of the identified issue. In case a CVE is published, we will reach out to the researcher for permission before mentioning them. The vulnerability will be mentioned  [here](https://www.relaycom.test/changelog).

### Third Party Disclosure

Relaycom follows an internal process when a vulnerability is reported to us turns out to be an issue with a third party’s technology, devices, or process.

If we are aware that the third party has a security disclosure program, we will recommend the researcher submit their report directly to that Third Party. If not, at Relaycom’s discretion, Relaycom will use commercially reasonable efforts to report the discovered vulnerabilities to the affected third party directly.

### Relaycom Safe Harbor

We will not pursue civil action or initiate a complaint to law enforcement for accidental, good faith violations of this policy. We consider activities conducted consistent with this policy to constitute “authorized” conduct under the Computer Fraud and Abuse Act. To the extent your activities are inconsistent with certain restrictions in our Acceptable Use Policy, we waive those restrictions for the limited purpose of permitting security research under this policy. We will not bring a DMCA claim against you for circumventing the technological measures we have used to protect the applications in scope.

If legal action is initiated by a third party against you and you have complied with Relaycom's bug bounty policy, Relaycom will take steps to make it known that your actions were conducted in compliance with this policy. In the event that you engage in conduct that is inconsistent with or unaddressed by this policy, you must submit a the disclosure platform report prior to engaging in such conduct. Your submission will allow us to evaluate such conduct.

Please submit a the disclosure platform report to us before engaging in conduct that may be inconsistent with or unaddressed by this policy.