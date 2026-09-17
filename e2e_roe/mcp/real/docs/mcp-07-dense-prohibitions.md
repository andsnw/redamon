Sakura Financial Public Vulnerability Disclosure Program (VDP) Overview
The security and privacy of your data are our utmost concern. Sakura Financial abides by rigorous security policies and implements robust systems to protect user data. Sakura Financial looks forward to working with the security community to find vulnerabilities in order to keep our businesses and customers safe. 

Response Targets 
Sakura Financial will make a best effort to meet the following response targets for hackers participating in our program: 
• Time to first response (from report submit) - 2 business days 
• Time to triage (from report submit) - 2 business days 
• Time to resolution - depends on severity and complexity

We’ll try to keep you informed about our progress throughout the process. 

Disclosure and Confidentiality Policy 
• As this is a private program, please do not discuss the program or any vulnerabilities (even resolved ones) outside of the program without express written consent from the organization. 
• Follow the disclosure platform’s disclosure guidelines.
________________________________________
Sakura Financial is a complex global brand that includes many entities and products. The Sakura Financial Vulnerability Disclosure Program is an unpaid program which is intended to allow for responsible disclosure of vulnerabilities discovered on Sakura Financial assets.
If valid, in-scope findings are reported, the reporter will be recognized with “reputation points” and may receive an invite to the private Sakura Financial Bug Bounty Program. Sakura Financial reserves the right to extend invitations to their private Sakura Financial Bug Bounty Program on a case-by-case basis.

Program Rules 
•	All of the tests must not violate any law, or compromise any data that is not your own.
•	You must be the first reporter to report the issue to us. When duplicates occur, we only award the first report that was received (provided it can be fully reproduced). 
•	When submitting a vulnerability, please provide detailed reports with reproducible steps for verification. If the report does not contain sufficient detail to reproduce the issue, the issue may not be eligible for an award.
•	Do not gain access to another user's account or their confidential information. Authenticated testing is OUT OF SCOPE for testing.
•	Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.
•	Submit one vulnerability per-report, unless you need to chain vulnerabilities to provide impact.
•	Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.
•	Make a good faith effort to avoid privacy violations, tampering and destruction of data, and interruption or degradation of our service. 
The following actions are not permitted:
•	Any intrusive tests or exploits that could crash or disable a service (i.e. Denial of Service)
•	Denial of service, spam, and social engineering (e.g. phishing, vishing, smishing) are prohibited.
•	Network layer Man-in-the-Middle (MITM) attacks
•	Testing that could result in damage to the systems or data, including modification, tampering of data, destruction of data, or degradation of services
•	Excessive network scanning that could saturate firewall connection tables or network resources
•	Brute-force attacks or testing of any accounts is strictly prohibited
•	Physical attacks against any physical facility owned by MUBK
________________________________________
Testing and Guidance
•	Testing should be limited only to the assets explicitly outlined in the scope.
• 	Comply with Code of Conduct and Core Ineligible Findings
      https://disclosure-platform.test/policies/code-of-conduct
      https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings
________________________________________
Out of Scope Vulnerabilities
When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) security impact of the bug. The following issues are considered out of scope:
•	Any submission determined to be low risk, based on unlikely or theoretical attack vectors, requiring significant user interaction, or resulting in minimal impact
•	Reports from automated tools or scans
•	Best practice reports without a valid exploit (e.g. use of "weak" TLS ciphers)
•	Social Engineering/Phishing 
•	Physical security 
•	Attacks requiring MITM or physical access to a user's device 
•	Denial of Service attacks 
•	Missing best practices in SSL/TLS configuration 
•	Software version disclosure / banner identification issues / descriptive error messages / missing security headers 
•	Missing email best practices (invalid, incomplete or missing SPF/DKIM/DMARC records, etc.) 
•	Missing Cookie Flags (Secure/HTTPOnly) 
•	Cookie scoped to parent domain or anything related to the path misconfiguration and improperly scoped • CSRF with minimal impact i.e. login CSRF, logout CSRF, etc. 
•	The submission of form data via HTTP sites 
•	Clickjacking on pages with no sensitive actions 
•	Vulnerabilities only affecting users of outdated or unpatched browsers 
•	Any XSS that requires Flash. Flash is disabled by default in most modern browsers, thus greatly reducing the attack surface and associated risk. 
•	Self-XSS, which includes any payload entered by the victim 
•	Issues that require unlikely user interaction 
•	Any vulnerabilities requiring significant and unlikely interaction by the victim, such as disabling browser controls 
•	Publicly accessible login panels
•	Full Path Disclosure 
•	Lack of autocomplete attribute on web forms
•	IP address disclosure 
•	Cross-Origin Resource Sharing (CORS) without a valid attack scenario or Proof-of-Concept 
•	OPTIONS/TRACE/DELETE/PUT/WEBDAV or any other HTTP Methods accepted by the server which do not specifically show a valid attack scenario 
•	Vulnerabilities involving stolen customer credentials or credentials not related to operations of the organization
•	Exposed credentials that are either no longer valid, or do not pose a risk to an in-scope asset 
•	Vulnerabilities on third party libraries without showing specific impact to the target application (e.g. a CVE with no exploit) 
•	Security Practices where other mitigating controls exist i.e. missing security headers, etc. 
•	Stack Traces, Path Disclosure, Directory Listings 
•	HTTP Trace Method 
•	Comma Separated Values (CSV) injection without demonstrating a vulnerability 
•	Content spoofing and text injection issues without showing an attack vector/without being able to modify HTML/CSS 
•	Cross-Site Request Forgery (CSRF) on unauthenticated forms or forms with no sensitive actions 
•	Disclosure of server or software version numbers 
•	Hypothetical subdomain takeovers without supporting evidence  
•	Perceived security weaknesses without concrete evidence of the ability to compromise a user (e.g., missing rate limits, missing headers, etc.)  
•	Brute force issues on non-authentication endpoints 
•	Tabnabbing 
•	Public Zero-day vulnerabilities within 9 months after a CVE assignment will be awarded on a case-by-case basis.
•	Open redirect will be evaluated to no more than a low impact unless there is additional demonstrated security impact.
Notes about IDOR Vulnerabilities Researchers must be able to prove a feasible way to gain an ID as an attacker and we will not accept reports where IDs are being brute forced.
•	Example: An ID is 19 characters long. To guess this ID, an attacker will have to calculate 10^19 combinations which is not in the range of an online brute force attack. IDOR vulnerabilities with access to unimportant data will also not be eligible for bounty.
Out of Scope bugs for Android apps
•	Any URIs leaked because a malicious app has permission to view URIs opened
•	Sensitive data in URLs/request bodies when protected by TLS
•	Lack of obfuscation and binary protection
•	Any kind of sensitive data stored in app private directory
•	Runtime hacking exploits using tools like but not limited to Frida/ Appmon (exploits only possible in a jailbroken environment & root permission)
•	Shared links leaked through the system clipboard.
•	Intent or URL Redirection leading to phishing
•	Third party library 0day
Out of Scope bugs for iOS apps
•	Lack of Exploit mitigations i.e., PIE, ARC, or Stack Canaries
•	Absence of certificate pinning
•	Path disclosure in the binary
•	User data stored unencrypted in the app private directory
•	Lack of obfuscation is out of scope
•	Lack of jailbreak detection is out of scope
•	OAuth & app secret hard-coded/recoverable in IPA
•	Crashes due to malformed URL Schemes
•	Lack of binary protection (anti-debugging) controls
•	Snapshot/Pasteboard leakage
•	Runtime hacking exploits using tools like but not limited to Frida/ Appmon (exploits only possible in a jailbroken environment)
•	Third party library 0day is out of scope
•	URL Redirection leading to phishing
•	Mail headers lacking proofed impact will be accepted at our discretion.
•	Rate Limiting
*Special Note: Subdomain takeovers are in scope but will be accepted at a low severity at this time.

Safe Harbor
Any activities conducted in a manner consistent with this policy will be considered authorized conduct and we will not initiate legal action against you. If legal action is initiated by a third party against you in connection with activities conducted under this policy, we will take steps to make it known that your actions were conducted in compliance with this policy. This safe harbor does not apply if any part of the security researcher’s actions violates any part of this policy. Furthermore, without prior written consent from Sakura Financial, the disclosure of any information to third parties or the public, including the contents of reports to the program and communications related to the investigation of the program, is not permitted.
Thank you for helping keep Sakura Financial and our users safe!

【Legal】
Cooperation with Requests from Investigative Authorities, Financial Supervisory Authorities, and Courts in Japan and Other Countries
・In the event of requests for inspection, supervision, or judicial proceedings from investigative authorities, financial supervisory authorities, courts, etc. in Japan, the United States, or other countries/states directed at Sakura Financial, security researchers must cooperate by submitting materials and reports related to tests conducted by these agencies or Sakura Financial, and by cooperating with on-site investigations conducted by these agencies or Sakura Financial. The obligations under this section shall continue even after the completion of the tests.

Matters to be Complied with
・Security researchers must comply with all applicable laws when conducting tests, including but not limited to Japanese laws (such as the Japanese Personal Information Protection Law, guidelines on personal information protection in the financial sector, and the EU's GDPR, as listed in the URL below). The security researchers' lack of knowledge of Japanese laws or other applicable laws does not exempt them from their responsibilities to Sakura Financial.
https://www.japaneselawtranslation.sakura-financial.test/en/laws/view/4241/en
https://www.japaneselawtranslation.sakura-financial.test/en/notices/view/165
・Security researchers must strictly adhere to the obligations (including best-effort obligations) under the platform's policies when conducting tests. If security researchers violate the platform's policy obligations (including best-effort obligations) even once while conducting tests, it will be treated as a violation of this policy, and the security researchers will be liable for damages to Sakura Financial. The obligations under this section shall continue even after the completion of the tests.
・Notwithstanding the provisions of the disclosure platform General Terms and Conditions or any other agreements, if security researchers violate this Policy or the platform's policies (including policies that stipulate best-effort obligations) even once while conducting tests and cause damage to Sakura Financial, the security researchers must compensate Sakura Financial for all damages (including special damages such as loss of customer information and service interruptions). Notwithstanding the provisions of the disclosure platform General Terms and Conditions or any other agreements, the security researchers' liability for damages to Sakura Financial shall have no upper limit or restriction, except as provided by law. The obligations under this section shall continue even after the completion of the tests.
* https://disclosure-platform.test/terms/general
・Notwithstanding the provisions of the disclosure platform General Terms and Conditions or any other agreements, if security researchers violate this Policy or the platform's policies (including policies that stipulate best-effort obligations) even once while conducting tests, Sakura Financial may demand the immediate cessation of the tests by the security researchers and may also seek an injunction from the court. If Sakura Financial demands the cessation of the tests from the security researchers, the security researchers must immediately cease the tests.
* https://disclosure-platform.test/terms/general

Strictly Prohibited Actions
・Security researchers must not test credentials or any vulnerability against our customers.
・Security researchers must not engage in actions that cause interruption or degradation of Sakura Financial's services.
・Security researchers must not use tools that cause interruption or degradation of Sakura Financial's services, tools that enable access to, destruction, or alteration of Sakura Financial's customer information, or any other tools that may cause damage to Sakura Financial.
・Security researchers must not conduct tests that are deemed unsafe.
・Security researchers must not disclose or leak any information about Sakura Financial and its customers that they have learned during the tests to third parties without prior consent from Sakura Financial, both during and after the tests. The obligations under this section shall continue even after the completion of the tests.
・Security researchers must not use Sakura Financial's confidential information for purposes other than the tests. The obligations under this section shall continue even after the completion of the tests.
・Security researchers must take necessary and appropriate measures to prevent the leakage, loss, or damage of Sakura Financial's confidential information and to ensure the safe management of Sakura Financial's confidential information that they have learned during the tests. The obligations under this section shall continue even after the completion of the tests.
・If security researchers become aware of any incidents that involve the leakage of Sakura Financial's confidential information or any facts that may hinder the confidentiality protection of Sakura Financial's confidential information, they must immediately report to Sakura Financial and take emergency measures to minimize the damage caused by the incident, regardless of the responsibility for the occurrence of the incident. They must also promptly submit a detailed report of the incident and a proposed response plan to Sakura Financial in writing. The obligations under this section shall continue even after the completion of the tests.
・Security researchers must not delegate the tests to third parties.
・Sakura Financial may, at any time and for any reason, refuse and prohibit security researchers from participating in this program by notifying them. After such notification, security researchers must not conduct tests.
・Security researchers must not conduct tests after the program has ended.

Governing Law and Jurisdiction
　　　・The governing law for the tests and the contract related to this program between Sakura Financial and the security researchers shall be Japanese law. The obligations under this section shall continue even after the completion of the tests.
　　　・For all disputes related to the tests and this program between Sakura Financial and the security researchers, both parties agree that the Tokyo District Court in Japan shall have exclusive jurisdiction as the court of first instance. The obligations under this section shall continue even after the completion of the tests.