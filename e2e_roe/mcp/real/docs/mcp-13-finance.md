**Purpose** 

This policy is intended to give security researchers and other participants in the security community clear guidelines under the Indexa Analytics Vulnerability Disclosure Program for conducting vulnerability discovery activities directed at web properties owned or operated by Indexa Analytics, its affiliates, or subsidiaries and submitting discovered vulnerabilities to Indexa Analytics. Your participation in the program is voluntary and subject to the terms and conditions set forth on this page. By submitting a report, you acknowledge and agree to the terms and conditions contained in this Policy. You also acknowledge that, to the extent they are not inconsistent with this Policy; you are subject to: 

[the disclosure platform’s Disclosure Guidelines](https://disclosure-platform.test/disclosure-guidelines/)

[Finder Terms and Conditions](https://disclosure-platform.test/terms/finder/)

[General Terms and Conditions](https://disclosure-platform.test/terms/general/)

**Guidelines** 

- Your activities are limited exclusively to: 

Testing to detect a vulnerability or identify an indicator related to a vulnerability; or 

Sharing with, or receiving from, Indexa Analytics information about a vulnerability or an indicator related to a vulnerability. 

- You do no harm and do not exploit any vulnerability beyond the minimal amount of testing required to prove that a vulnerability exists or to identify an indicator related to a vulnerability. 

- You avoid intentionally accessing the content of any communications, data, or information transiting or stored on Indexa Analytics information system(s) – except to the extent that the information is directly related to a vulnerability and the access is necessary to prove that the vulnerability exists. 

- You do not exfiltrate, alter, or destroy any data under any circumstances. 

- You do not compromise the privacy or safety of Indexa Analytics personnel or any third parties. 

- You do not compromise the intellectual property or other commercial or financial interests of any Indexa Analytics personnel or entities, or any third parties. 

- You do not publicly disclose or share with any third-party any details of the vulnerability, indicator of vulnerability, or the content of information rendered available by a vulnerability, except upon receiving explicit written authorization from Indexa Analytics. 

- You do not conduct denial of service testing or other testing that impacts the availability of Indexa Analytics services. 

- You do not conduct social engineering, including spear phishing, of Indexa Analytics personnel, contractors, customers. 

- You do not attempt to gain physical access to any of our offices or data centres. 

- You do not include any information that may identify an individual other than yourself (such as name, contact information, IP address, or other similar information) in your vulnerability report or any attachments thereto. 

- You do not submit a high-volume of low-quality reports. 

- For information on how Indexa Analytics processes your personal data and your rights regarding data processing in the Vulnerability Disclosure Program, please refer to our Privacy Notice: Privacy notice - Indexa Analytics 

- If at any point you are uncertain whether to continue testing, please engage with the disclosure platform team at support@indexa-analytics.test. 

**Accepted Vulnerabilities**  

- **OWASP Top 10 vulnerability categories** 

- **Other vulnerabilities with demonstrated impact (CVSS greater than 6)** 

**Out of Scope Techniques and Methods** 

Certain vulnerabilities are considered out of scope for our Responsible Disclosure Program. Out-of-scope vulnerabilities include: 

- Physical testing 

- Social engineering or phishing 

- Denial of service attacks 

- Resource Exhaustion Attacks 

- Attacks requiring MITM or physical access to a user's device. 

**Low Impact Vulnerability** 

The following vulnerabilities are considered too low of an impact to the client and would be marked as Out of Scope if submitted: 

- Google Maps API Keys 

- Account/e-mail enumeration using brute-force attacks 

- Any low impact issues related to session management (i.e. concurrent sessions, session expiration, password reset/change logout, etc.) 

- Clickjacking/UI redressing 

- Client-side application/browser autocomplete or saved password/credentials 

- Descriptive or verbose error pages without proof of exploitability or obtaining sensitive information: Information Sensitivity will be determined by Indexa Analytics  

- Directory structure enumeration (unless the fact reveals exceptionally useful information) 

- Incomplete or missing SPF/DMARC/DKIM records 

- Issues related to password/credential strength, length, lock outs, or lack of brute-force/rate limiting protections 

- Lack of SSL or Mixed content 

- If leaking of sensitive data requires MiTM positioning to exploit, it will be considered out of scope 

- Login/Logout/Unauthenticated/Low-impact CSRF 

- Low impact Information disclosures (including Software version disclosure) 

- Missing Cookie flags 

- Missing/Enabled HTTP Headers/Methods which do not lead directly to a security vulnerability 

- Reflected file download attacks (RFD) 

- SSL/TLS best practices that do not contain a fully functional proof of concept 

- Heartbleed requires a valid POC which shows sensitive data leakage. Information Sensitivity will be determined by Indexa Analytics  

- POODLE requires a POC demonstrating a downgrade, not just the result of SSLScan or Nmap scan 

- URL Redirection 

- Use of a known-vulnerable library which leads to a low-impact vulnerability (i.e. jQuery outdated version leads to low impact XSS) 

- Valid bugs that are not directly related to the security posture of the client 

- Vulnerabilities affecting users of outdated browsers, plugins or platforms 

- Vulnerabilities that allow for the injection of arbitrary text without allowing for hyperlinks, HTML, or JavaScript code to be injected 

- Vulnerabilities that require the user/victim to perform extremely unlikely actions (i.e. Self-XSS) 


**What You Can Expect from Us** 

Indexa Analytics remains committed to coordinating with you as openly and quickly as possible under the circumstances. We will aim to respond to new reports within five business days. We will investigate reports based on information available and may contact you for further information. Please note, reports marked as triaged are subject to change pending our team’s final analysis. We’ll try to keep you informed about our progress throughout the process. 

**Legal** 

You must comply with [Indexa Analytics’s Terms of Use](https://www.indexa-analytics.test/terms-of-use/), security industry best practices, and all applicable Federal, State, and local laws in connection with your security research activities or other participation in this vulnerability disclosure program. You agree that any and all information acquired or accessed as part of this exercise is confidential to Indexa Analytics and you shall hold all such information in strict confidence and shall not copy, reproduce, sell, assign, license, market, transfer or otherwise dispose of, give, or disclose such information to third parties or use such information for any purposes other than for the performance of your work or expressly authorized in writing by Indexa Analytics. 

Indexa Analytics does not authorize, permit, or otherwise allow (expressly or impliedly) any person, including any individual, group of individuals, consortium, partnership, or any other business or legal entity to engage in any security research or vulnerability or threat disclosure activity that is inconsistent with this policy or the law. If you engage in any activities that are inconsistent with this policy or the law, you may be subject to criminal and/or civil liabilities. 

To the extent that any security research or vulnerability disclosure activity involves the networks, systems, information, applications, products, or services of a non-Indexa Analytics entity (e.g., Federal departments or agencies; State, local, or tribal governments; other private sector companies or persons; employees or personnel of any such entities; or any other such third party), that non-Indexa Analytics third party may independently determine whether to pursue legal action or remedies related to such activities. 

By submitting a report to Indexa Analytics, you grant to Indexa Analytics, its subsidiaries and its affiliates, a perpetual, irrevocable, no charge license to all intellectual property rights licensable by you in or related to the use of information or material submitted. You must notify us if any part of your report is not your own work or is the intellectual property of a third-party. 

Indexa Analytics may modify the terms of this policy or terminate the policy at any time. 

Thank you for helping keep Indexa Analytics Inc. and our users safe!
