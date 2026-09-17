Policy Page
==========

We are committed to ensuring the privacy and safety of our users. If you believe that you have discovered a security vulnerability on our website or within our mobile applications, we appreciate your help in reporting the issue to us. We will validate and fix vulnerabilities in accordance with our commitment to security and privacy.

---


Table of Contents
===============

1. [Rules of Engagement](#user-content-rules-of-engagement)
    1. [Program Policy](#user-content-program-policy)
    1. [Prohibited Actions](#user-content-prohibited-actions)
    1. [Disclosure](#user-content-disclosure)
1. [Guidelines](#user-content-guidelines)
    1. [Testing Guidelines](#user-content-testing-guidelines)
    1. [Reporting Guidelines](#user-content-reporting-guidelines)
    1. [Report Sections](#user-content-report-sections)
1. [Response Time](#user-content-response-time)
1. [Common Vulnerabilities](#user-content-common-vulnerabilities)
    1. [Leaked Credentials](#user-content-leaked-credentials)
1. [Exclusions](#user-content-exclusions)
    1. [Informative](#user-content-informative)
    1. [Duplicate](#user-content-duplicate)
    1. [Not Applicable](#user-content-not-applicable)
    1. [Known Ineligible Vulnerabilities](#user-content-known-ineligible-vulnerabilities)
1. [Safe Harbour](#user-content-safe-harbour)

---


Rules of Engagement
=================

All hackers participating in Voyantis Travel's program fully agree to follow the rules outlined in this page, as well as the platform's Code of Conduct. Failure to comply with the program rules can lead to deduction of bounty, ineligibility of bounty, disqualification of the report, temporary ban, and permanent ban from Voyantis Travel program.

Program Policy
------------------

1. Voyantis Travel may make amendments to the program rules and other contents in the policy page at any time without prior notice.
1. Changes made to the program rules and the policy page will NOT be applied retroactively.
1. Award, severity, and qualification of the reported vulnerabilities are at Voyantis Travel's discretion, which may involve business impacts and other external factors.
1. Voyantis Travel cannot reward or conduct business engagements with any individual on any US sanction lists or any individual residing in any country on any US sanction lists. This includes residents of Cuba, Sudan, North Korea, Iran, and Syria.

Prohibited Actions
----------------------

1. Compromising any Voyantis Travel customer or employee accounts
1. Compromising any sensitive data of Voyantis Travel or Voyantis Travel customers, including viewing, modifying, damaging the data
1. Storing sensitive data of Voyantis Travel or Voyantis Travel customers on your personal data storage
1. Performing social engineering on Voyantis Travel customers or employees, e.g., phishing, spamming, scamming.
1. Communicating with Voyantis Travel staff via other channels apart from the disclosure platform
1. Discussing or disclosing any part of the vulnerability outside of the disclosure platform before it has been approved by Voyantis Travel
1. Performing automated security testing or scanning
1. Intentionally creating high traffic volume to Voyantis Travel

Disclosure
------------

1. Disclosure is currently NOT allowed for any report.
1. Unless explicitly permitted by Voyantis Travel, DO NOT disclose vulnerabilities outside of Voyantis Travel's the disclosure platform program.
1. When applicable, Voyantis Travel will abide by [Disclosure Guidelines](https://disclosure-platform.test/disclosure-guidelines)

---


Guidelines
===========

The following guidelines are provided to the hackers to ensure minimum friction during testing and reporting the vulnerability on Voyantis Travel's program. Please follow the outlined guidelines to prevent unnecessary delays, blockages, and investigations that may occur if the guideline is not abided by.

Testing Guidelines
------------------------

* Hackers should self-provision test account(s) on our applications for security testing.
* If the testing procedure involves sending HTTP requests to Voyantis Travel, please specify the unique identifier `Researcher-<your-Researcher-username>` (e.g., `Researcher-Voyantis Travelhacker` if your the disclosure platform username is `Voyantis Travelhacker`) in your **request header** to distinguish testing from other forms of abuse.
  * **We recommend putting it in the HTTP header `User-Agent`** (e.g., `User-Agent: Researcher-Voyantis Travelhacker`).
  * You may also put your identifier on other applicable and appropriate parameters, or in multiple places.
  * Not providing the identifier may result in a deactivation of your account on Voyantis Travel platforms.
* **If the hacker wishes to create a test property on `ycs.voyantis-travel.test`, please follow below instructions to ensure minimal interruption to your testing:**
  1. Select `Test City, Comoros` as property location – please note that the property location cannot be changed once the property has been published
**Voyantis Travel is NOT responsible for any charges incurred from refunds as a consequence of real guests completing a booking with a test property.**
  1. Include `Test` and `Do not book` in the property name
  1. Include `For security testing` in the property description

Reporting Guidelines
--------------------------

* Do not report using automated scanner output. Instead, provide the steps to reproduce and/or a proof of concept.
* Screenshots and screen recordings of the exploit are accepted in the reports.
* To handle some cases where the vulnerability is independently fixed after reporting but before being triaged by Voyantis Travel team, a complete evidence of the vulnerability's existence (e.g., screen recordings) in the initial reporting will be beneficial during the triage process.
* Bounties will be awarded based on the demonstrated impact of the vulnerability reported. *Please provide clear and detailed steps on how to reproduce the issue and any potential impact it may have, including the possibility of escalation or privilege escalation. If you claim a higher impact than what is demonstrated, we will only consider the demonstrated impact when
determining the bounty amount.

Report Sections
--------------------

To minimize triage time, please include the following sections in the report as applicable:

| Section | Description | Examples |
|------------|-----------------|---------------|
| Vulnerability summary | Describe the nature and/or background of the vulnerability | - |
| Prerequisites | Describe the preparatory conditions of the attack scenario | The attacker must have a valid hotel listing on ycs.voyantis-travel.test.  The victim must be logged in |
| Vulnerability location | Describe where the vulnerability can be found | *Click on `Contact Voyantis Travel Customer Service` at https://www.voyantis-travel.test/info/contact.html* |
| Steps to exploit | Preparation steps on the attacker's side must also be included | e.g., stored XSS must include the steps to inject the script into the vulnerable input field or parameter |
| Proof of exploit | Evidence proving the exploitability of the vulnerability | *e.g., screen recording, screenshot* |
| Limitations | Highlight any observed non-trivial limitations | *The API has a rate limiting of 5 requests per minute* |
| Impact | Highlight the potential impact to Voyantis Travel and its customers | - |

---


Common Vulnerabilities
===================

All eligible reports will be individually evaluated for severity as per our Program Policy. To serve as a guidance for hackers in the Voyantis Travel program, the list below shows common vulnerabilities and their **likely range** of severity. The severity range is typically applicable when the report solely comprises the mentioned vulnerability. However, if a report combines several vulnerabilities into one attack path resulting in a significantly higher impact, its severity level may increase. The `Lower Severity` field **does not** necessarily represent the minimum guaranteed severity level.

| Vulnerability | Lower Severity | Higher Severity |
|------------------|----------------------|----------------------|
| Authentication bypass | High | Critical |
| SQL Injection | High | Critical |
| Remote Code Execution | High | Critical |
| Insecure Direct Object Reference | Medium | Critical |
| User personal information enumeration (multiple fields) | Medium | Critical |
| Stored Cross-site Scripting | Low | High |
| Multi-factor Authentication (OTP) Bypass | Low | High |
| Improper rate-limiting on authentication | Low | Medium |
| Reflected/DOM-based Cross-site Scripting | Low | Medium |
| Subdomain Takeover by Dangling DNS | None | Medium |
| Open redirect - Rocket Travel, Rocketmiles, Hitrewards assets | None | Medium |
| Open redirect - other assets | None | Low |
| User personal information enumeration (single field) | None | Low |

Leaked Credentials
-------------------------

###Testing Leaked Credentials

* Do not attempt to validate, use, or log in with leaked credentials.
* Do not attempt to change data, test MFA, or perform any actions using the credentials.
* No further testing of the affected account is permitted; when applicable, please only submit the evidence of the leakage.

###Reporting Leaked Credentials

* **[Required]** Include the exact source or link where the credentials were found. List out detailed systematic steps to gain the leaked credentials
* Attach the full data dump or relevant excerpt as evidence.
* When applicable, clearly specify if the credentials belong to Voyantis Travel employees, third-party partners, or Voyantis Travel customers, and if the leak is from an Voyantis Travel-controlled source.

###Ineligible Reports

* Leaks involving credentials obtained by malware (e.g., StealerLog), browser compromise, or directly from end-users without an Voyantis Travel-related breach.
* Credentials from personal repositories, third-party sites not controlled by Voyantis Travel, or public data breach indexes (e.g., HaveIBeenPwned, oss-bounty.test, scan-service.test, VirusTotal, Wayback Machine) unless organization impact from an Voyantis Travel source can be demonstrated.
* Credentials for accounts not belonging to Voyantis Travel employees, Voyantis Travel-controlled systems, or designated third-party partners.
* Credentials obtained from illegal or unauthorized channels, including but not limited to forums, messaging platforms, and dark web sources.

---

Exclusions
==========

Please ignore and do not report vulnerabilities under this section. Unless they can be proven to cause high impact to Voyantis Travel and its customers with high likelihood and feasibility, any reports involving the vulnerabilities listed below will be closed and ineligible for bounty.
All vulnerabilities included in the disclosure platform standard ineligible findings are not accepted and will be closed without triaging.

###Informative

The vulnerabilities below do not impose substantial risk to Voyantis Travel. If the reported vulnerability belongs to any of the following weaknesses, it will be closed as **Informative**.
* Lack of HTTPS in web applications
* Stack error messages
* Generic error messages
* Vulnerabilities affecting other Booking Holdings brand's assets
* Vulnerable, misconfigured, or outdated third-party software libraries, packages, or services; unless high impact can be achieved.
  * Assessment of impact level and report eligibility subject to Voyantis Travel team’s discretion.
  * Recently disclosed (less than 30 days of publishing) vulnerabilities on third-party components (“zero-day”) are not eligible for bounty.
*  Improper access control to non-sensitive files or documents, regardless of their sensitivity labels (e.g., "Confidential", "Internal", “Restricted”)
* Vulnerabilities relying on far-fetched assumptions, unlikely user interactions, or conditions beyond Voyantis Travel’s control, for example:
* Brute-forcing of high-entropy string values (e.g., UUIDs/GUIDs, booking tokens—see explanation in [Ineligible Risk - Accepted Vulnerabilities](#user-content-ineligible-risk-accepted-vulnerabilities) below) without a systematic way of retrieving these values beforehand
* The user has been compromised
* The attacker knows the user’s password
* The attacker has access to the user’s physical device
* The user has intentionally or unintentionally disclosed their own sensitive information, e.g., passwords, session tokens, or booking tokens

###Duplicate

If the reported vulnerability falls under any of the following conditions, it will be closed as **Duplicate**.
* An identical vulnerability has been reported by other hackers in the past and has not yet been resolved.
* The same vulnerability has been identified internally prior to the report submission.
* The same vulnerability with the same fix on the same code base has been reported on a different API, endpoint, hostname, or IP address.

###Not Applicable
These vulnerabilities are out of scope for our program. If the reported vulnerability falls under any of the following conditions, it will be closed as **Not Applicable**
* DNSSEC
* Web-scraping
* SPF records related issue
* Self cross-site scripting
* Missing HTTP security headers
* Missing cookie flags on non-sensitive cookies
* Hosted Zone Takeover outside `*.voyantis-travel.test` and `*.voyantis-travel.test`
* Brute force attacks against passwords, hash secrets, or any other credentials Denial-of-Service or resource-exhaustion
* Physical attacks against any Voyantis Travel office, server, datacenter, or other infrastructure
* Social engineering, including but not limited to, phishing or calling, any Voyantis Travel employee, contractor, agent, or user.
* Vulnerabilities on any site or application not explicitly listed as in-scope, including any other Booking Holding brands
* Vulnerabilities introduced by the content served through one of our advertisement networks.

###Ineligible Risk-Accepted Vulnerabilities

The following vulnerabilities are known to be either by design or non-issue. These vulnerabilities alone do not impose security concerns to Voyantis Travel, and they will not increase the severity of the vulnerabilities reported by the hackers.

* **Booking tokens** are considered sensitive information which should not be shared publicly by users. You can find booking tokens in the URL of Booking Details page as a base-64 value that follows
`hxxps://www.voyantis-travel.test/account/editbooking.html?bookingId=` . We accept that the possession of booking tokens translates to full access to the corresponding bookings. As a result, the following vulnerabilities are considered risk-accepted when the
attack requires supplying the value(s) of booking token.
  * Lack of authentication/authorization on manage booking page, mostly seen on the endpoint
`hxxps://www.voyantis-travel.test/account/editbooking.html?bookingId=<booking_token>`
  * Lack of authentication/authorization on any endpoints when booking token(s) is supplied as an input, e.g., IDOR by manipulating booking token values
  * Disclosure of the manage booking page URL `hxxps://www.voyantis-travel.test/account/editbooking.html?bookingId=<booking_token>`
However, vulnerabilities leading to a systematic retrieval of booking tokens remain eligible for bounty.
* User accounts can be created without email verification
* Cache poisoning attacks resulting in caching of error responses
* Any vulnerability found on Voyantis TravelVIP Campaign Feature, Pointsmax, and other campaigns/promotions

---

Safe Harbour
=============


Any activities conducted in a manner consistent with this policy will be considered authorized conduct and we will not initiate legal action against you. If legal action is initiated by a third party against you in connection with activities conducted under this policy, we will take steps to make it known that your actions were conducted in compliance with this policy. Thank you for helping keep Voyantis Travel safe!

