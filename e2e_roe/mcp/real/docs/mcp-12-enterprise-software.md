Only Security Researchers, as defined in our Vulnerability Disclosure Policy, may report a vulnerability via this Portal. Subject to the exceptions below, Security Researchers are any third-party computer,network, or other technical expert who uses their technical knowledge for non-malicious purposes toidentify security vulnerabilities. All Security Researchers must be at least 16 years old.

**A Security Researcher excludes:**
* A Docuvault employee, or the spouse, partner, parent, child, or sibling (including by marriage) of a
Docuvault employee.
* A Docuvault customer or channel partner. Customers or channel partners must report solution
issues via Docuvault Community (add link). Any solution reports via the Portal will not trigger any
service level timelines or other contractual obligations.
* A resident of a country currently subject to any U.S. sanctions programs or be included on
the. U.S. State Department Specially Designated Nationals and Blocked Persons List and
may not participate in this program if such participation is prohibited by local law in their
country of residence.

Docuvault’s Vulnerability Disclosure Program is not a “Bug Bounty Program.”
By participating in Docuvault’s Vulnerability Disclosure Program and reporting via this Portal, you
acknowledge that you have read and agree to Docuvault’s Vulnerability Disclosure Policy.

**Out of scope**

The following actions do not qualify for Coordinated Disclosure and should not be tested when
participating in the Program:

* DoS or DDoS attacks
* Physical Attacks against our properties or data centers
*  Phishing and Social Engineering Attacks
* Missing http security headers which do not lead to a vulnerability (you must deliver a proof of
concept that leverages their absence)
* Vulnerabilities in third-party applications or services which use or integrate with our services
and applications.
* Reports from automated tools or scans without an exploitation proof of concept
* Missing cookie flags on non-sensitive cookies
*  Reports of SSL best practices or insecure ciphers (unless you have a working proof of
concept, and not just a report from a scanner)

We will not accept reports from automated vulnerability scanners hence aggressive scans are not
tolerated to avoid services disturbance.

**Docuvault Vulnerability Disclosure Policy**

 * The Docuvault Vulnerability Disclosure Policy (“Policy”) is intended to give Security
Researchers clear guidelines for researching and reporting vulnerabilities in certain Docuvault
products and network
environments.
 * This Policy describes the applicable systems, products and types of research which are
covered by this Policy, how to submit vulnerability reports to Docuvault, and the desired timeline for
public disclosure of vulnerabilities by Security Researchers.

**II. Who May Report**
 * Only a Security Researcher may report a vulnerability pursuant to this Policy. Subject to
the exceptions below, a “Security Researcher” is any third-party computer, network, or other
technical expert who uses their technical knowledge for non-malicious purposes to identify
security vulnerabilities.
 * A Security Researcher may not be:
 *  A Docuvault employee, or the spouse, partner, parent, child, or sibling (including by
marriage) of a Docuvault employee.
 * A Docuvault customer or channel partner.
 * A resident of a country currently subject to any U.S. sanctions programs or be included
on the. U.S. State Department Specially Designated Nationals and Blocked Persons List, and may
not participate in
this program if such participation is prohibited by local law in their country of residence.
 *  All Security Researchers must be at least 16 years old.

 **III. Scope of Policy**
 *  This Policy applies to vulnerabilities found in Docuvault products and network environments
(except items included in the list below). Docuvault considers a vulnerability to be a weakness in our
products or network environments that could allow an attacker to impact the confidentiality,
integrity, or availability of the product or environment.
 * Docuvault does not consider the following types of vulnerabilities to be findings:
 *  Presence or absence of HTTP headers (X-Frame-Options, CSP, nosniff, etc.). These
are security best practices and therefore Docuvault does not consider them as vulnerabilities.
 * Missing security-related attributes on non-sensitive cookies. Docuvault sites and products may set certain security-related attributes on cookies. The absence of these headers on non-
sensitive cookies is not considered a security vulnerability.
 *  Exposed stack traces. Docuvault does not consider stack traces by themselves to be a
security issue.
 * Vulnerabilities found on the systems of Docuvault’s customers, vendors, or channel
partners fall outside the scope of this Policy. Any vulnerability findings related to those systems
should be reported directly to that customer, vendor, or channel partner according to its disclosure
policy, if any.

**IV. No Bug Bounties, Payments**

 * Docuvault’s Vulnerability Disclosure Policy is not a “Bug Bounty Program.”
 * Docuvault is not offering or promising to pay or provide anything of value to Security
Researchers under this Policy.
By undertaking any activities under this Policy and/or by submitting a report to Docuvault,

**Security Researchers:** 
 * agree that they have no expectation of payment or renumeration or compensation from
Docuvault of any kind;
 * waive any present or future claim for payment, renumeration, or compensation; and
 * agree not to file an action in any court, whether for legal, equitable, or declaratory relief,
regarding a claim for payment, renumeration, or compensation.
 * Docuvault will not provide any form of public acknowledgment, credit, and/or payment for
reporting a vulnerability under this policy.

 **V. Authorization**

 * Work undertaken by Security Researchers in a good faith effort to comply with this
Policy will be deemed to constitute conduct under the U.S. Computer Fraud and Abuse Act, 18
U.S.C. § 1030.
* The following work and activities of Security Researchers, including vulnerability
research and testing of any kind, are prohibited and not authorized under this policy:
* Testing on Docuvault products which have been sunset, retired, or otherwise designated
by Docuvault as “end of life;”
* Penetration tests of Docuvault facilities or facilities of hosting providers;
* Disrupting, disabling, compromising, damaging, or impairing access to data, systems,
connected devices, or property of any kind that is owned or maintained by Docuvault or its
customers, channel partners or vendors;
* Use of any network denial of service tests or attacks (DoS or DDoS);
* Use of exploits for any purpose, except to the extent necessary to confirm the presence
of a vulnerability;
* Scanning from an origin IP that is also used by production users, (as this may be
detected as malicious traffic);
* Testing for vulnerabilities in physical security, or for network or data access via physical
means, including through unauthorized physical entry to any Docuvault property, social engineering
such as phishing, or by any other non-technical means;
* Continued research or testing upon encountering any confidential or sensitive data
(including user data, personally identifiable information, financial information, information
proprietary to Docuvault or others, trade secrets of any party, or any other information that is of such
a nature as customarily would be considered confidential). If confidential or sensitive data is
encountered, the Security Researcher must cease all work undertaken under this Policy and notify
Docuvault immediately.
* For Docuvault’s customers, channel partners or vendors, any actions which violate the
terms of the customer’s, channel partner’s, or vendor’s agreement(s) with Docuvault; and
* Any activity of any kind not covered above which negatively impacts the confidentiality,
integrity, or availability of Docuvault’s data and its network and attached devices.
* If legal action against the Security Researcher is initiated by any third party for activities
conducted in accordance with this Policy, Docuvault will comply with any request to confirm that
actions of the Security Researcher were conducted in compliance with this Policy and therefore
authorized as that term is defined in this Policy.

**VI. Responsible Disclosure Guidelines**
* In conducting work and submitting a report, all Security Researchers must comply with
these guidelines:
* Docuvault shall be notified as soon as possible after discovery of a potential security
vulnerability.
* In undertaking their work, Security Researchers must make good faith efforts to avoid
degradation of user experience and any disruption to production systems.
* When reporting vulnerabilities, Security Researchers should provide Docuvault with
specific details on the (1) attack scenario/exploitability, and (2) the assumed security impact/risk of
the vulnerability.
* Security Researchers should use the least intrusive means to validate a vulnerability.
* Any vulnerability and related details must not be discussed with or disclosed to anyone
outside of Docuvault, without Docuvault’s prior written consent.
* Security Researchers must comply with all applicable laws and regulations, including
local laws of the country or region in which the Security Researcher resides and works, and where
Docuvault and its employees are present.
* Security Researchers are solely responsible for all costs of any kind incurred due to
their participation in activities covered by this Policy.

 **VII. Reporting a Vulnerability**
* Docuvault will not share the Security Researcher’s contact information without express
permission, unless otherwise required by law or court order.
* Security Researchers may submit reports via the Docuvault Vulnerability Disclosure Portal.
* Personal information of the Security Researcher, if provided, will be handled by Docuvault
in accordance with its Privacy Policy at https://www.docuvault.test/en/legal/privacy-policy.
* Docuvault does not support PGP-encrypted emails.
* Security Researchers grant to Docuvault a worldwide, perpetual, royalty-free, irrevocable,
nonexclusive, fully sublicensable (through multiple levels) license to use, reproduce, modify,
adapt, create derivative works from, translate, publish, publicly perform, publicly display,
broadcast, transmit, distribute, and otherwise use any submission (or any part thereof) for any
purpose and in any form, medium, or technology now known or later developed. The content of
any submissions will not be treated as proprietary or confidential to the Security Researcher.
* Vulnerabilities identified by Docuvault customers or channel partners must be submitted via
Docuvault Community. Customer or channel partner reports improperly submitted via this Policy will
not trigger any service level or other commitments set forth in any applicable agreement between
the relevant parties.

 **VIII. Content of Submissions**
* In triaging submissions, clear, well-written reports will have a higher priority for review
and a greater chance of resolution. Reports that are unclear or otherwise difficult to understand
will not be reviewed.
* All reports must be submitted in English.
* All Security Researcher reports must provide:
*  The product name/version or host address/location where the vulnerability was
discovered.
* A detailed description of the vulnerability, including
	* how the vulnerability was found
	* its potential impact on Docuvault
	*  suggested potential remediation
* a numbered list of steps needed to reproduce and validate the vulnerability (i.e., proof of concept scripts, code or screenshots)
* manual verification of all findings, with clear reproduction steps for each finding
(findings generated from automated scanners will not be accepted.)
* Only one vulnerability may be submitted per report, unless the Security Researcher
needs to combine two or more related vulnerabilities to provide context.

**IX. What to Expect from Docuvault**
* Docuvault commits to working with Security Researchers in good faith, and with appropriate transparency and speed.
* After receiving a report from a Security Researcher, if the vulnerability is validated and contact information is provided, Docuvault will: (1) acknowledge receipt of the report; (2) confirm the existence of the reported vulnerability; and (3) undertake to share whatever remediation Docuvault
may take, including any issues that may delay remediation.
* Docuvault, in its sole discretion, will determine the appropriate remediation steps, if any, and schedule for implementation.

 **X. Policy Changes**
 *  Docuvault may change this Policy at any time by posting the revised Policy
at [https://security.docuvault.test]. Security Researchers are responsible for reviewing the Policy and ensuring compliance with any changes made. Security Researchers participating in any research after changes become effective will be subject to the revised