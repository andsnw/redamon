# Keystone Asset Vulnerability Disclosure Program Guidelines

## Introduction

Keystone Asset’s Global Enterprise Security team works diligently to protect Keystone Asset’s assets, services, products, customer information, contractor information, and employee information. Additionally, we recognize the valuable role the research community plays in submitting responsible disclosures that may improve our security posture, and we welcome the opportunity to partner with you.

Through the disclosure platform, Keystone Asset accepts certain reports of potential security vulnerabilities that may provide an attacker with the ability to compromise the integrity, availability, or confidentiality of Keystone Asset’s products, services, or information technology infrastructure (the "**Keystone Asset Program**"). By participating in the Keystone Asset Program, you agree to abide by these Keystone Asset Vulnerability Disclosure Program Guidelines (“**Guidelines**”). If you do not agree to the Guidelines, do not participate in the Keystone Asset Program.

## Relationship to the disclosure platform Terms

These Guidelines supplement, and do not replace, the disclosure platform policies governing your use of the disclosure platform, including but not limited to the disclosure platform Terms of Service and the disclosure platform Code of Conduct (collectively, the “**the disclosure platform Terms**”), which are incorporated by reference. In the event of any conflict between these Guidelines and the disclosure platform Terms, the Guidelines will govern unless Keystone Asset expressly states otherwise in writing.

## Authorization

Keystone Asset authorizes you to perform good-faith security research solely within the scope of the Keystone Asset Program and in accordance with these Guidelines and the disclosure platform Terms. Any activity outside this authorization is prohibited.

## Program Rules

By participating in the Keystone Asset Program, you agree:

- to act in good faith and avoid causing harm to Keystone Asset, Keystone Asset contractors, Keystone Asset crew, or Keystone Asset customers;
- to report confirmed vulnerabilities promptly and with sufficient detail for us to determine validity;
- not to exploit the vulnerability beyond what is necessary to demonstrate impact;
- to avoid compromising the privacy of our customers or employees, or disrupting the operation of our products, services, or information technology infrastructure;
- to comply with all applicable local, state, federal, and international laws and regulations, including but not limited to laws governing unauthorized access to computer systems, data protection, and privacy;
- not to store, use, disclose, share, compromise, or destroy Keystone Asset or customer data;
- if you encounter Personally Identifiable Information (PII), confidential information, or other non-public data, to immediately cease testing, permanently delete any such data in your possession, and promptly notify Keystone Asset;
- not to publicly disclose or share vulnerability details;
- not to retain any copies of non-public Keystone Asset information or share such information with any third party;
-	not to create or login to Keystone Asset investor accounts to test and/or perform transactions;

Use of automated tools is prohibited unless expressly permitted by Keystone Asset or the disclosure platform for the Keystone Asset Program. Excessive, indiscriminate, or disruptive automated scanning is strictly prohibited.

Violation of these Guidelines may result in ineligibility for the Keystone Asset Program and removal from the disclosure platform, and may also result in Keystone Asset taking further action, including bringing legal claims.

## Acknowledgement; Expenses; Limited Non-Assertion

The Keystone Asset Program is a vulnerability disclosure program and does not offer monetary rewards or bug bounties for submissions. Keystone Asset is under no obligation to provide compensation for any vulnerability report. Keystone Asset may, in its discretion, choose to provide recognition or other non-monetary acknowledgment for eligible submissions. Any such acknowledgment does not create an entitlement or expectation of compensation for this or any future submission.

Subject to your full compliance with these Guidelines, the disclosure platform Terms, all Keystone Asset policies, and all applicable laws, Keystone Asset will not initiate legal action against you solely for good-faith security research activities conducted within the scope of the Keystone Asset Program. This assurance does not apply to any activity that violates law, exceeds authorized scope, causes harm, or involves fraud, extortion, or other misconduct.

## Keystone Asset Program Scope

The scope of the Keystone Asset Program may evolve. Assets currently identified as in-scope or out-of-scope may change. Currently, any vulnerability of a Keystone Asset product, system or asset falls within the Keystone Asset Program’s scope, while the systems or assets of third parties such as software-as-a-service (SaaS) solutions not operated by Keystone Asset are outside the scope of the Keystone Asset Program. If you have any questions about what is in scope, please contact Keystone Asset through the disclosure platform.

## Unacceptable Submissions

The following submissions are not accepted by Keystone Asset:

- Submissions that result in alteration, destruction, or theft of Keystone Asset data, or the interruption or degradation of Keystone Asset systems.
- Attacks which require internal network access, or are performed by Keystone Asset employees or contractors.
- Social engineering attempts.
- Any activity involving Keystone Asset physical locations, including physical attacks against assets (e.g., equipment within Keystone Asset facilities).
- Attacks requiring man-in-the-middle (MITM) or physical access to a user’s device.
- Testing that requires mass creation of accounts, rate limit testing intended to disrupt service, credential stuffing, or similar high-volume activity.
- User enumeration reports without material security impact.
- Activity that could lead to disruption of service (DoS), including cache poisoning.
- Previously known vulnerable libraries without a working proof of concept demonstrating impact.
- Missing best practices in SSL/TLS configuration, Content Security Policy, or email authentication (SPF/DKIM/DMARC), unless a concrete security impact is demonstrated.
- Cross-Site Request Forgery (CSRF) with no security impact (e.g., unauthenticated/logout/login CSRF).
- CSV injection, content spoofing/text injection issues, or missing cookie flags (HTTPOnly/Secure/SameSite) unless a concrete security impact is demonstrated.
- Clickjacking/Tabnabbing attacks without demonstrated impact.
- Banner exposure/version disclosure without demonstrated impact.
- Open redirects that are not chained into a more impactful vulnerability.
- Broken links in documentation.
- Additional missing security controls often considered best practice (e.g., certificate pinning) without demonstrated security impact.

Keystone Asset reserves the right to reject any submission in its discretion.

Keystone Asset employs third-party vendors, and some subdomains may be managed by third parties. Where a reported issue relates to systems operated by a third-party vendor, Keystone Asset may share relevant details with that vendor for purposes of investigation and remediation.

## Crafting a Report; Keystone Asset Disclosure

To help streamline our intake process, please submit one vulnerability per report (unless chaining is necessary to demonstrate impact), and include the following information:

- Your IP address.
- A detailed description of the vulnerability.
- Detailed steps to reproduce.
- Proof of exploitability (e.g., screenshots or video).
- Perceived impact to another user or to Keystone Asset.
- Tools used or required.
- Proposed CVSS v3 vector and base score (without environmental or temporal modifiers).
- List of URLs and affected parameters.
- Other vulnerable URLs, additional payloads, and proof-of-concept code (if applicable).
- Browser, OS, or app version used during testing.
- Do not use URL shorteners in reports.  
- Report findings in English.  
- Store supporting evidence and attachments only within the report you submit; do not host files on external services.  

Failure to adhere to these minimum requirements may delay processing.  

Keystone Asset may consider whether a disclosure of the vulnerability provides a positive contribution to the security community when evaluating submissions.

## Legal Notice

By submitting information through this Program, you grant Keystone Asset a worldwide, perpetual, irrevocable, non-exclusive, transferable, sublicensable, fully-paid and royalty-free license under any intellectual property rights you own or control to use, reproduce, modify, create derivative works from, and otherwise exploit the submitted information for security, remediation, and related purposes.

Keystone Asset may contact you regarding your participation in this Program or reports you submit through the Program. Any information you receive or generate relating to Keystone Asset or its service providers or agents in connection with this Program (collectively, “Keystone Asset Confidential Information”) must be kept strictly confidential, and Keystone Asset Confidential Information must not be disclosed to any third party without the express written permission of Keystone Asset.

Any activity that intentionally compromises the privacy of customers or employees, intentionally disrupts the operation of our products, services, or information technology infrastructure, or otherwise causes harm is prohibited, will result in permanent disqualification from the Keystone Asset Program, and may result in Keystone Asset taking action, including bringing legal claims. Keystone Asset further reserves all rights and remedies if you do not comply with these Guidelines or applicable laws.

Nothing in these Guidelines creates an obligation for Keystone Asset to remediate or respond to any reported vulnerability. Keystone Asset reserves the right to modify or terminate the Keystone Asset Program at any time, in its discretion, and without prior notice. By participating in the Keystone Asset Program, you agree to accept any modifications to these Guidelines or the Keystone Asset Program.

## Sanctions and Export Controls

You represent that you are not subject to economic sanctions or export control restrictions that would prohibit participation in this Program, and that your participation complies with applicable sanctions and export control laws.

## Governing Law

These Guidelines are governed by the laws of the Commonwealth of Pennsylvania, without regard to conflict-of-laws principles.
