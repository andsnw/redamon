# Transacta Vulnerability Disclosure Program (VDP) Policy
#

Transacta is a leading payments technology company delivering innovative software and services to merchant and issuer customers globally. Transacta looks forward to working with the information security community to find vulnerabilities in order to keep our businesses and customers safe. To achieve this, a Vulnerability Disclosure Program (“VDP”) policy has been defined in this document which outlines the rules of engagement for researchers participating in the VDP. Transacta VDP is hosted through [the disclosure platform](https://disclosure-platform.test/Transacta) and all researchers (“hackers”) must be registered and report findings through this channel.



## Eligibility for Participation

- You must be 18 years old or older to submit a vulnerability for consideration. If you are a minor, you must submit through a parent or legal guardian.
- You must be an individual security researcher participating in your own individual capacity.
- If you work for a security research organization, that organization must permit you to participate in your individual capacity. You are responsible for reviewing your employer’s rules for participating in the Program.



## Ineligibility for Participation

You may not participate in the Program if you are any of the following:

- A resident or have a tax form from China or Hong Kong.
- A resident of any country/region that is under United States sanctions, such as Cuba, Iran, North Korea, Sudan, Syria, or Crimea, or a person designated in the U.S. Department of the Treasury’s Specially Designated Nationals List.
- A current employee of Transacta Inc., a Transacta affiliate, or an immediate family member (parent, sibling, spouse, or child) or household member of such an employee.
- A contingent staff member, contractor, or vendor employee that is currently working with, or has worked in the past twelve (12) months with, Transacta Inc. or a Transacta affiliate.


---
#

## Response Targets

Transacta will make a best effort to meet the following response targets for researchers participating in our program:


| Type of Response   | Response Target                |
|--------------------|-------------------------------|
| First Response     | 2 days                        |
| Time to Triage     | 2 days                        |
| Time to Resolution | Depends on severity/complexity |


We will try to keep you informed about our progress throughout the process. Please note, however, that numerous circumstances, including but not limited to resource constraints, a high volume of submissions, intervening public holidays, and more may interfere with our ability to meet these response targets, and that you are obligated to continue to comply with all of the Program Guidelines even if we do not respond on time.


---
#
## Disclosure Policy

By participating in the program, you agree **not to discuss or disclose any vulnerabilities (even resolved ones) outside of the Program without express prior consent from Transacta**.

- Transacta reserves the right to approve or deny any request for disclosure for any reason.
- You agree to follow the platform's disclosure guidelines.

---
#

## Program Guidelines

- This program is not intended to encourage any researcher to access or view any of the following sensitive forms of data, each of which is subject to stringent legal protections:  
  1. Personal Information, defined here to include any information that identifies, relates to, describes, is reasonably capable of being associated with, or could reasonably be linked, directly or indirectly, with a particular individual or household; or  
  2. Any Payment Account Number (PAN), Cardholder Data (CHD), or Sensitive Authentication Data (SAD), as each term is defined by the Payment Card Industry Data Security Standard (PCI-DSS).  
  Should you encounter any such information during your research, you must immediately halt your activity and contact Transacta, and you must purge any such data from your system(s) following the submission of your report. Adhering to these requirements protects both Transacta and you.
- Please provide detailed reports with reproducible steps. If the report is not sufficiently detailed to enable reproduction of the issue, the issue may not be triaged.
- Submit one vulnerability per report, unless you need to chain vulnerabilities to provide impact.
- When duplicates occur, we only triage the first report that was received (provided that it can be fully reproduced).
- Multiple vulnerabilities caused by one underlying issue will be treated as one valid report.
- Social engineering (e.g. phishing, vishing, smishing) is prohibited.
- Only interact with accounts you own or with explicit permission of the account holder.
- Do not engage in any activity that can potentially or actually cause harm to Transacta, our customers, or our employees.
- Do not engage in any activity that can potentially or actually stop or degrade Transacta’s services or assets.
- Do no harm and do not exploit any vulnerability beyond the minimal amount of testing required to prove that a vulnerability exists or to identify an indicator related to a vulnerability.
- Do not initiate a fraudulent financial transaction.



## Out of Scope Vulnerabilities

When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) security impact of the bug.

In addition to the below, any vulnerability on the disclosure platform Core Ineligible Findings list is out of scope:

- Unexploitable vulnerabilities discovered via scanning. All submissions must have a valid proof of concept.
- Attacks requiring MITM or physical access to a user's device.
- Vulnerabilities on partner or supplier products.
- Rate limiting or bruteforce issues on non-authentication endpoints.



## Grounds for Disqualification

Attempting any of the following could result in permanent disqualification from the Program and could result in a possible criminal and/or legal investigation:

- Disruption or denial-of-service attacks (Application and Network)
- Social engineering attacks
- Brute-force attacks
- Exfiltration of data
- Code injection on live systems
- The compromise or testing of application accounts that are not your own
- Any threats, attempts at coercion, or extortion of Transacta employees, other partner employees, or customers
- Physical attacks against Transacta, contractors, or customers
- Any physical attempts against Transacta property or data centers
- Any other action that violates these Program Guidelines
- Any other action that violates the law
- Any action that endangers yourself or others
- Aggressive vulnerability scans or automated scans on Transacta servers (including scans using tools such as Core Impact or Nessus)



## Additional Legal Terms

By submitting security or vulnerability information to Transacta, you confirm that you have read, understand, and agree to these Program Terms. Further, you agree that by submitting such information to Transacta, even if the information is not eligible for a reward, you grant Transacta a worldwide, perpetual, irrevocable, non-exclusive, transferable, sublicensable, fully-paid and royalty-free license under any and all intellectual property rights that you own or control to use, copy, modify, or create derivative works based upon such information and otherwise exploit such information for any purpose.

Any Transacta information that you may encounter, view, acquire, or access, is owned by Transacta or its customers, clients, or third-party providers. You have no rights, title, or ownership in any such information. Nothing in these Program Terms shall be deemed to constitute a grant of any license or other right to or in any Transacta or third-party product, service, patent, trademark, trade secret, or other intellectual property.

You must comply with all applicable federal, state, local, and international laws, regulations, and rules in connection with your security research activities and your participation in the Program. If you violate any applicable law or any requirement established by these Program Terms, you will not be considered a security researcher, and you may become subject to criminal penalties and civil liability. In particular, by participating in the Program, you confirm your understanding:
1. That applicable United States federal laws make it a felony offense for you to intentionally access an information system that is connected to the internet without authorization, or to exceed the scope of your authorized access to such a system, and in doing so to obtain any information therefrom; and
2. That any action that you take on a Transacta information system that exceeds the limits established by these Program Terms may therefore constitute a federal crime.

Transacta reserves all rights to pursue all available remedies, civil and criminal, against any individual or entity operating in violation or excess of the Program Terms.

Transacta retains the right to obtain your Personal Data (as defined in the disclosure platform Privacy Policy) from the disclosure platform, and to process such Personal Data as necessary to accomplish the legitimate business objectives of Transacta, including but not limited to ensuring the security and integrity of our infrastructure, data, products, and services. Transacta may also obtain and process your Personal Data for the purpose of exercising or defending legal rights; to take precautions against liability; to protect the rights, property, or safety of Transacta, of any other individuals, or of the general public; to protect Transacta and our assets from fraudulent, abusive, or unlawful uses; or to investigate and defend Transacta against third-party claims or allegations. By submitting a vulnerability report via the Transacta Vulnerability Disclosure Program ([https://disclosure-platform.test/Transacta](https://disclosure-platform.test/global-payments)) you consent to the disclosure platform disclosing Personal Data to Transacta, upon request, in the circumstances described in this paragraph.

Transacta may modify these Program Terms or terminate the Program at any time.


---
#

## Data Protection

To the extent you access, or view, transmit, disclose, interact with, or otherwise process Personal Information in connection with the Program, you constitute a Processor and/or Service Provider, as each term is defined by Data Protection Laws. For purposes of these Program Terms, “Data Protection Laws” means all laws and regulations applicable to the processing of Personal Information in connection with the Program, which may include, but may not be not limited to, the California Consumer Privacy Act, as modified by the California Privacy Rights Act of 2020 (“CCPA”) and the General Data Protection Regulation (EU) 2016/679 (“GDPR”). Any capitalized term not defined herein shall have the meaning given to that term in the Data Protection Laws.

### Processing Instructions and Details

As a Processor/Service Provider, you shall process Personal Information:

- Only to the extent necessary for participation in the Program;
- In compliance with all instructions provided by Transacta in relation to the processing; and
- In accordance with these Program Terms and Data Protection Laws.

The categories of Personal Information to which you gain access may include Transacta team member and customer contact information and any other Personal Information accessed or viewed in connection with the Program. The nature of the processing is solely for the purpose of identifying and submitting a vulnerability through the Program and the duration of processing is limited to the time needed to submit the report. The business purpose and/or lawful basis of the processing is to ensure the security and integrity of our infrastructure, data, products, and services.

### Processing Restrictions

You will not:

- Retain, use, disclose or otherwise process Personal Information for any purpose not contemplated by these Program Terms;
- Retain, use, disclose, or otherwise process Personal Information outside of the direct business relationship between you and Transacta;
- Use, distribute, sell, rent, release, or disclose Personal Information to a third party for monetary or other valuable consideration;
- Combine Personal Information with any other personal information that you receive from, or on behalf of, another person or persons, or collect from your own interaction with a Data Subject; or
- Share Personal Information with any third party for cross-context behavioral advertising, whether or not for monetary or other valuable compensation.

### Compliance with Data Protection Laws

You agree that:

- You shall provide Personal Information with the same level of protection that Transacta would be required to provide for it; and
- You understand the obligations placed upon you by Data Protection Laws. If you determine that you are no longer able to meet your compliance commitments in these Program Terms, you must immediately notify Transacta in writing.

### Sub-Processors

You agree that you will not use any Sub-Processors to process Personal Information without the prior written consent of Transacta.

### Confidentiality and Security

You shall maintain the confidentiality of Personal Information to which you have access and limit such access to what is strictly necessary to participate in the Program. While any Personal Information is in your possession or accessible by you, you shall ensure you have reasonable and appropriate security procedures and practices in place to protect the Personal Information from unauthorized access, destruction, use, modification, or disclosure.

### Privacy Incidents

You shall notify Transacta immediately, and in no event later than within 24 hours, upon becoming aware of a Privacy Incident, and you shall provide full assistance to Transacta in meeting Transacta’s obligation(s) with respect to such Privacy Incident under Data Protection Laws. For purposes of these Program Terms, “Privacy Incident” means any act, omission, event or occurrence that compromises the confidentiality, integrity, or availability of Personal Information. For the avoidance of doubt, the term “Privacy Incident” includes, without limitation:

- Any incident involving the accidental or unlawful destruction, loss, alteration, unauthorized disclosure of or access to Personal Information; and
- Any incident involving Personal Information that meets the definition of a “security breach,” “personal data breach,” “breach of the security of the system,” or any other similar term under the Data Protection Laws.

### Assistance

You shall provide full assistance to Transacta to enable Transacta to meet its obligations(s) to perform any assessments or respond to any requests regarding the processing of Personal Information that are required by Data Protection Laws. You shall promptly provide to Transacta, upon request, all information necessary to demonstrate your compliance with these Program Terms and Data Protection Laws.

### Return and Deletion

You must return any Personal Information you obtain during your research or in connection with the Program when you submit a report, and securely delete all copies of the Personal Information immediately following the submission of your report.

### Transfers

You shall not Transfer Personal Information without the prior written consent of Transacta. For purposes of these Program Terms, “Transfer” means the access by, transfer or delivery to, or disclosure to, a person, entity or system of Personal Information where such person, entity or system is located in a country or jurisdiction other than the country or jurisdiction from which the Personal Information originated. You and Transacta agree that when a Transfer is subject to the GDPR, the EU Standard Contractual Clauses Module Two (Controller to Processor) or Module Three (Processor to Processor) (found in Commission Implementing Decision (EU) 2021/914 of 4 June 2021 on standard contractual clauses for the transfer of personal data to third countries pursuant to Regulation (EU) 2016/679 of the European Parliament and of the Council), which are deemed incorporated into and form part of these Program Terms, will apply as follows:

- Transacta shall be deemed to be the “data exporter” and you shall be deemed the “data importer” with respect to the processing of Personal Information.
- Clause 7 shall not apply.
- The audits described in Clause 8.9 shall be carried out in any manner that Transacta deems appropriate.
- For Clause 9, Option 1: Specific Prior Authorization shall apply, and the time period for the request for specific authorization shall be 30 days.
- For Clause 11(a), the optional language shall not apply.
- The Data Protection Commissioner of Ireland shall be the competent supervisory authority (Clause 13(a)).
- The EU Standard Contractual Clauses will be governed by the laws of the Republic of Ireland (Clause 17).
- Disputes shall be resolved before the courts of Ireland, County of Dublin (Clause 18).
- The information included in the “Data Protection” section of these Program Terms is incorporated accordingly into Annexes I (A, B and C), II and III of the EU Standard Contractual Clauses.

Transfers subject to the laws of the United Kingdom or the Swiss Confederacy shall be pursuant to the EU Standard Contractual Clauses, as incorporated above, subject to any modifications required by the applicable jurisdiction’s regulatory authority to render those clauses a suitable mechanism for papering an international transfer.

For the avoidance of doubt, nothing about your agreement to comply with the terms set forth in this Data Protection section renders you an agent, employee, or contractor of Transacta.

---
#

## Safe Harbor

Any research activities conducted in strict accordance with these Program Guidelines, as determined by Transacta, will be considered authorized conduct, and we will not initiate legal action against you relating to such research activities.



**Thank you for helping keep Transacta and our users safe!**
