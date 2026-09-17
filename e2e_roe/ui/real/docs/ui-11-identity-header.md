Cardinal Markets looks forward to working with the security community to find vulnerabilities in order to keep our businesses and customers safe.

# Bug Bounty Program Rules
By submitting reports to our program, you agree that you’ve read, understood, and will follow our Program Rules and overall Program Policy.

* Be careful with sensitive information. If sensitive information such as personal information or user credentials are uncovered as part of your research, stop and report it to us immediately. Do not save, store, copy, move, or otherwise retain sensitive information, and work with us on any additional requests we may have.
* Test responsibly. Only interact with and test bugs against accounts you own. We do not allow testing against user accounts not owned by the Security Researcher. Reach out to us if you need help with testing cross-account issues.
* Do not cause harm. Do not engage in activities that disrupt, damage, or otherwise cause harm to or defraud Cardinal Markets, our users, our employees, our data or our users’ data, or our brand—including, without limitation, denial of service attacks, social engineering, phishing, spam, social media scams, fraudulent transactions, data exfiltration or tampering, or physical attacks.
* Do not exceed $1,000 USD when testing unbounded loss vulnerabilities. When you reach $1,000 USD file your report with all verification you have completed so far. Internal teams will verify unbounded loss vulnerabilities collaboratively with you. Testing over $1,000 USD may result in termination from our program.
* Do not disclose reports made to the Cardinal Markets bug bounty program at any time, in any location independent of the disclosure platform.

Violation of any of our Program Rules may result in (but is not limited to) consequences such as ineligibility for a bounty, permanent disqualification and removal from the Cardinal Markets Bug Bounty Program, or voiding the protections of the disclosure platform 

# Special Considerations
Due to the nature of our business, we ask that you also follow these guidelines:
* Do not perform resource intensive tests which could result in disruption or downtime for our services.
* Do not make financial transactions with other user accounts you do not own.
* Findings dependent on account takeover (ATO) are typically not accepted, though we may award a small bonus for bugs we consider novel.
* Do not send large volumes of data to our websockets.
* Do not create large volumes of support tickets.

The most common reason reports are rejected as ‘informative’ rather than for a bounty is because of impact. If your report shows theoretical impact rather than demonstrates an impact (e.g. ‘This flaw could result in information disclosure’ versus ‘Here is the information I was able to access using the flaw’), severities (and bounties) will be lower.

Safe harbor for researchers is applied.

# Eligibility to Participate
To be eligible to participate in any Cardinal Markets Bug Bounty Program, you must:
* Be at least 18 years of age and meet Cardinal Markets account requirements if you test using a Cardinal Markets account
* Not be employed by Cardinal Markets as an employee, contingent worker, or contractor (including individuals who separated from Cardinal Markets within the prior 12 months) or be an immediate family member of a current or former Cardinal Markets employee, contingent worker, or contractor
* Not be a resident of or an individual located within a country appearing on any U.S. sanctions lists, as administered by the Office of Foreign Assets Control (OFAC)
* Not be in violation of any national, state, or local law or regulation with respect to any activities directly or indirectly related to the Bug Bounty Program

Cardinal Markets also maintains a VIP Bug Bounty Program, which allows access to pre-release features in advance of their launch before the general public. Researchers who participate in our program may be invited to join the VIP Program based on the quality and consistency of their reports, with at least 3-5 reports submitted over time.

# Submission Requirements
Use the following headers when making requests to Cardinal Markets resources or assets for bug bounty where <Username> is your the disclosure platform username and <TestAccountEmail> is the email associated with the test account you’re making the request with:
```X-Bug-Bounty: <Username>```
```X-Test-Account-Email: <TestAccountEmail>```
Please include these host values in your report, as well as your breakdown of the CVSS score you assign to your submission.

# Rewards
Our rewards are based on severity per CVSS (the Common Vulnerability Scoring Standard). We’ll work with you to find an accurate CVSS score for your report, but please note these are general guidelines and reward decisions are up to the discretion of Cardinal Markets.

Our program calculates bounties for reports based on a sliding CVSSv3 scale; the higher the issue’s score, the higher your bounty will be. We’ll use lower environmental scores for assets that are less important to Cardinal Markets. We encourage rating your issues with CVSS before submission and including a breakdown of what your understanding of the criteria to be, but know that we may have to make adjustments in the event the score isn’t representative of the true impact. True impact will be determined by a host of factors including whether mitigations are in place, whether token interception/account takeover (ATO) is a requirement of the attack, the type of sensitive information disclosed, and what can actually be done with the identified exploit. The most common reason reports are rejected as ‘informative’ rather than for a bounty is because of a failure to provide demonstrable impact. If your report shows theoretical impact rather than demonstrates impact (e.g. ‘This flaw could result in information disclosure’ versus ‘Here is the information I was able to access using the flaw’), severities will be lower. It’s worth noting that severity gets decreased when: exploitation is currently mitigated by effective compensating controls; the vulnerability is only exploitable internally such as behind authentication systems (e.g., Okta) or requires specific privileges that limit accessibility; or the exploitation scenario involves user interactions or conditions that are unlikely to be met or are heavily constrained. Additionally no bounties will be awarded for issues which are fixed and no longer reproducible if the issue is fixed prior to the ticket being triaged/not as a result of the bug bounty ticket. Final determination of the eligibility and severity of the issue will be made by and at the sole discretion of the Cardinal Markets Security Team.

Eligibility is limited to domains and properties owned and operated by Cardinal Markets and its acquisitions. Software components used within Cardinal Markets are eligible and may be exploited in your vulnerability testing. Note that bugs in third-party components only qualify if we determine that they can be used to successfully exploit Cardinal Markets. Root cause duplicates (i.e. same issue across multiple hosts or endpoints) will be considered duplicates when the underlying component/mechanism is the same.
Bounties will not be paid for fixed issues which are no longer reproducible, if issues are already known before the ticket is validated, or if they were fixed not as a result of the bug bounty submission.

# Zero-Day Issues
Cardinal Markets accepts zero-day issues in third party software that can be directly used to compromise the confidentiality or integrity of our products. Zero-day issues may be submitted to our program at any time; however, we will only accept reports that permit us to disclose the issue to the relevant vendors. We cannot authorize testing against any third parties or our vendors.

# Starting Point
Not sure where to start? Here are a few areas we’d like to see more coverage of and some questions to get you started:
* Authenticated issues - Create a test account using your the disclosure platform email and test functionality from the perspective of an authenticated user. What bugs exist in authenticated workflows?
* Business Logic issues - Can UI protections be circumvented with underlying API calls or can you perform sequence steps out of order in ways that have a security impact?
* Sensitive Information Disclosure - Are there places in the application where sensitive data like SSNs or other PII are handled insecurely?

Configuration files are provided solely to assist you in configuring your tooling. Cardinal Markets makes no representations or warranties, express or implied, and assumes no responsibility or liability for any outcomes or issues arising from its use.

# Scope
Tier 1:
* *.cardinal-markets.test - cardinal-markets.test contains internal Cardinal Markets services.
* *.cardinal-markets.test - cardinal-markets.test contains internal Cardinal Markets services.
* *.cardinal-markets.test - cardinal-markets.test contains the bulk of Cardinal Markets web assets, APIs, and publicly accessible services.
* api.cardinal-markets.test - api.cardinal-markets.test is an AWS ALB that proxies traffic to many different Cardinal Markets services.
For example, while Cashier is available at cashier.cardinal-markets.test, it’s also available at api.cardinal-markets.test/cashier. In most cases, the endpoints should be identical in functionality.
* nummus.cardinal-markets.test - Nummus handles cryptocurrency trading for Cardinal Markets users, and tracks cryptocurrency account balances.
* *.cardinal-markets.test - cardinal-markets.test contains internal Cardinal Markets services. You shouldn’t be able to log into anything here.
oak.cardinal-markets.test
* Major Oak (also accessible internally at oak.cardinal-markets.test) is our internal administrative tooling, which is used by Customer Support to make changes to customer accounts. Access to and vulnerabilities in Major Oak are very sensitive.
* 1634080733 iOS - Cardinal Markets Wallet is an application for owning and managing your blockchain assets in a self-custody crypto wallet.
* 6462308655 iOS - Cardinal Markets Credit Card is an application for the Cardinal Markets Gold Card.
* 938003185 iOS - Cardinal Markets: Trading and Investing is an online brokerage application for trading and investing
* com.cardinal-markets.test Android - Cardinal Markets: Trading and Investing is an online brokerage application for trading and investing
* com.cardinal-markets.test Android - Cardinal Markets Wallet is an application for owning and managing your blockchain assets in a self-custody crypto wallet.
* com.cardinal-markets.test Android - Cardinal Markets Credit Card is an application for the Cardinal Markets Gold Card.
* com.cardinal-markets.test Android - Cardinal Markets: Trading and Investing is an online brokerage application for trading and investing for international users
* www.cardinal-markets.test - www.cardinal-markets.test is the main host associated with the Bitstamp website. Subdomains are in Tier 3.

Tier 2:
* *.cardinal-markets.test
* *.cardinal-markets.test

Tier 3:
* *.cardinal-markets.test
* *.cardinal-markets.test
* *.cardinal-markets.test
* *.cardinal-markets.test
* *.cardinal-markets.test
* *.cardinal-markets.test
* fusion.cardinal-markets.test - Production environment and TradePMR application.
* www.cardinal-markets.test
* insight2.cardinal-markets.test
* *.cardinal-markets.test - All Bitstamp supporting services and subdomains which are listed below.  Details about APIs can be found here: https://www.cardinal-markets.test/api/ Subdomains pointing to third-party services are not in scope.
* Id1406825640 - Bitstamp iOS application
* test.cardinal-markets.test - Bitstamp Android application


# Out of Scope
* shop.cardinal-markets.test - Report findings to Brilliant Made https://www.cardinal-markets.test/
* fleet.infra.cardinal-markets.test
* content.research.cardinal-markets.test - Report findings to https://www.cardinal-markets.test
* events.cardinal-markets.test
* www.cardinal-markets.test/contact/sales
* affiliates.cardinal-markets.test
* vgs-api.cardinal-markets.test
* share.cardinal-markets.test
* affiliates.cardinal-markets.test
* esg.cardinal-markets.test
* startinvesting.cardinal-markets.test
* go.cardinal-markets.test
* underthehoodpod.cardinal-markets.test
* press.cardinal-markets.test
* roadshow.cardinal-markets.test
* weareallinvestors.cardinal-markets.test
* careers.cardinal-markets.test
* earlytalent.cardinal-markets.testauth-sandbox.cardinal-markets.test
* api-sandbox.cardinal-markets.test
* fusion-demo.cardinal-markets.test
* fusion-demo.uat.cardinal-markets.test
* fusion-demo.uat2.cardinal-markets.test
* fusion.uat.cardinal-markets.test
* fusion.uat2.cardinal-markets.test
* fusion.uat3.cardinal-markets.test
* auth-validation.cardinal-markets.test
* api-validation.cardinal-markets.test
* auth.cardinal-markets.test
* api.cardinal-markets.test
* sandbox.cardinal-markets.test

We consider most informative-type issues to be out of scope, like SPF issues. If most other bug bounty programs exclude it, we likely would too. 
* Physical attacks against Cardinal Markets employees, offices, or data centers
* Social engineering attacks against Cardinal Markets employees or users, including phishing
* Vulnerabilities in third-party integrations with the Cardinal Markets API or third-party banking functionality (e.g. credit card chargebacks made through your financial institution)
* Vulnerabilities that require physical access, rooted / jailbroken devices, or debug access to a user’s device
* Denial of service without prior authorization
* Subdomain takeover without taking over the subdomain
* Cache poisoning
* Email list or notification setting configuration issues or information disclosure
* Clickjacking without impact
* Disclosure of publicly available information
* Lack of security flags in cookies (except session cookies)
* Lack of security headers unless exploitable
* Vulnerabilities caused by out-of-date browsers or browser add-ons
* Vulnerabilities caused by out-of-date or no longer maintained Android or iOS versions
* Mobile application root and jailbreak detection
* For Say Technologies: Voting information disclosure via IDOR, and anything including contact or support forms
* DNS records including email policy (SPF, DKIM, DMARC), DNSSEC
* Issues related to unsafe SSL/TLS cipher suites or protocol versions unless exploitable
* Lack of EXIF stripping on uploads, unless those uploads are publicly accessible
* Logout CSRF

Additionally the disclosure platform has core ineligible findings that are applicable to this program