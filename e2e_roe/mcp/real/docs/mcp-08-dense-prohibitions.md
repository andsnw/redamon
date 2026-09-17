Cursolar looks forward to working with the security community to find vulnerabilities in order to keep our businesses and customers safe.

----------------------

# Response Targets
Cursolar will make a best effort to meet the following response targets for hackers participating in our program. If any additional information is required from you, please allow for another 5 days for our team to review and respond. Our security team often needs to validate internally with our development team. In those cases, your patience will be much appreciated.

| Type of Response | SLA in business days |
| ------------- | ------------- |
| First Response | 5 days |
| Time to Triage | 8 days |
| Time to Resolution | depends on severity and complexity |

We’ll try to keep you informed about our progress throughout the process.

----------------------

# Disclosure Policy
* Please do not discuss any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).
* Disclosure is strictly prohibited

----------------------

# Program Rules
* ==The ***.cursolar.test** environment is available only from .**Monday** to **Friday**. Do not perform tests in a production environment.==
* Only test against assets that are explicitly defined in the scope.
* Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue will not be eligible.
* Please, use markdown to send commands and HTTP request/response examples.
* Submit one vulnerability per report, unless you need to chain vulnerabilities to provide impact.
* When duplicates occur, we only accept the first report that was received (provided that it can be fully reproduced).
* Multiple vulnerabilities caused by one underlying issue will be accepted the first one.
* Social engineering (e.g. phishing, vishing, smishing) is prohibited.
* Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service. Only interact with accounts you own or with explicit permission of the account holder.
* Although the disclosure platform has [Detailed Platform Standards](https://docs.disclosure-platform.test/en/articles/8369826-detailed-platform-standards), the final severity of the vulnerability will be determined by the Cursolar team, considering internal criteria that may result in a different severity.

## Subdomain Takeover
Researchers must provide a proof of concept (PoC) demonstrating that the takeover was performed by them (e.g., by creating a PoC that includes their nickname).
Takeovers conducted by third parties will be accepted as **Informative**.

## Cross Site Scripting (XSS)
If you found a XSS, please inform in your report:
1. Who is the attacker and the victim of the XSS context?
Ex.: Does a customer without privileges affect an admin user through this XSS vulnerability?

2. Does the attacker is able to obtain the victim's session cookie through this XSS vulnerability? If this is not possible, considering the application context, what is the worst thing an attacker could do through this vulnerability?

3. Does the attacker need to encode the XSS payload to bypass some sanitization controls?

## Session Layer: HTTP Headers
Researchers should add headers to requests such as:

| Identifier | Format | Example |
| ------------- | ------------- |------------- |
| Your Username | X-Bug-Bounty: Researcher-<username> |X-Bug-Bounty: Researcher-bughunter |

##Big Reward
Researchers who demonstrate excellence by submitting 2 valid critical severity reports or 4 valid high severity reports may apply for entry into our prestigious Cursolar private program.

As a member of the Cursolar private program, you’ll unlock:

* Access to various platform features.
* Opportunity to participate in special bug bounty campaigns.
* Higher bounty payouts and more!

---

# About Us
Cursolar is a platform for the distribution of digital products, offering services to host a product, help boosting sales and payment processing. Cursolar has three different profiles that can be found within the platform: Producers, Affiliates and customers.

* [Producers](https://blog.cursolar.test/en/what-are-producers/) are people or companies who publish some kind of digital content to be sold online. This includes courses, e-books or any other form of digital product.
* [Collaborators](https://help.cursolar.test/en/article/115007885368/how-to-set-up-and-access-the-collaborators-center-on-Cursolar-) were profiles with permissions to perform certain tasks for the Producers, and help manage their sales and customers. For each collaborator profile, Producers can define specific permissions and add collaborators to each of them.
* [Affiliates](https://blog.cursolar.test/en/what-are-affiliates/) are people or companies who participate in an Affiliate Program and wish to earn commissions to recommend or promote other people’s or companies’ products.
* Customers are the consumers who buy or access digital products through Cursolar’s platform.

If you want to know more about Cursolar, Producers, Collaborators, Affiliates and Products, please refer to:
   * [Cursolar Academy](https://www.cursolar.test/pt/academy) 
   * [Cursolar Blog](https://blog.cursolar.test/en/)

----------------------

# Test Plan
* STOP testing if you are unsure about the impact it may have on our systems. If you think you may cause, or have caused, damage while testing a vulnerability, report your initial finding(s) and request authorization to continue testing.
* Please use your hacker email alias when testing (h1username@cursolar.test)
* Only interact with accounts you own or with the explicit permission of the account holder.
* Include a custom HTTP header in all your traffic. Burp and other proxies allow the easy automatic addition of headers to all outbound requests. 
* Do not upload shells or create a backdoor of any kind.
* No Data deletion / alter is allowed
* Minimize the mayhem. Adhere to program rules at all times. Do not use automated scanners/tools - these tools include payloads that could trigger state changes or damage production systems and/or data.
* Register an account here: https://sso.cursolar.test/signup

* **Test Card Information 1**
   * Card Banner: VISA
   * Card number: 4111 1111 1111 1111
   * Name on Card: Any name
   * Expiration: 03/30
   * CVV: 737

* **Test Card Information 2**
   * Card Banner: MASTERCARD
   * Card number: 5555 4444 3333 1111
   * Name on Card: Any name
   * Expiration: 03/30
   * CVV: 737

# Processes in the Platform

**Registering**
* [How do I register at Cursolar?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/115000438272-How-do-I-register-at-Cursolar-)
* [How can I update my Personal Information?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/215826318-How-can-I-update-my-Personal-Information-?mobile_site=false)
* [How can I update my buyer account to Affiliate/Producer?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/216971287-How-can-I-update-my-buyer-account-to-Affiliate-Producer-)
* [How do I change the e-mail registered in my Cursolar account?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/208279118-How-do-I-change-the-e-mail-registered-in-my-Cursolar-account-)
* [How can I reset my Cursolar access password?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/215826368-How-can-I-reset-my-Cursolar-access-password-)
* [General Articles on registering a product](https://atendimento.Cursolar.cursolar.test/hc/pt-br/sections/201722498-Cadastrando-meu-produto)

**Editing and setting up a product**
* [How to register my product?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/215828518-How-to-register-my-product-)
* [How to adjust your product guarantee deadline](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/360034552751-How-to-adjust-your-product-guarantee-deadline)
   
**[Frequent questions asked by Producers](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/360017791931-Frequent-questions-asked-by-Producers)**
* [What payment types and methods can I opt for my product?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/216440337-What-payment-types-and-methods-can-I-opt-for-my-product-)
* [What is a subscription product and how to create one?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/115002364191-What-is-a-subscription-product-and-how-to-create-one-)
* [General Articles on Managing a product](https://atendimento.Cursolar.cursolar.test/hc/pt-br/sections/115001767627-Gerenciando-meu-produto)

**Creating an offer and discount coupons**
* [How do I create an offer for my product?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/215827788-How-do-I-create-an-offer-for-my-product-)
* [How do I create an offer for my subscription product?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/115001961407-How-do-I-create-an-offer-for-my-subscription-product-)
* [How to create discount coupons for my product?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/360015325411-How-to-create-discount-coupons-for-my-product-)

**Affiliate Program**
For producers:
* [How do I set up my Affiliate Program?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/210874788-How-do-I-set-up-my-Affiliate-Program-)
* [How to recruit Affiliates to my product?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/210917278-How-to-recruit-Affiliates-to-my-product-)
* [How to manage affiliation requests](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/360008311652-How-to-manage-affiliation-requests)
   
**[General Articles on Affiliate program](https://atendimento.Cursolar.cursolar.test/hc/pt-br/sections/201704957-Programa-de-Afiliados)**
For affiliates
* [How do I become an Affiliate to a product on Cursolar?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/215829028-How-do-I-become-an-Affiliate-to-a-product-on-Cursolar-?mobile_site=false)
* [FAQ about Affiliation](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/360017507912-Frequent-questions-about-Affiliation?mobile_site=false)
* [What are HotLinks?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/215829088-What-are-HotLinks-?mobile_site=false)
* [How to search for products on Cursolar Market?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/115006334868-How-to-search-for-products-on-Cursolar-Market-?mobile_site=false)
* [What are Cursolar’s rules to attribute commissions?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/360016601731-What-are-Cursolar-s-rules-to-attribute-commissions-?mobile_site=false)
* [General Articles on Commission Tracking](https://atendimento.Cursolar.cursolar.test/hc/pt-br/sections/115001783228-Rastreamento-de-comiss%C3%A3o?mobile_site=false)

**Co-Production**
* [How to setup a product’s co-production?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/215828398-How-to-setup-a-product-s-co-production-)

**Withdrawals and Extracts**
* [How to withdraw sales commissions?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/216440207-How-to-withdraw-sales-commissions-)
* [Which status can a withdrawal request take?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/115000436912-Which-status-can-a-withdrawal-request-take-)
* [What can stop me from receiving a commission after a sale?](https://atendimento.Cursolar.cursolar.test/hc/en-us/articles/209003477-What-can-stop-me-from-receiving-commission-after-a-sale-)

**Generating a Brazillian CPF (document ID)**
If you see some CPF field to fill, you can use a fake CPF generated by a CPF generator, such as:
* https://www.4devs.cursolar.test/gerador_de_cpf
* https://www.cursolar.test/gen-random-br-br.php

This fake CPF is just for tests propose

----------------------

# Out of scope vulnerabilities
* Any activity that could lead to the disruption of our service (DoS or DDoS).
* Clickjacking
* Cross-Site Request Forgery (CSRF) on unauthenticated forms or forms with no sensitive actions
* Self-exploitation (self XSS, self denial-of-service, etc.), unless a method to attack a different user can be demonstrated.
* Attacks requiring MITM or physical access to a user's device.
* Previously known vulnerable libraries without a working Proof of Concept.
* Comma Separated Values (CSV) injection without demonstrating a vulnerability.
* Missing best practices in SSL/TLS configuration.
* Content spoofing and text injection issues without showing an attack vector/without being able to modify HTML/CSS
* Rate limiting or other 'load testing' types of issues
* Brute force of promo code
* Missing best practices in Content Security Policy.
* Missing HttpOnly or Secure flags on cookies
* Missing email best practices (Invalid, incomplete or missing SPF/DKIM/DMARC/TXT records, etc.)
* Vulnerabilities only affecting users of outdated or unpatched browsers [Less than 2 stable versions behind the latest released stable version]
* Software version disclosure / Banner identification issues / Descriptive error messages or headers (e.g. stack traces, application or server errors).
* Tabnabbing
* Open redirect - unless an additional security impact can be demonstrated
* Issues that require unlikely user interaction
* Internal IP exposure, unless you can do something impressive with it
* Leaking information via the Referer header
* Password or account recovery policies, such as reset link expiration or password complexity
* Account/email Enumeration
* Fixed Session
* Issues related to credentials/info disclosure in public sources such as Trello, GitHub, Wayback, etc, will be analyzed in each case and may not be eligible for bounty.
* Content spoofing, XSS or HTML injection in places where intentionally accepting HTML or via Third-party Subdomain.
* Any GraphQL vulnerabilities with DoS impact
* 0-day and other CVE vulnerabilities reported 30 days after initial publication (CVE List Status of Published). 

## Nginx Misconfiguration Issues
The following Nginx-related security issues are considered out of scope for this bug bounty program:

1. Common Nginx Configuration Issues:
   - Missing security headers (X-Frame-Options, X-Content-Type-Options, etc.)
 
2. Nginx Proxy Configuration:
   - Proxy bypass attempts through header manipulation
   - X-Forwarded-For spoofing
   
3. Server Block Configuration:
   - Default error pages exposed

----------------------

# Safe Harbor
Any activities conducted in a manner consistent with this policy will be considered authorized conduct and we will not initiate legal action against you. If legal action is initiated by a third party against you in connection with activities conducted under this policy, we will take steps to make it known that your actions were conducted in compliance with this policy.

----------------------

Thank you for helping keep Cursolar and our users safe!