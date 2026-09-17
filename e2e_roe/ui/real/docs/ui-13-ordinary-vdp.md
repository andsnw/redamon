# Disclosure Policy
* Please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

# Scope
** Any domain that has the brand name of Aurelian Chemical  ** 
* Please see the structured scope section for our list of assets.
* For wildcard matches please validate the content of the website to be relevant to Aurelian Chemical business.

# Program Rules
* Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue may not be marked as triaged.
* Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
* When duplicates occur, we only triage the first report received (provided that it can be fully reproduced).
* Multiple vulnerabilities caused by one underlying issue will be treated as one valid report.
* Social engineering (e.g., phishing, vishing, smishing) is prohibited.
* Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service. 
* Only interact with accounts you own or with explicit permission of the account holder.
* **Any report, that is a direct copy obtained from an Ai model in an attempt to impose a risk inflation/risk exaggeration, will be directly closed as 'Not Applicable' **.

# Out of Scope

## Domains
* Any domain that is not listed in the Domains section, is out of scope for this program
* For wildcard matches please validate the content of the website to be relevant to Aurelian Chemical business

## Application
* POST/GET based XSS without demonstrated business impact will not be accepted
* CSRF without demonstrated business impact will not be accepted
* Social Media Link Hijacking will not be accepted
* API key disclosure without proven business impact
* Adobe Experience Manager (AEM) Information disclosure, when it's simply public data without any demonstrated impact
* WordPress usernames disclosure
* CAPTCHA related abuse scenarios without proven exploitation
* Pre-Auth Account takeover/OAuth squatting
* Self-XSS that cannot be used to exploit other users
* Verbose messages/files/directory listings without disclosing any sensitive information
* CORS misconfiguration on non-sensitive endpoints
* Missing cookie flags
* Missing security headers
* Cross-site Request Forgery with no or low impact
* Presence of autocomplete attribute on web forms
* Reverse tabnabbing
* Bypassing rate-limits or the non-existence of rate-limits.
* Best practices violations (password complexity, expiration, re-use, etc.)
* Clickjacking without proven impact/unrealistic user interaction
* CSV Injection
* Sessions not being invalidated (logout, enabling 2FA, etc.)
* Tokens leaked to third parties
* Anything related to email spoofing, SPF, DMARC or DKIM
* HTML Content injection (HTMLi)
* Username/email enumeration
* Email bombing
* HTTP Request smuggling without any proven impact
* Homograph attacks
* XMLRPC enabled
* Banner grabbing/Version disclosure
* Not stripping metadata of files
* Same-site scripting
* Subdomain takeover without taking over the subdomain
* Arbitrary file upload without proof of the existence of the uploaded file
* Blind SSRF without proven business impact (pingbacks are not sufficient)
* Disclosed/misconfigured Google Maps API keys
* Host header injection without proven business impact
* Open redirect without proven business impact.
* PHPinfo without any sensitive information.
* SSL/TLS misconfigurations

## General
* In case that a reported vulnerability was already known to the company from their own tests, it will be flagged as a duplicate
* Theoretical security issues with no realistic exploit scenario(s) or attack surfaces, or issues that would require complex end user interactions to be exploited
* Spam, social engineering and physical intrusion
* DoS/DDoS attacks or brute force attacks
* Vulnerabilities that only work on software that no longer receive security updates
* Attacks requiring physical access to a victim's computer/device, man in the middle or compromised user accounts
* Recently discovered zero-day vulnerabilities found in in-scope assets within 14 days after the public release of a patch or mitigation may be reported, but are usually not eligible for a bounty
* Reports that state that software is out of date/vulnerable without a proof-of-concept

## Mobile
* Shared links leaked through the system clipboard
* Any URIs leaked because a malicious app has permission to view URIs opened
* The absence of certificate pinning
* Sensitive data in URLs/request bodies when protected by TLS
* Lack of obfuscation
* Path disclosure in the binary
* Lack of jailbreak & root detection
* Crashes due to malformed URL Schemes
* Lack of binary protection (anti-debugging) controls, mobile SSL pinning
* Snapshot/Pasteboard leakage
* Runtime hacking exploits (exploits only possible in a jailbroken environment)
* API key leakage used for insensitive activities/actions

# Testing
# # Session Layer: HTTP Headers
Researchers should add headers to requests such as: “X-Researcher-Research: [H1 username]”

* While you’re welcome to create accounts where they are available. We ask that you use your the disclosure platform alias when doing so. You can find instructions on how to find your alias [here](https://docs.disclosure-platform.test/en/articles/8404308-hacker-email-alias).
* We’re unable to provide account licenses or refund expenses incurred during testing.


Thank you for helping keep Aurelian Chemical and our users safe!