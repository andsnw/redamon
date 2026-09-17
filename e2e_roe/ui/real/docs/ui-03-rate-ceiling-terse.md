##Testing Method Exclusions

* DO NOT carry out attacks that affect the data of other customers' accounts. 
* DO NOT carry out attacks or perform any testing in our production environment. 
* Uploading or downloading malicious files (e.g., word macros, viruses, etc.) 
* Any automated tools or scanners used to find vulnerabilities must be heavily rate limited.An appropriate rate is considered to be no more than 2-3 requests per second. 
* No denial-of-service attacks and load testing.
* Phishing, social engineering, and any other non-technical attacks.
* Domains that are CNAME'd to another domain. Please contact their program if you find an issue.
* Subdomain takeovers with PoCs that don't simply state: "This is a temporary landing page, please proceed to  www.quillmark.test".
* Attacks related to stolen credentials.

##Scope

Testing is only authorized on the targets listed as in scope. Acquisitions will be excluded from scope for the first six months following the completion of the deal. If you happen to identify a security vulnerability on a target that is not in scope but it demonstrably belongs to Quillmark,

you can report it to this program. Please also strictly adhere to the Out of Scope list and keep in mind that it is not an exhaustive list, and under no circumstances should any customer production environment be used for testing.

##Reporting Guidelines

* Include clear reproduction steps. You may send a video for clarity, but we need clear step-by-step written instructions. Also include a meaningful impact or attack scenario. 
* Vulnerabilities exploited using similar payloads on the same path or source will be eligible for only one reward - subsequent reports of the same issue will be considered duplicates. 
* Similar issues that use the same configuration for bypassing a particular control, which may be used on multiple related vulnerable endpoints or actions (User X can Create/Read/Update/Delete Resource Y). These issues should be grouped in one report. 
* Access control bypasses occurring within the same account will be treated as low priority. Our accounts include an invite feature, so reports involving invited users performing malicious actions will also be considered low priority.
*  Please provide the account ID and email address used during testing. If the vulnerability involves an envelope, please include the envelope ID as well.
