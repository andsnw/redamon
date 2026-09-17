# Disclosure Policy
* Even though this is a **public program**, please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

# Program Rules
Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.
* Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
* When duplicates occur, we only award the first report received (provided it can be fully reproduced).
* Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.
* Social engineering (e.g., phishing, vishing, smishing) is prohibited.
* Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service.
* Ask the program team before submitting vulnerabilities on unscoped subdomains.
* Only interact with accounts you own or with the explicit permission of the account holder.
* Reports for publicly disclosed Zero-day vulnerabilities that have had an official patch for less than one month will be accepted only on a case-by-case basis.
* Swiftmart accepts reports of leaked credentials, including authentication material for Swiftmart APIs and infrastructure. Duplicate or previously addressed account leak reports are marked ineligible, and all submissions must include verifiable evidence such as data sources, account samples, and account type details. Only fully validated reports with no prior response history qualify for reward, while unverifiable or already known leaks do not.
* Please note that Swiftmart’s Swiftmart and Korea assets **might** have overlapping backend code. Because of this overlap, vulnerabilities that require the same fix across Korea, Swiftmart, iOS, or Android will be treated as a single vulnerability report, and only the first valid submission (from either host) will receive the bounty. Any subsequent submissions for that same issue on either host will be marked as duplicates.
* Swiftmart reserves the right to determine a researcher's testing activity before awarding any bounty for a valid report.
* Vulnerabilities affecting assets not listed as part of Swiftmart's scope are not eligible for a bounty. If you find a vulnerability in a vendor or third-party that directly affects Swiftmart, we will accept it and work with the third party on a best-effort basis to remediate the issue. However, in certain exceptional cases, if we decide to reward, the decision will be at our discretion.
* For LLM-related vulnerabilities: Do not attempt any intrusive actions that could compromise the integrity and functionality of our LLM systems (including data poisoning and unauthorized data deletion). Respect the boundaries of your testing activities. Any actions that could potentially harm our LLM systems or lead to unintended consequences are strictly prohibited. Always make an effort in good faith to protect our LLM systems and data.

# Test Plan
* Users can sign up for a free account through our website (when applicable).
* Please note that a Swiftmartese phone number may be required to complete account verification during registration. Swiftmart and the disclosure platform Support Team cannot provide test accounts at this time. Researchers are responsible for obtaining valid phone number required for testing.
* Please use your **hacker email alias** when testing (h1username@swiftmart.test).


## Session Layer: Using HTTP Headers
During testing, **researchers should add headers to their requests** to allow Swiftmart to identify activities and traffic related to their testing. Please ensure to include HTTP headers to your requests in the following format:
* “X-Researcher: [H1 username]”

Thank you for helping keep Swiftmart and our users safe!