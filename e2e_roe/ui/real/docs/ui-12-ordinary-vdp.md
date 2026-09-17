# Disclosure Policy
* Please, follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

# Program Rules
Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.

* Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.
* When duplicates occur, we only award the first report that was received (provided that it can be fully reproduced).
* Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.
*  Employees and contractors of the organization are not eligible to participate in this program.
* ⛔ Don't use or interact with accounts or data you don't own, including but not limited to  restaurants/venues and merchant data.
* ⛔ Use only your own accounts and data for testing purposes.

# Testing Plan
* Users are able to sign up for a free account through our website
* Please use your **hacker email alias** when testing (`h1username@norvik-delivery.test`)
* Claim credentials (when applicable) for additional testing
* Add the following headers to requests: `X-Researcher-Research: [H1 username]`. Reports resulting in testing without headers can result in the forfeiture of the eligible bounty.
* Please, keep report brief and concise. 300-400 words per report is a good limit.

## Test entities
- If you need to test any sort of access to user data, please do it only against this specific **consumer test account**, whose `user_id` is `670fa3e9ead6e49d65cc3614`. 
- If you need to test any sort of access to restaurant or venue data, please do it only against this specific **venue test account**, whose `venue_id` is `670e7897e3c56dcc5b5a0989`.
- If you need to test any sort of venue-related functionality, please do it only against this test venue (real purchase is not available): https://norvik-delivery.test/en/fin/helsinki/venue/test-670e7897e3c56dcc5b5a0989-sh0p

## Where can we get credentials?
We have several user types:
- Customer account. You can self-register using [norvik-delivery.test](https://norvik-delivery.test), the [iOS app](https://app-store-ios.test/app/id943905271), or the [Android app](https://app-store-android.test/store/apps/details?id=com.norvik-delivery.test).
- Courier account. Not available at the moment.
- Merchants or business account. Not available at the moment.

# Out of scope

 * Multiple leaked human identity credentials originating from third-party datasets (leaked credential lists, databases, monitoring services and credential marketplaces)
 * Testing the payment processors is out of scope
 * Spam, social engineering and physical intrusion
 * There are humans behind every Customer Support chat. Any interaction with Customer Support staff, including social engineering attempts, is forbidden and out of scope
 * Network DoS/DDoS attacks
 * Web Cache Poisoned Denial of Service
 * Brute force attacks
 * Attacks requiring access to a victim's computer/device
 * Reports that state that software is out of date/vulnerable without a proof-of-concept
 * Mass creating of entities, including accounts, profiles and applications
* `GATEKEEPER_API_KEY` exposure since it is not a secret value

## Web
 * API key disclosure without proven business impact
 * Signup with unverified mobile numbers (if you took over an existing number, then that's a finding!)
 * Verbose messages/files/directory listings without disclosing any sensitive information
 * CORS misconfiguration without proven impact
 * Missing cookie flags
 * Missing security headers
 * Cross-site Request Forgery without proven impact
 * Autocomplete on web forms
 * Bypassing rate-limits or the non-existence of rate-limits
 * Best practices violations (password complexity, expiration, re-use, etc.)
 * Clickjacking without proven impact/unrealistic user interaction
 * CSV Injection
 * Sessions not being invalidated (logout, enabling 2FA, etc.)
 * Content injection without being able to modify the HTML
 * Username/email enumeration
 * Email bombing
 * HTTP Request smuggling without any proven impact
 * Homograph attacks
 * Banner grabbing/Version disclosure
 * Subdomain takeover without proof
 * Arbitrary file upload without proof
 * Host header injection without proven business impact

## Mobile
 * Shared links leaked through the system clipboard
 * Attacks requiring malicious apps to be installed beforehand
 * Sensitive data in URLs/request bodies when protected by TLS
 * Lack of obfuscation
 * Path disclosure in the binary
 * Lack of jailbreak & root detection
 * Crashes due to malformed URL Schemes
 * Lack of binary protection (anti-debugging) controls, mobile SSL pinning
 * Snapshot/Pasteboard leakage
 * Runtime hacking exploits (exploits only possible in a jailbroken environment)

# Legacy Hall of Fame

We appreciate reports received by the following researchers previously on the Intigriti platform: `0xcm1k3`, `0xd0m7`, `0xdln`, `_lauritz_`, `agnel123`, `altcool6`, `amirsec76`, `anhdva`, `anonymoushobbit`, `apogiatzis`, `athulms`, `badmusmuritado`, `baloocky`, `black_dd`, `bughuntar`, `bunny0417`, `callmedaddy`, `chrismas_here`, `commadno6407`, `crofr`, `cybersamurai`, `d0xing`, `deneuv`, `dk4trin`, `drak3hft7`, `drdoctor0`, `dynnyd20`, `floerer`, `giongfnef26`, `godiego`, `goseck`, `greenfire`, `greensec`, `gug_saas`, `h4rshbothra`, `harshtalavaniya99`, `hashem_mm`, `hetroublemak3r`, `ja`, `juniorbrets`, `k_link_1337`, `kir_tis`, `kurt4j`, `liikala96`, `ling0`, `lucsouza`, `m0chan`, `maara`, `makaveli`, `mariosk`, `marius_dp`, `mherano`, `mikemyers`, `mysc0x1`, `nc5`, `nd_passenger`, `neolokir`, `ninjan11`, `noman181`, `notroks`, `notron`, `nva`, `oxidor`, `phiko`, `pod_krinko1`, `pprab`, `pushpak35`, `pwnedchicken`, `qwe_aldo1`, `rahimian`, `redyetidev`, `richlee`, `rjflsec`, `s3c_krd`, `s3nn`, `saintbarber`, `sanfindings`, `sezo`, `sheikhrishad`, `six2dez`, `slashx0x`, `soloboy`, `steffe`, `talha`, `testt0`, `th3ho4ds`, `thaivd98`, `the14st`, `themastersunil`, `theokeen`, `thezodd`, `valbrux`, `vkiee`, `wcraft`, `whitehatind`, `xburns`, `yotamsofer`, `youngvanda`, `yuzadef`, `zere`, `bricked`, `rev1th`

Thank you for helping keep Norvik Delivery and our users safe!