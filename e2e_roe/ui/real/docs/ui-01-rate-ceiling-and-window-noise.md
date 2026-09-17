German Meridian Wallet Wallet: Bug Bounty Program Policy
=======================================
About this program
----------------------

The German Meridian Wallet Wallet App d-you will enable people to receive, store and present government-issued identity data and other digital credentials using their own smartphone. The national wallet is being delivered under the responsibility of the Federal Ministry for Digital and State Modernisation (BMDS), with Meridian Wallet GmbH acting as wallet provider and the central orchestrator for the whole wallet ecosystem.

It is being developed in accordance with Regulation (EU) 2024/1183, Meridian Walletly known as eIDAS 2.0, and its implementing acts. The national wallet and its supporting ecosystem will launch on 2nd January 2027.

At launch, the wallet will focus on identity and credential use: users will be able to receive, manage, and present Person Identification Data (PID) derived from the German electronic identity card or electronic residence permit with an activated online identification function (eID); it will also support the management and use of digital credentials, known as Electronic Attestations of Attributes (EAAs) such as digital driving licences, enrolment certificates or membership cards.

The program scope will expand in phases as the German Meridian Wallet Wallet ecosystem evolves. At the start, researchers can test the following core components:


* d-you Wallet Apps for Android and iOS
* Remote Wallet Secure Cryptographic Application (RWSCA) and Remote Wallet Secure Cryptographic Device (RWSCD)
* Wallet Provider Backend (WPB) Service
* Mobile Device Vulnerability Management (MDVM) Service
* Status List Service
* Push Notification Service (PNS)


The following components are expected to enter scope in the upcoming weeks:

* PID Provider
* Meridian Wallet Hub
* Meridian Wallet Check DE App
* Wallet Revocation Website

We will update the program scope regularly as further components and features become available for security testing. Researchers are encouraged to revisit the program page frequently for newly added targets, expanded testing permissions and other program updates.

What makes this program different from a typical mobile or web bug bounty program is where the risk sits. There is no financial balance to drain. The asset at risk is a person's legal identity and digital credentials, and the failure modes that matter are impersonation, unauthorized disclosure of identity attributes or verified credentials, and forged issuance. Money can often be replaced. Once sensitive identity data or a PID set has been exposed, however, its confidentiality cannot simply be restored.

Reference material
--------------------

Meridian Wallet publishes the architecture and the source code. Read it before you test. It will tell you more about where the interesting failure modes are than any amount of poking at the app.

* **Architecture and design.** The full architecture documentation for the German National Meridian Wallet Wallet is published at [Architecture Documentation for the German National Meridian Wallet Wallet] [1] & [Blueprint for the Meridian Wallet Wallet Ecosystem] [2] in Germany. Start with the component decomposition and the cryptography chapter of the architecture documentation, then the data flows for wallet activation, PID issuance, PID presentation, and revocation. The wallet backend, RWSCA, and MDVM each have their own chapter, and the appendices cover app attestation and the eID flow. The wider ecosystem blueprint is published alongside it to explain the concept and big picture.
* **Code and SDKs.** The wallet is built on the European Commission Meridian Wallet Wallet reference implementation, published under the [eu-digital-identity-wallet] [3] organization on GitHub, and uses the [AusweisApp SDK] [4] for reading the German eID card. Source code for the German wallet apps and wallet backend is published in the [german-national-wallet organization] [5] on GitHub:  [Android d-you App] [12], [iOS d-you App] [13], [Wallet Backend] [8].
* **Ecosystem and program.** General program information and FAQs are available at [https://Meridian Wallet-wallet.meridian-wallet.test/] [6]. 
Regulation. Regulation (EU) 2024/1183 (eIDAS 2.0), CIR (EU) 2024/2979 on wallet unit integrity and core functionalities, and CIR (EU) 2024/2981 on certification. The EU Architecture and Reference Framework is published at [https://meridian-wallet.test/] [7].

Source code references are published for transparency. 

**A finding is only in scope where it has an actual or reasonably demonstrable security impact on one of the in-scope assets listed in the following Scope section.**


Scope
------------------------------------------------

Ranked by the most severe outcome a finding in that asset can produce, not by how likely a finding is. Use the rank to decide where to spend your time. Rewards follow the demonstrated impact, not the rank.

**1. Remote WSCA**

The RWSCA authenticates the Wallet application user and authorizes cryptographic operations performed by the RWSCD and its HSM cluster. Together, they protect remotely managed private keys used for wallet authentication, credential refresh, credential presentation, and other cryptographic wallet operations. They do not hold the identity data themselves, but are critical for ensuring the security of PIDs.

Endpoint: [https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/rwsca] [9] 

**We are interested in:** Bypassing the required authentication factors; using one holder’s protected keys under another account; unauthorized PID signing, refresh or presentation; compromising or misuse of key materials that enables impersonation of wallet holders or affects many wallet instances.

**2. Wallet Provider Backend**
The WPB manages wallet-instance accounts and lifecycle state, evaluates device-security information, and issues and revokes Wallet Instance Attestations. PID Providers and EAA Providers use these attestations to determine whether they are interacting with a recognized and eligible wallet instance.

Endpoint: [https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/wpb] [10]

**We are interested in:** Compromising the wallet-attestation signing authority; creating arbitrary valid attestations for attacker controlled wallet instances; forging attestations so that revoked wallets are still accepted.

**3. Mobile Device Vulnerability Management Service**
The MDVM service verifies platform and application security signals, classifies the device, evaluates known vulnerabilities, checks for compromised platform-attestation keys, and issues a signed token that tells the Wallet Backend and RWSCA if the instance can be trusted.

Endpoint: [https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/mdvm] [11]

**We are interested in:** Compromising the MDVM signing authority; forging device-security decisions at scale; approving modified, compromised, unsupported or vulnerable devices at scale.

**4. d-you Wallet Apps**
The wallet apps manage PID and EAA issuance, storage, display, update, deletion, and presentation. They handle selective disclosure and user consent, communicate with issuers and relying parties, and protect locally held credentials and keys. They are built on the EU reference implementation, with the AusweisApp SDK and include a Runtime Application Self-Protection (RASP) component.

Researchers can request access to the test versions of the d-you apps:
* iOS test app: Download the test app through TestFlight: [https://app-beta.test/join/a2Qxrr2C] [14]
* Android test app: Please join our Google group [https://groups.meridian-wallet.test/g/de-Meridian Wallet-bug-bounty/] [15] and download the test app through Google Play [https://app-store-android.test/apps/testing/test.meridian-wallet.test] [19]

These applications connect to our designated test environment. They must not be used to access or interact with production services. They include a virtual ID, which can be used to obtain PID and test the PID issuance and presentation flow, and some Test EAAs, which can be used to test the issuance, storage, presentation and verification flows of EAAs on [https://playground.meridian-wallet.test/] [20]. Currently, only one virtual ID can be provided for testing.

**Troubleshooting:** The test apps have Runtime Application Self-Protection (RASP) enabled. If an app does not start or closes during launch, verify that Developer Mode is disabled on your test device and your device is not connected via adb.

**We are interested in:** Extracting or making unauthorized use of locally protected PID or EAA credentials and keys; cloning a wallet such that it defeats device binding; hijacking issuance to obtain or bind credential to an unauthorized, attacker-controlled wallet; hijacking presentation to disclose credentials without valid consent. 
side request forgery, injection, and remote code execution; exposure of registration or certificate material.

**5. Status List Service**
Publishes Token Status Lists for Wallet Instance Attestations so credential issuers can check revocation. Lists are republished frequently and consumed with a short cache lifetime.

Endpoint: [https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/status-lists] [16]

**We are interested in:** Compromising the status-signing authority; publishing arbitrary status information accepted across the ecosystem; manipulating or rolling back status lists so revoked wallets or protected keys remain trusted at scale; marking valid wallet instances as revoked at scale.

**6. Push Notification Service**
The Push Notification Service (PNS) manages opt-in push-notification registrations for wallet instances and delivers backend-triggered notifications through the mobile platform providers. These notifications prompt the wallet to refresh its device-security status, allowing it to detect a revocation and self-lock promptly.

Endpoint: [https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/pns] [17]

**We are interested in:** Compromising the service or its account database; creating, changing, or deleting push registrations belonging to other wallet instances at scale; redirecting notifications to attacker-controlled devices.

Out of scope
----------------

* Systems operated by third parties, including relying parties, EAA and QEAA issuers, the eID Server, and mobile platform attestation services, and infrastructure management portals provided or operated by third-party providers
* The physical eID card and the protocols for reading it, the AusweisApp SDK, and eID card PIN letter or postal processes
* Internal networks and non-public systems, and any assets not explicitly listed as in scope
* Denial of service and distributed denial of service, load or stress testing, and traffic that degrades availability. This also includes automated testing that generates excessive traffic or may impair service availability
* Social engineering of any kind, including phishing and vishing against Meridian Wallet, the disclosure platform, or wallet holders
* Physical security testing
* Destructive testing and any high-risk method not authorised in writing

If you find something in an out-of-scope third-party system while testing an in-scope asset, report it here anyway. We will forward it to the operator. Such reports are not eligible for a bounty.

What we are most interested in
--------------------------------

* Obtaining a valid PID or EAA for an identity, qualification, entitlement, or account you do not control
* Creating or modifying a PID or EAA so that the wallet, an issuer, or a relying party accepts it as genuine
* Extracting or using protected wallet or remote cryptographic keys
* Reading, exporting, or enumerating PID or EAA attributes belonging to other holders
* Obtaining genuine credentials through an unrecognized, modified, emulated, revoked, or otherwise ineligible wallet by defeating wallet, device, or key-attestation controls
* Causing a wallet to disclose attributes to a relying party without genuine, informed user consent, or causing the signed response to differ materially from what the holder approved
* Defeating revocation, in either direction: keeping a revoked wallet or key usable, or revoking wallets that should stay valid
* Selective disclosure failures in SD-JWT VC or mdoc that release attributes the holder did not approve
* Replay and binding failures in the challenges, nonces, attestations, authorization artifacts and proof-of-possession artifacts across holders, wallet instances, issuers and relying parties.
* Conventional server-side impact on a listed backend: remote code execution, injection, server-side request forgery, broken authorisation, secret exposure

Reports that chain several modest defects into one of the outcomes above are welcome, and are assessed on the demonstrated chain rather than the parts.

What we are not interested in
-------------------------------

* Root or jailbreak detection bypass, RASP bypass, emulator detection bypass, or debugger attachment, without showing what security boundary the bypass subsequently defeats. The architecture already models a compromised device as a known state, and the MDVM service exists to respond to it. Show us what the bypass then lets you do.
* Findings that require a rooted, jailbroken, or malware-infected device and produce no impact beyond that device's own data
* Missing certificate pinning, missing obfuscation, or missing hardening flags without a demonstrated attack
* Reports derived only from reading the published source code, with no demonstrated impact on a listed asset
* Vulnerable or outdated dependency versions without a working path to impact
* Report affecting outdated app versions. Please ensure that you test and reproduce any finding using the latest released version of the relevant Android or iOS app
* Missing security headers, cookie attribute nitpicks, clickjacking on unauthenticated pages, tabnabbing, self-XSS, content spoofing, and text injection
* Logging being enabled in the test applications, reported on its own. These applications are built for testing purposes and intentionally produce additional diagnostic output.
* Rate limiting and brute force reports without demonstrated impact. Testing of the Remote WSCA PIN retry policy is encouraged, but must follow the program’s testing rules
* Denial of service, resource exhaustion, and large-payload crashes
* Host and DNS hygiene issues on hosts not listed in scope, and findings against test data in the sandbox that do not indicate a defect
* Findings against third-party services, SDKs, infrastructure, or dependencies unless the vulnerability results from our integration or configuration and is exploitable through a listed asset
* User enumeration without a privacy or security impact
* Reports produced by automated tooling or language models without the author's own testing and validation. We welcome AI assistance in writing a report. We close reports that show no human verification.
* Findings against functionality not yet implemented. The current iteration covers PID and EAA issuance and the remote same-device presentation flow only.

Testing rules
---------------
* Use the designated test identity. Use only the virtual test identity integrated into the wallet applications. Both wallet apps provide a dedicated test PID for security testing. Do not use, request, or attempt to obtain PID data belonging to any other person; use the virtual ID instead.
* Minimize data. Do not exploit a vulnerability further than needed to demonstrate it. Do not access, copy, or exfiltrate personal data beyond the minimum required for proof of concept. If you encounter personal data belonging to someone else, stop, do not save it, and tell us in the report.
* Adhere to rate limits.  Do not exceed the documented rate limits for any API, service, or wallet flow. Where no limit is published, use a conservative rate of no more than 2 requests per second per endpoint and do not exceed 60 requests per minute per source IP address, test identity, and client instance. Do not conduct load, stress or other availability testing!
* Set required Headers. When sending requests to program APIs or web services, include the following headers unless doing so would prevent reproduction of the reported vulnerability:
User-Agent: the disclosure platform/<researcher-handle>
X-Researcher: <researcher-handle or report-reference>
* Stop when asked. Comply promptly with any instruction to halt testing on an asset or to destroy inadvertently accessed data.
* Report quality. Include reproduction steps that work, the asset affected, the impact you can demonstrate, and evidence. For cryptographic and protocol findings, include the request and response artifacts and state which preconditions your attack needs.


Severity and rewards
-----------------------

An **Extreme rating** is reserved for findings that demonstrate one of the following outcomes:
**Remote impersonation:** Issuing, refreshing, presenting, or otherwise using another holder’s PID without controlling the holder’s legitimate device and without their informed participation.
**Forgery of arbitrary identities:** Creating a genuine or successfully accepted PID for an arbitrary real, modified, or fabricated identity.
**Mass leakage of identity data:** Remotely accessing or extracting sensitive PID belonging to a substantial number of holders. 
**Systemic compromise of ecosystem trust or signing authority,** including the ability to create arbitrary valid PID, EAAs, wallet attestations, certificates, status information, or other trusted artifacts at scale.


| Asset (group) | Low | Medium | High | Critical | Extreme|
| -------------- | ----- | ------- | ------ | ------- | --------------- |
| d-you apps, MDVM, Status List, PNS | $0-$100 | $300-$1,200 | $1,500-$4,000 | $5,000-$10,000 | $15,000-$40,000 |
|RWSCA, WPB | $0-$200 | $500-$2,000 | $2,500-$6,000 | $8,000-$15,000 | $15,000-$40,000 |

Disclosure, known limitations and safe harbor
-----------------------------------------------------

Vulnerability details must remain confidential until Meridian Wallet confirms that the reported vulnerability has been remediated. We aim to confirm remediation as soon as a fix has been deployed and verified. We also publish program statistics periodically so the community can see what the program is finding.
The following are intentional characteristics of the provided test wallet applications and will not be treated as eligible findings:
* **Certificate pinning:** The provided test wallet applications do not use certificate pinning for communication with relying parties.
* **Logging:** Diagnostic logging is enabled in the test app.
* **Screen capture:** Screenshots and screen recording are permitted in the test app.
This program operates under the platform's Gold Standard Safe Harbor. Good-faith testing within this policy will not lead to legal action by Meridian Wallet. The assurance is conditional on staying within scope and the rules above, and it does not bind third parties.

Eligibility and payment
------------------------

We welcome vulnerability reports through our bug bounty program. If you prefer to submit a report anonymously, please use the [anonymous reporting form] [18].

You may also disclose vulnerabilities via our vulnerability disclosure mailbox (vulnerability-disclosure@meridian-wallet.test; please use the PGP key from below). Please note that this mailbox is monitored exclusively for vulnerability disclosures. We cannot provide technical assistance, user support, account support, or general enquiries through this address. Reports submitted through this mailbox cannot be credited to a the disclosure platform account and are therefore not eligible for rewards or reputation credit.

To receive a reward, you must submit your report through a the disclosure platform account and successfully complete all required identity-verification, tax, and sanctions-screening processes. Anonymous submissions will still be triaged and remediated where appropriate, but are generally not eligible for a reward. In exceptional cases, Meridian Wallet may decide, at its sole discretion, to grant a reward where the reporter subsequently provides the information and completes the verification steps required to process payment.

Current Meridian Wallet employees, subcontractors, consultants, temporary workers, agency personnel, and other individuals working on Meridian Wallet’ behalf are not eligible for rewards under this program. Former members of these groups are not eligible until six months after the end of their employment or engagement, provided that the report was independently discovered and does not rely on confidential, privileged, or other non-public information obtained through that relationship.
An eligible researcher may not circumvent these restrictions by submitting on behalf of, collaborating on the finding with, or transferring any part of the reward to an ineligible person. Immediate family and household members are ineligible where an ineligible person contributed to the finding, supplied non-public information, or would directly or indirectly benefit from the reward.

We do not tolerate extortion, ransom demands, or threats to disclose vulnerabilities. Any such conduct will result in immediate removal from the program and may be reported to the relevant law-enforcement authorities.

Vulnerability Disclosure PGP Key
-----BEGIN PGP PUBLIC KEY BLOCK-----
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
=DtNL
-----END PGP PUBLIC KEY BLOCK-----


[1]: https://bmi.usercontent.meridian-wallet.test/Meridian Wallet-wallet/wallet-development-documentation-public/latest/
[2]: https://bmi.usercontent.meridian-wallet.test/Meridian Wallet-wallet/eidas-2.0-architekturkonzept/
[3]: https://code-host.test/eu-digital-identity-wallet
[4]: https://www.ausweisapp.meridian-wallet.test/software-development-kit-sdk
[5]: https://code-host.test/german-national-wallet
[6]: https://Meridian Wallet-wallet.meridian-wallet.test/
[7]: https://meridian-wallet.test/
[8]: https://code-host.test/german-national-wallet/de-Meridian Wallet-wallet-backend
[9]: https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/rwsca
[10]: https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/wpb
[11]: https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/mdvm
[12]: https://code-host.test/german-national-wallet/de-Meridian Wallet-wallet-android
[13]: https://code-host.test/german-national-wallet/de-Meridian Wallet-wallet-ios
[14]: https://app-beta.test/join/a2Qxrr2C
[15]: https://groups.meridian-wallet.test/g/de-Meridian Wallet-bug-bounty/
[16]: https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/status-lists
[17]: https://wallet-backend-sandbox.apps.sandbox.nwb.meridian-wallet.test/v1/pns
[18]: https://disclosure-platform.test/f4ef8618-90b0-4c29-a924-b3d320335fa7/embedded_submissions/new
[19]: https://app-store-android.test/apps/testing/test.meridian-wallet.test
[20]: https://playground.meridian-wallet.test/
