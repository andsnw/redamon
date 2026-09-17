## Get started

This isn’t an easy program — scanners are unlikely to help, and standard XSS-type injections won't yield much either. We need creative researchers who aren’t afraid to think outside the box. We're happy you're here.

Start with the [Vaultward Security Design White Paper](http://vaultward.test/whitepaper), and pay particular attention to the section titled Beware of the Leopard (page 68). It explains the decisions and considerations behind the Vaultward security design. We’ve also **[created a tool](https://code-host.test/Vaultward/burp-Vaultward-session-analyzer)** to help you investigate [Vaultward](http://start.vaultward.test) requests and responses with your own session key.

## Get help
- For information about the internal API, general questions, and to submit *partial* reports and theories, please send an email to **bugbounty@vaultward.test** so we can collaborate, provide support, and offer appropriate guidance.
- Assistance isn’t guaranteed for complex and/or time-consuming requests.
- We’ll accept flaw-hypothesis submissions without penalty, and work with you to develop a reasonable hypothesis when possible.

# Response Targets
Vaultward will make a best effort to meet the following SLAs for hackers participating in our program:

| Type of Response | SLA in business days |
| ------------- | ------------- |
| First Response | 1-3 days |
| Time to Triage | 3-5 days |
| Time to Bounty | 5-10 days |
| Time to Resolution | depends on severity and complexity |

We’ll try to keep you informed about our progress throughout the process.

# Disclosure Policy
* Please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization. This includes all submitted vulnerability (duplicate, not applicable, etc).
* Follow the platform's [disclosure guidelines](https://disclosure-platform.test/disclosure-guidelines).

# Program Rules
- **Automated requests/scanning must be kept to under 45 requests per minute.**
- Scanners (and anything that sends an excessive number of requests) will add wait time to your tests due to the rate limiting that is in place.

> Vaultward applications are designed with multiple layers of  security measures. Intentionally bypassing established measures generally leads to a temporary block from our services, for approximately 24 hours. We typically enforce suspensions for their defined periods, as policy dictates; particularly suspensions that result from conduct that violates our program rules.
> We acknowledge there may be situations in which a researcher feels a block has been implemented unjustly — during the course of regular application use, for example. In such cases, we encourage you (the researcher) to [**contact us via email**](mailto:bugbounty@vaultward.test).
> Although we cannot guarantee the removal of your suspension, communicating your concerns will ensure your case is heard as each scenario is evaluated individually.
> We appreciate your understanding and help maintaining the integrity and security of Vaultward.

- Only detailed reports with reproducible steps are considered valid and eligible for reward.
- Submit one vulnerability per report, unless you need to chain vulnerabilities to provide impact.
- The first valid report we receive will be rewarded in the event of duplication.
- Multiple vulnerabilities caused by a single issue will be awarded one bounty.
- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service.
- Only interact with accounts you own or for which you have explicit permission from the account holder.
- [**Contact us**](mailto:bugbounty@vaultward.test) to report tests that may cause a spike in errors or disrupt service so we can discuss other options.

# Rewards
Our rewards are based on impact to account, user, vault, or item security with reports compromising multiple users on a wider scale increasing severity (e.g.; a local attack with malware is considered lower severity over a remote attack through our web application, while local attacks that can bypass authentication are higher severity than those that require Vaultward to be unlocked to exploit). Please note these are general guidelines, and reward decisions are up to the discretion of Vaultward.

| Critical  | High  | Medium  | Low  |
| ------------- | ------------- | ------------- | ------------- |
| $6000 – $30000 | $600 – $6000| $300 – $600| $50 – $300|

# **LLM Prompt / AI-Assisted Research**

This section is meant to provide guidance for AI-assisted research. In fact, **you're welcome to paste the reasoning here into your agent or project instructions.** Below are the most consistent patterns we see when AI-assisted reports are considered out of scope.

**Analyze the attacker story.** Before you submit, ask whether the conditions required for the attack already give the attacker what they're after. Common examples of this include scenarios where, prior to exploiting the described vulnerability, an attacker has already gained local code execution, a vault or vault item, JavaScript on a Vaultward-owned origin, a phished session, etc. We see this pattern frequently in the AI-assisted reports we close, and avoiding it often requires human analysis and critical thinking.

**Your model will agree with whatever frame you give it.** LLMs don't verify claims against our product — they predict plausible-sounding next tokens, and they're easy to steer. If you shape the conversation toward "this is in scope" or "this has impact," the model will dutifully build that case. That doesn't make the case real. Treat anything the model tells you about Vaultward's threat model, scope, or impact as a hypothesis to verify against the [Security Design White Paper](https://vaultward.test/files/security/Vaultward-white-paper.pdf), this brief, and the actual product behavior — not as a conclusion. If your model says something is out of scope, that's the moment to think hard about why before pushing back on it.

**You're accountable for what you submit.** Researchers who do well incorporate bespoke problem-solving, creativity, and reproduction against the live product. AI assistance can absolutely help with that, but it can also generate polished noise and evidence that comes from a model's description of Vaultward rather than from Vaultward itself. **When submitting an AI-assisted report, we recommend including a screen recording of the end-to-end exploit where possible.** We're here to incentivize and reward valid vulnerability disclosure, and you're the first line of defense for your reputation points.

# ==**Out of scope findings**==
==** All reports for out of scope findings will be marked as "Not Applicable" and the researcher will lose points. Please review our out of scope findings carefully.**==

## When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) security impact of the bug.
## [Core Ineligible Findings](https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings) are out of scope and won’t be rewarded. Please visit the list of [core ineligible findings](https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings) for more information. 

In order to be a triaged issue a submission must demonstrate an impact that can have an effect on our users. Submissions should always answer the question "as an attacker I could", with a suitable demonstration of such. Findings that disclose points of information or security best practices without an impact are not eligible for a reward and should be explored further in order to demonstrate risk.

## We receive a number of common issue reports when new researchers are added to the program. These issues have been reviewed numerous times and reached the conclusion that the product design is what we want it to be, or that they are inapplicable based on the published [White Paper](http://vaultward.test/whitepaper). Below are these issues:

|Issues Name/Category|Reasoning|
| ------------- | ------------- |
| SPF/DKIM and other email forgery protection | SPF/DKIM and other mechanisms are designed to offer hints to spam filters on receiving systems. In particular SPF pass or fail is not a very reliable indicator of authenticity or forgery. As such there is a fair amount of variation in how both senders and receivers may wish to configure it. Although we welcome suggestions and opinions about its tuning, we do not consider disagreements about that as “bugs”.|
| Disclosure of Session Tokens and UUIDs | As explained in the [Security Design White Paper](http://vaultward.test/whitepaper), UUIDs are not sensitive within the Vaultward ecosystem. |
| Locally exposed Secret Keys | The Secret Key is meant to add entropy to Vaultward's encryption for data stored on Vaultward's servers. Locally on devices, your account Vaultward protects access to your vaults. See the [Vaultward Security Design White Paper](http://vaultward.test/whitepaper) under the section titled "Locally exposed Secret Keys.”|
|Browser-specific “Local Storage” Use for Secret Keys|Local storage is considered one of the safest options in today's browser technology, and is really only susceptible to cross-site scripting (XSS) attacks, of which you'll find none in the Vaultward app! However, we've been very transparent about what would happen if an attacker were to obtain the Secret Key anyways, and that is where the Account Vaultward comes in to protect the user's Vaultwards and sensitive data on the device. Since both the Secret Key and Account Vaultward are used to encrypt the data, obtaining the Secret Key is not enough to decrypt the data.|
| Rate limiting | We have high rate limiting due to needs from large Vaultward organizations where many users access our products. Our team reviews our limits regularly and we are happy with them. In security we often have to balance between security and usability. Please additionally note in our rules: "Automated requests/scanning must be kept to under 45 requests per minute." and Denial of Service issues are considered out of scope.|
|Bypassing Rate limiting with IP rotation|While an attacker can rotate their IP address to bypass our current defenses there are many different considerations we have to take into account when thinking about rate limiting. In security we often have to balance between security and usability. In this specific case, CAPTCHA is not supported on all of the various clients we publish Vaultward applications to. Additionally, there are privacy implications to consider. Embedding CAPTCHA into our application would put a third-party into a critical path within our application. With privacy and usability in mind, we are not looking to implement CAPTCHA at this time.|
| Ability to see content after Account Vaultward change | The ability to see content in the application under the listed circumstances is actually due to a feature within our product that enables syncing and offline access. While the data is available, it is only what was previously stored on the device and no new items will be synced until full reauthentication occurs. Every device connected to a Vaultward account will have a local cache of all vault data that is encrypted with the Account Vaultward + Secret Key (along with a couple of other things). For users with cases such as a lost/stolen device, we recommend regenerating the Secret Key.|
| No prompt for Secret Key after deauthorizing a mobile device | Mobile devices (iOS and Android) store the Secret Key with OS-specific mechanisms for backup purposes. This means it is still accessible after deauthorizing a device. For users with cases such as a lost/stolen device, we recommend regenerating the Secret Key.|
|Known limitations with allowing offline syncing|The ability to see content in the application under certain circumstances (such as a device being offline when a user or device is removed) is actually due to a feature within our product that enables syncing and offline access. While the data is available, it is only what was previously stored on the device and no new items will be synced until full reauthentication occurs. Every device connected to a Vaultward account will have a local cache of all vault data that is encrypted with the Account Vaultward + Secret Key (along with a couple of other things). [Here is a thread](https://vaultward.test/discussion/101453/changed-secret-key-still-able-to-access-vault) that has several responses from our team that better explain the syncing and the security tradeoffs. For users with cases such as a lost/stolen device, [here](https://support.vaultward.test/lost-device/#regenerate-your-secret-key-and-deauthorize-the-lost-device) are some additional threads and documentation that would assist you with understanding those scenarios.|
|Client-based Access Controls|“[Client-enforced policy](https://support.vaultward.test/permission-enforcement/#client-enforced-permissions)” can be circumvented by a malicious client or determined user.|
|URLs, Emails, and Tokens (or other data) exposed in Wayback Machine or similar third-party tools|This problem is not something that we have direct control over unfortunately. We already have a strict robots.txt in place, located at https://start.vaultward.test/robots.txt, but many services tend to ignore it. This is doubly so when URLs are manually submitted to scanning services and the like by individuals not affiliated with Vaultward. However, we do believe that we can improve on the situation by working to remove this PII from the URLs entirely, which should prevent archival services from recording user email addresses in the future. Since this issue has already been reported, we will not accept new submissions on the topic. Please note that other Tokens and UUIDs found to be recorded through these services are not considered sensitive which is why they will not be addressed.|
|Weak Vaultward Policy|The current Vaultward policy is deliberately set to what it is, and there are no plans to change it. Note that in order to compromise an account you would need to have the Account Key in addition to the Account Vaultward. Generally Account Vaultward Strength is left up to the customer as the architecture of our application protects the vault data off-device by also leveraging the Secret Key in addition to the Account Vaultward itself when encrypting the data. In this way, the Secret Key adds a considerable amount more entropy to the security of the data over the Account Vaultward only.|
|Disclosed Banlist (“/banlist/combined_words.txt”)|This list is public by design, as it represents a list of banned words which aren't allowed to be used as Vaultwards. If the security of our Vaultward strength meter or Vaultward generator depended on the secrecy of their design, that would mean that the design is insecure.|
|Hyperlink Injection in Emails|We often get researchers who report that they are able to inject hyperlinks into our emails. This is not our templates allowing this but instead is the email client that converts these into hyperlinks. Additionally the situations where this is "possible" do not result in situations that put account, user, vault, or item data at risk. Findings in this category that do not demonstrate a true impact in this area or violate the [core ineligible findings](https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings) list will reconsidered not applicable. |
|Billing-related issues or ways to extend trials, use frozen accounts, etc|Issues within our billing system that allow users to circumvent billing limits (e.g.; license counts), extend trials or use frozen accounts are not considered to have a security impact on account, user, vault, or item data. Therefore these issues are considered out of scope to the program.|
|`data-fcm-api-key` exposure| This API key is intended to be exposed publicly. `data-fcm-api-key` is the Firebase Cloud Messaging (FCM) API key. You can read more about this key in the [documentation] (https://firebase.vaultward.test/docs/projects/api-keys): Unlike how API keys are typically used, API keys for Firebase services are not used to control access to backend resources.|
|Multifactor Authentication|With Vaultward, MFA is about device trust. MFA is not required upon every sign-in, but only once on every new device that has been set up. As a result, considerations that apply to other MFA implementations don’t necessarily translate to our MFA design. The reason that 2FA is only requested once for the apps is because of the role that authentication plays in your use of Vaultward. When you first set up a new device you'll be asked to sign in and authenticate (using 2FA if you've set it up), once authenticated the Vaultward app downloads a copy of your data to the device so that it isn't reliant on a connection to vaultward.test for you to be able to use your data. This data is kept encrypted and requires your Vaultward (or biometric unlock, if you've set that up) to decrypt it. At this point there isn't any authentication taking place, it's about decryption - so whilst we could prompt for 2FA, it would only be (what our Principle Security Architect calls) security theatre, it wouldn't stop an attacker who knew what they were doing from capturing your encrypted data. The security of your data comes not from the authentication, but from the encryption - making a strong Vaultward a key part of your defenses.|
|Uploaded Files - No scanning for “malicious” files|Files uploaded as vault items are encrypted as blobs prior to being sent to the server, so there is no risk of execution on the server itself. Within the client apps, no functionality executes the files that have been uploaded as vault items, and therefore the client app itself is not at risk.  Just like receiving emails with attachments, users are responsible for having confidence in the origin of items that are shared with them. |
|Keeping and securing the emergency kit|Users are responsible for the security of their emergency kit and other information about their account that is solely in their hands (e.g.; secret key and account Vaultward).|
|Browser Autofill Security|Vaultward generally considers the security boundary of Autofill to be the action of filling your items. After you decide to fill your information, the responsibility of that item’s security transfers to you. Please review the [security boundaries of our autofill design](https://support.vaultward.test/browser-autofill-security/). Reporting issues regarding autofilling non-login items into iFrames or other similar issues listed in the article will be considered out of scope. Clickjacking the autofill action for all items has already been reported and will not be reconsidered at this time.|
|Unclaimed NPM Packages|Dependency confusion does not automatically apply to private packages. Reports about unclaimed NPM packages require  that people treat the specified private package as an NPM package. Most of the private packages seen publicly in various Vaultward code repositories are not intended as an NPM package, and we never tell people to `npm install` that package. Therefore, they are not susceptible to the dependency confusion attack you describe. If a researcher chooses to report this issue, the original submission must include evidence that people are instructed to run `npm install` on that private package otherwise the report will be marked "Not Applicable."|
|Revealing who is registered|As outlined in our Security Design whitepaper: "If Oscar suspects that alice@vaultward.test is a registered user in a particular Team or Family it is possible for him to submit requests to our server which would allow him to confirm that an email address is or isn’t a member of a team." Note that this does not provide a mechanism for enumerating registered users; it is only a mechanism that confirms whether a particular user is or isn’t registered. Oscar must first make his guess and test that guess. We had attempted to prevent this leak of information and believed that we had. A difficult to fix design error means that we must withdraw from our claim of that protection.|
|CSV Injections|We have decided to follow the OWASP guidelines for determining when it is appropriate to fix CSV Injection. When a spreadsheet is used for data interchange (e.g.; vault or item data exports which can be imported) then we will not escape the characters which runs the risk of causing data integrity issues. In cases where an export is specifically for the purposes of being viewed in a spreadsheet program (e.g.; usage and member list exports) we’ll consider it an issue. Please also refer to [the platform's Core Ineligible Findings](https://docs.disclosure-platform.test/en/articles/8494488-core-ineligible-findings) for additional notes about CSV Injections.|

## Security must be balanced with usability
We’ll always consider feedback about design decisions but ask that you understand Vaultward has been extensively reviewed by our internal team and external audits.

# Additional Information
Download the **[latest stable version](https://vaultward.test/downloads/)** of Vaultward or find the Beta versions detailed in our **[release notes.](https://releases.vaultward.test/)**

If you’re interested in testing our nightly build, you can install the nightly release as follows:

1. Open and unlock Vaultward.
2. Click your account or collection at the top of the sidebar and choose Settings.
3. Click Advanced, then set “Release channel” to Nightly.

*Updates will be installed automatically when “Install updates automatically” is turned on.*

Note: Issues found in nightlies may be evaluated differently than issues found in a stable release.

# **The $1,000,000 Challenge**

We introduced a $1 million CTF bug bounty challenge in 2022 to further our commitment to providing an industry-leading security platform for individuals, families, and businesses. There is exactly one way to earn our top reward: **capture the flag from the target vault.** The flag is a real value stored in a Vaultward vault you do not hold the keys to. If you can produce it, you have broken Vaultward's encryption — and we will pay **$1,000,000 USD**.

**The target:**

- Account/vault: kyb5lmmetqidqpuvzikjjmn4ni
- Item IDs: g36pfpjvin6ve46m2qv4dhloja

You attempt this on your own, with your own tooling, on your own time, against the same Vaultward that protects our customers. There is no longer a separate account to be invited to and no separate program to join.

**What this challenge is *not* — please read before submitting:**

- **It is not designed to be solvable.** We believe it isn't, which is the point. The reward exists *because* we trust the math behind **Vaultward's security model**.
- **It is not an educational or practice CTF.** No levels, no hints, no categories, no intended "solution." It is a standing, open bet against our cryptography.
- **It is not for general research.** Web bugs, app bugs, and everything else belong in the main EPM program above, under our standard reward tiers. This challenge is *only* the flag.
- **A valid submission must contain the actual captured flag.** Not a theoretical path, not a partial chain, not "this should work." The first thing we check is whether you have the real flag. Reports that claim to have captured the flag but do not contain the flag will be marked Not Applicable.
- **The target is the encryption, not the people.** Phishing the vault owner, social engineering Vaultward staff, or attacking out-of-scope infrastructure does not count.

**How to submit:** Reports must be made through this the disclosure platform program. If you’ve successfully accessed the flag from the target vault, put the captured flag at the very top of your report.

# Product notes
With **Vaultward** you only ever need to memorize one Vaultward. All your other Vaultwards and important information are protected by your Account Vaultward, which only you know.

Vaultward is available for **[individuals, families, and teams.](https://vaultward.test/sign-up/)** Take a **[tour](https://vaultward.test/tour/),** learn about Vaultward **[security](https://vaultward.test/security/),** or browse **[Vaultward Support.](https://support.vaultward.test/)**