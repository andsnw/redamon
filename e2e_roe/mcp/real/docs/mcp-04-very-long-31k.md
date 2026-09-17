Lumiphone’s commitment to global researcher collaboration significantly enhances product security. 
We welcome hackers worldwide to submit security vulnerability reports related to Lumiphone services. Your contributions will help enhance the security of Lumiphone's business and products. 
Lumiphone program on H1 currently accept vulnerabilities in the following areas :

**Web/App services**
For the scope of acceptance, please refer to:
🔹 Google Document (detailed domain/package name scope): https://docs.lumiphone.test/spreadsheets/d/1K2knhissfw817g_wLNQYJLGIn--j9HKHYBXsdALrD8Y/edit?usp=sharing

Notes:
In addition, if other businesses nested within a certain coefficient business are involved, they will be calculated according to their actual belonging coefficients. For example, an high level property embedded within an open platform or mid level property nested within an e-commerce platform will be calculated based on the mid level property. The specific circumstances will be clarified by OSRC.

**Web Application Scoring Rules**
We have defined four levels for mobile phone security vulnerabilities based on the degree of their impact: Critical, High, Moderate, and Low.

| Level   | Example of Vulnerability and Impact | 
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Critical| Including but not limited to: <br> 1. Directly obtain permissions to servers that host important data and processes as well as other important data, including but not limited to remote command execution, arbitrary code execution, web shell upload for acquisition of web server permissions, SQL injection allowing individuals to obtain system permissions, and buffer overflows allowing individuals to obtain system permissions. <br> 2. Serious leakages of sensitive information, including but not limited to SQL injection in core databases (relating to funding, user identity, and transaction) and interface problems which allow individuals to obtain the identity information, order information, and bank card information of large numbers of key users. <br> 3. Serious logic design flaws and process flaws, including but not limited to interface problems allowing individuals to consume the money in any bank account, log in to any Lumiphone account, and change the password of any Lumiphone account. |
| High    | Including but not limited to: <br> 1. Directly obtain permissions to servers that host general data and processes as well as other general data, including but not limited to remote command execution, arbitrary code execution, web shell upload for acquisition of web server permissions, SQL injection allowing individuals to obtain system permissions, and buffer overflows allowing individuals to obtain system permissions. <br> 2. Leakages of sensitive information, including but limited to SQL injection in non-core databases, leakage of source code packages, reversible server application encryption or storage of passwords as plain text, hard coding, and GitHub sensitive information leakage (including but not limited to the leakage of key server accounts and their passwords). <br> 3. Unauthorized access to sensitive information, including but not limited to direct access to the backend by bypassing authentication, weak backend passwords, and Server-side Request Forgery (SSRF) enabling individuals to obtain large amounts of sensitive Intranet data. <br> 4. Unauthorized manipulation of sensitive data, including but not limited to modification of important information, manipulation of orders, and modification of important configurations through an unauthorized account. <br> 5. Other vulnerabilities that affect users on a large scale, including but not limited to Stored XSS on important pages that can cause automatic spread of and allow acquisition of authentication credentials (cookies). |
| Moderate| Including but not limited to: <br> 1. Vulnerabilities that can affect users only through interaction, including but not limited to Stored XSS to general web pages and major Cross-site Request Forgery (CSRF) vulnerabilities. All vulnerability descriptions must provide the proof of the harm to other users. <br> 2. Actions with moderate destructive capabilities due to privilege escalation. This includes, but is not limited to, viewing general user information, editing/deleting comments, and changing functionality attributes that could pose actual business risks. <br> 3. Leakages of ordinary information, including but not limited to web path traversal, system path traversal, and plain-text password transmission over the HTTP when a HeyTap account is used for sign-in. <br> 4. Ordinary logic design flaws and process flaws, including but not limited to flaws in the verification code logic for important systems that cause the verification and relevant restrictions to be bypassed, leading to credential stuffing attacks. <br> 5. Unrestricted brute-force attacks on important account systems.                                                                                                                 |
| Low     | Including but not limited to: <br> 1. Vulnerabilities allowing individuals to access user identity information only in specific unpopular browser environments (for example, IE6). Such vulnerabilities include but are not limited to Reflected XSS (including Reflected DOM-based XSS) and Stored XSS in ordinary properties. <br> 2. Minor information leakages, including but not limited to leakage of path information, SVN information, PHP information, exceptions information and configuration settings, log printing and plain-text password transmission over HTTP when a non-HeyTap account is used for sign-in. <br> 3. Unauthorized access, including but not limited to client-side active defense bypass and Lumiphone URL redirection vulnerabilities. (Note that redirecting an Lumiphone URL to a normal website is not considered a vulnerability. If PoC for URL redirection shows that an Lumiphone URL can be redirected to any domain that doesn't belong to Lumiphone without any prompts displayed, then there is a vulnerability. Otherwise no vulnerability exists.) <br> 4. Vulnerabilities that are difficult to exploit but may cause security risks. Such vulnerabilities include but are not limited to Self-XSS that may cause the spread and exploitation of XSS, JSON Hijacking that has obtained sensitive information, clickjacking on input web pages containing sensitive information (a valid exploit must be provided in the vulnerability details), CSRF attacks involving unimportant sensitive information, and remote code execution through man-in-the-middle (MITM) attacks (valid PoC must be provided in the vulnerability details). <br> 5. Other vulnerabilities that can only cause slight impact. Such vulnerabilities include but are not limited to inappropriate configuration settings for system/service maintenance and operations and vulnerabilities in component-level permissions. <br> 6. Verification code message/email bombing, which means that a single IP or user keeps sending more than 50 verification code messages/emails to the same mobile number/email box within 30 minutes. (Note: Reported problems wherein the same interface is used to send one verification code message/email to an unlimited number of mobile numbers or email boxes will be ignored.) |
| NSI     | Including but not limited to: <br> 1. Bugs involving no security risks, including but not limited to product function defects, garbled pages, mixed content, directory traversal that has caused the leakage of meaningless or non-sensitive information, and application compatibility issues. <br> 2. Vulnerabilities that cannot be exploited, including but not limited to a scanner's meaningless vulnerability reports (such as a report on a low web server version), meaningless XSS (such as Self-XSS attacks), XSS that uses social engineering or phishing, POST based XSS, JSON hijacking involving no sensitive information, leaking of meaningless exception information, leaking of IP addresses or domain names in the intranet, meaningless clickjacking, HTTP request smuggling, obtaining the user's cookies by exploiting unconfigured CORS during user interaction, and brute-force attacks that cannot be further exploited. <br> 3. CSRF attacks involving no sensitive information, including but not limited to adding items to or deleting items from an online shopping cart, as well as executing actions on an online forum such as logging out of an account, giving likes, following others, publishing posts, making comments, and sending flowers. <br> 4. Traversals and leakages of non-sensitive information. Such information includes but is not limited to middleware version and non-sensitive information. <br> 5. Vulnerabilities that cannot be reproduced or other issues that cannot directly reflect any vulnerability, including but not limited to vulnerabilities that are purely a user's guesses. <br> 6. Cracking of 6-digit verification codes by distributed equipment. <br> 7. Other vulnerabilities with extremely low risks.                                                              |

**Note:** NSI = Not Security Issue (vulnerabilities that do not qualify for bounty rewards)

** Mobile App Security Vulnerabilities **
This type of security vulnerability mainly refers to those in mobile devices powered by ColorOS or realme UI. It includes security vulnerabilities in ColorOS or realme UIbuilt-ins and security vulnerabilities in Lumiphone's and realme's proprietary apps available in the App Market.

# Vulnerability Levels
| Level   | Example of Vulnerability and Impact                                                                                                                                                                                                           |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Critical| Including but not limited to: <br> 1. Remote code execution (RCE): The attacker is able to remotely execute arbitrary code with the app permissions, including but not limited to a remote memory corruption vulnerability (complete exploit information should be provided), a code execution vulnerability caused by overwriting a dynamic library, and other RCE vulnerabilities caused by logic issues. <br> 2. Remote silent installation of any app: The attacker installs any app remotely or through low-level user interaction. <br> 3. Other severe logic vulnerabilities that can be exploited remotely: including but not limited to remote account takeover, lock screen bypass, money transfer, and other attacks that severely endanger a user's account or asset. |
| High    | Including but not limited to: <br> 1. Arbitrary code execution (ACE): The attacker locally executes arbitrary code with the app permissions, including but not limited to a local memory corruption vulnerability (complete exploit information should be provided), a code execution vulnerability caused by overwriting a dynamic library, and other ACE vulnerabilities caused by logic issues. <br> 2. Sensitive information leakages: The attacker obtains sensitive information on an app or device remotely or through low-level user interaction. Such sensitive information includes login credentials, SMS messages, call history, contacts, browsing history, and other sensitive information in the private app directory. <br> 3. Privilege escalation vulnerabilities: Such vulnerabilities allow individuals to gain elevated access to an app to perform dangerous operations, including but not limited to launching any protected component of the app, enabling silent installation of any app, modifying the security and privacy settings of the app, and making silent calls or sending silent SMS messages through the app permissions. <br> 4. Other severe logic vulnerabilities: including but not limited to account takeover, lock screen bypass, money transfer, and other acts that are performed locally or through low-level user interaction and severely endanger a user's account or asset. <br> 5. Vulnerabilities able to break the site isolation restrictions of a browser, including but not limited to UXSS. |
| Moderate| Including but not limited to: <br> 1. Arbitrary code execution or silent installation by staging MITM attacks (valid PoC must be provided in the vulnerability details). <br> 2. Leakages of common information, including but not limited to the leakage of IMEI, IMSI, mobile number, and other common user information. <br> 3. Sensitive information can be obtained from the app or device through local or high interaction attacks, including login credentials, SMS messages, call logs, contacts, browsing history, and other sensitive data stored in the app's private directory. <br> 4. Remote denial of service vulnerability. |
| Low     | Including but not limited to: <br> 1. Stealing of sensitive information by staging MITM attacks (valid PoC must be provided in the vulnerability details). <br> 2. UI deception vulnerabilities that may cause actual harm. The risk level for this kind of vulnerability can be defined based on the actual harm. |
| NSI     | Including but not limited to: <br> 1. Bugs involving no security risks, including but not limited to product function defects, garbled pages, mixed content, static directory traversals, and application compatibility issues. <br> 2. Vulnerabilities of no significance, including but not limited to a scanner's meaningless vulnerability reports (such as an automatic app analysis report on code decompilation and lack of security reinforcement). <br> 3. Vulnerabilities that result from necessary risky permissions but cannot be exploited. Such vulnerabilities include but are not limited to necessary component exposures, such as activity export. <br> 4. Vulnerabilities that cannot be reproduced or other issues that cannot directly reflect any vulnerability, including but not limited to vulnerabilities that are purely a user's guesses. <br> 5. Local denial-of-service vulnerabilities: Bugs that can only be launched locally on the phone and cause apps to crash temporarily without leading to further security issues. <br> 6. Other vulnerabilities with extremely low risks. |

## Notes:
The following explains concepts involved in, for example, mobile app security vulnerabilities that can be triggered only through actions such as inducing a user to click a link or phishing email, or to install malicious software:

- **Remote(ly)**: An online attack requires no physical contact with a user's mobile phone. Usually, the attacker uses a browser, IM software or SMS messages to launch an attack.
- **Local(ly)**: It is necessary for the attacker to induce the victim to install malicious apps on the phone, or the attacker directly uses ADB commands, NFC, Bluetooth, or any other function to launch an attack.
- **Low-level user interaction**: specific to scenarios where a security vulnerability can be triggered just by clicking on a link.
- **High-level user interaction**: specific to scenarios where a security vulnerability can be triggered after an induced user installs a malicious app, clicks a phishing email, or clicks to confirm twice or more, or after a risk prompt is displayed.

# Vulnerability Levels and Examples
# Lumiphone Mobile Devices Security Vulnerability Severity and Reward Table

| Level | Example of Vulnerability and Impact | Reward (USD) |
|-------|-----------------------------------|--------------|
| **Critical** | 1. Arbitrary code execution in the TEE;<br><br>2. Unauthorized access to TEE-protected data (only limited to fingerprints, face data, payment information, and other data that can cause property loss to the victim);<br><br>3. Remote code execution in a privileged process or the TCB or ICE;<br><br>4. Remote permanent DoS attacks (causing the attacked device to be unusable; for example, the device is damaged permanently or can resume only through re-flashing the entire OS);<br><br>5. Remote bypass of interaction requirements for installing an app package or an equivalent action;<br><br>6. Bypass of secure boot mechanism;<br><br>7. Upgrading to firmware or image not signed by Lumiphone;<br><br>8. Vulnerabilities allowing individuals to extract or infer private user information from the AI model file, such as images and sounds. | **$5,000-$11,500** |
| **High** | 1. Remote code execution in an unprivileged process;<br><br>2. Local arbitrary code execution in a privileged process, the TCB or ICE;<br><br>3. Unauthorized access to TEE-protected data;<br><br>4. Remote access to protected data (usually limited to the data that can be accessed only after a local app requests and is granted access, or that can be accessed only by a privileged process);<br><br>5. Local permanent DoS attacks (causing the attacked device to be unusable; for example, the device is damaged permanently or can resume only through re-flashing the entire OS);<br><br>6. Remote temporary DoS attacks (remote hang or reboot);<br><br>7. Remote bypass of user interaction requirements (access to functions that usually require either user initiation or user permission);<br><br>8. Local bypass of user interaction requirements for modifying security settings (such as Developer Options);<br><br>9. Bypass of the security protection mechanism that separates the app data from other apps;<br><br>10. Bypass of the security protection mechanism that separates users or user profiles from one another;<br><br>11. Local bypass of user interaction requirements for installing an app package or an equivalent action;<br><br>12. Lock screen bypass;<br><br>13. Bypass of the device protection functions (such as the "Find My Phone" function);<br><br>14. Bypass of the carrier's restrictions (such as SIM card lock);<br><br>15. Bypass of the authentication mechanism to control Lumiphone smart devices;<br><br>16. Local acquisition of private user data through the AI model. | **$2,900-$3,500** |
| **Moderate** | 1. Remote code execution in a constrained process;<br><br>2. Local code execution in an unprivileged process;<br><br>3. Bypass of the mitigation technology in a privileged process or in the TCB, ICE, or TEE;<br><br>4. Bypass of restrictions on a constrained process;<br><br>5. Bypass of restrictions on privacy password;<br><br>6. Remote access to unprotected data (usually referring to all the data that can be accessed by locally installed apps);<br><br>7. Local access to protected data (usually limited to the data that can be accessed only after a locally installed app requests and is granted access, or that can be accessed only by a privileged process);<br><br>8. Local bypass of user interaction requirements without authentication (access to functions that usually require either user initiation or user permission);<br><br>9. Plain text leakage vulnerability caused by the incorrect encryption algorithm model or incorrect implementation of the encryption algorithm;<br><br>10. Bypass of the protection function for restoring factory settings;<br><br>11. Targeted blocking of access to emergency services. | **$230-$430** |
| **Low** | 1. Local arbitrary code execution in a constrained process;<br><br>2. Bypass of the mitigation technology in an unprivileged process. | **$20-$45** |

---

**Technical Abbreviations:**
- **TEE:** Trusted Execution Environment
- **TCB:** Trusted Computing Base  
- **ICE:** In-Circuit Emulator
- **DoS:** Denial of Service


# Special Notes of Mobile Devices Scoring Rules
** Concepts Involved in Mobile Phone Security Vulnerabilities **
- Remote: The attacker exploits vulnerabilities to launch an attack without installing the app concerned or without physical contact with the victim's device, such as by browsing web pages, reading SMS or MMS messages, receiving or sending emails, downloading files, or having wireless network communications (excluding communication with a distance of less than 10 cm).
- Local: The attacker exploits vulnerabilities to launch an attack. This kind of attack needs relevant apps to be installed in the victim's system or the attacker needs physical contact with the victim's system and the communication distance must be less than 10 cm.
- Constrained process: Such a process is subject to stricter permission restrictions than a normal app process, and runs in a strictly restricted domain such as SELinux or SEAndroid.
- Normal app process: refers to an application or process running in the untrusted_app or platform_app domain of SELinux (or SEAndroid), such as a third-party application/process or built-in application/process without system-level permissions.
- Privileged process: refers to an application or process running in the system_app of SELinux (or SEAndroid), such as a process running with system-level permissions or root permissions.
- TCB: stands for Trusted Computing Base. It refers to all of a computer's protective devices, including hardware, firmware, software, and components that implement security policies. It ensures a basic protection environment and provides additional user services required by a trusted computer system, including but not limited to parts of the kernel and drivers, or user services equivalent to the kernel, such as init and vold.
- TEE: stands for Trusted Execution Environment. It co-exists with the Android system on a device. It is mainly used to provide the Android system with a running environment for security services such as trusted computing and storage.
- ICE: stands for Independent Computing Environment. It refers to a function- and service-focused set of independent computing units, firmware and simple OS, such as a baseband modem.

** Application for CVE IDs **
l Lumiphone is the world's 100th CVE Numbering Authority (CNA). We can help security researchers who report vulnerabilities in Lumiphone products apply for CVE IDs.
For CVE application, you could send an application email to security@lumiphone.test. You need to list the following points in the email:
- The name and Report ID of the vulnerability
- The influence of the vulnerability
- The type and the severity of the vulnerability
- POC
- The nickname and the email of the applicant
OSRC Team will review their vulnerability reports in line with CVE requirements. If the review finds no problem, the OSRC will help the researchers apply for CVE IDs. 

**  Repeated Vulnerability Reports **
- Similar vulnerabilities in the same system should be reported in one package. These vulnerabilities share the same risk level, but the reward will be increased appropriately. If the vulnerabilities are reported separately, only the first report will be considered valid and the subsequent reports will be considered as repeated reports.
- For similar vulnerabilities affecting multiple systems, if internal troubleshooting has already started, a protection period of 1–3 months can be defined based on the proof of relevant internal communication. Vulnerabilities reported during this protection period will be ignored.
- If several similar vulnerabilities exist in more than one parameter for the same URL, the vulnerabilities should be combined as appropriate. For similar vulnerabilities resulting from the same source, only the first one will be recorded and the remaining will be left out.
-  For similar web or app vulnerabilities in the same common component or SDK, only the first one will be recorded and the remaining will be left out.

** Zero-Day Vulnerabilities **
- We accepts zero-day (also known as 0-day) vulnerabilities found only in Lumiphone or realme products and services.

** General Vulnerability Review Principles for Third-Party Products **
- Server-side vulnerabilities: including but not limited to vulnerabilities in the components of Tomcat and Apache being used by Lumiphone or realme , OpenSSL, and third-party SDKs. For a reported vulnerability which becomes publicly known within one month following report submission, if Lumiphone or realme has already received the vulnerability from another channel, Lumiphone or realme will give a FAIL result to the vulnerability report. If Lumiphone or realme remains unaware of the vulnerability one month after it is made public and the vulnerability remains in Lumiphone's third-party products, Lumiphone will reward the first vulnerability reporter. In general, this principle applies to low- and moderate-risk vulnerabilities.
- Client-side vulnerabilities: including but not limited to Android-native vulnerabilities and common app vulnerabilities. For a reported vulnerability which becomes publicly known within three months following report submission, if Lumiphone or realme has already received the vulnerability from another channel, Lumiphone or realme will give a FAIL result to the vulnerability report. If Lumiphone remains unaware of the vulnerability three months after it is made public and the vulnerability remains in Lumiphone's and realme's third-party products, Lumiphone or realme will reward the first vulnerability reporter. In general, this principle applies to low- and moderate-risk vulnerabilities.
- For vulnerabilities resulting from the same source, in general only the first reporter will be rewarded and the vulnerabilities will be counted as one.
-  If several similar vulnerabilities exist in more than one parameter for the same URL, the vulnerabilities should be combined as appropriate. For different types of vulnerabilities in the same URL, only the reporter of the vulnerability that has the greatest impact will be rewarded.
- Vulnerability reports should be as detailed and compliant as possible. The details of a reported vulnerability, its working principle and exploits, and fix recommendations affect the scoring of the vulnerability to some extent. For a reported vulnerability, the lack of PoC, exploit information, or analysis details will directly affect the scoring.
-  Reporting threats or intelligence already published online will be given no score.
-  The review results for a vulnerability are determined based on the level of difficulty in exploitation as well as the degree and scope of its impact.
- Scanner results without proof of harm will be considered invalid.
-  If you use security testing as an excuse to exploit security intelligence to harm the interests of users, affect the normal operation of our services, publish information about vulnerabilities before they are fixed, or steal user data, you will receive no score. In addition, Lumiphone will reserve the right to take legal action.

# Test Plan
* Users can sign up for a free account through our website
* Please use your **hacker email alias** when testing (h1username@lumiphone.test)
* Lumiphone generally do not provide sample devices for testing; researchers need to purchase the devices themselves.
* We currently only accept files smaller than 20MB in the following formats: doc, docx, 7z, zip, gz, bz2, excel.
* Lumiphone and realme employees (including both regular and outsourced employees) and their immediate family members cannot participate in this reward scheme.

**Clause Interpretation**
The OSRC reserves the right to interpret all the above clauses.

**AI Submission Guidelines for AI-Assisted Vulnerability Reports**
* To standardize AI-assisted discovery behaviors, ensure the quality of vulnerabilities, and optimize the platform review process, we are pleased to release the "Submission Guidelines for AI-Assisted Vulnerability Reports," which clearly outline the submission requirements for AI-generated vulnerability reports:

* Encouragement of AI Usage: The Lumiphone Security Center actively encourages white hats to utilize AI tools to assist or automate vulnerability discovery, enhancing the efficiency of finding vulnerabilities and uncovering more potential risks.

* Strict Manual Verification: For vulnerability reports generated by AI assistance or automation, manual verification is mandatory before submission. Please ensure that you have completed the assessment and reproduction of the report's authenticity and severity, and provide detailed results of the manual verification in the report, including but not limited to:

Description of the vulnerability's impact
Detailed reproduction steps
Complete Proof of Concept (PoC)
Key steps and result screenshots
* Handling of Invalid Reports: Reports that are directly generated by AI, not manually reproduced, or do not provide valid verification result screenshots will be directly rejected by the platform, and no reasons for rejection will be provided.

# Session Layer: HTTP Headers
Researchers should add headers to requests such as:
* “X-Researcher-Research: [H1 username]”

# Lumiphone Security Disclosure Statement

Lumiphone is committed to product security and user privacy protection. Our OSRC (Lumiphone Security Response Center) Vulnerability Disclosure Program provides a secure channel for researchers to report security issues.

## Responsible Disclosure Policy

When reporting vulnerabilities:
- Allow reasonable time for investigation before public disclosure
- Do not exploit discovered vulnerabilities or access sensitive data
- Follow applicable laws and privacy regulations
- Agree to Lumiphone's Privacy Policy and these Terms & Conditions

## Terms & Conditions

- Any inadvertent access to proprietary data must be declared in your report and not used, stored, or disclosed
- Submissions grant Lumiphone a worldwide, permanent, royalty-free license to address vulnerabilities
- Do not disclose vulnerabilities to third parties without prior written consent
- Lumiphone will respond within 15 working days and provide progress updates

## Important Notice

To protect users, Lumiphone will not discuss security issues before completing full investigations.

**Report vulnerabilities at:** [https://security.lumiphone.test/en/responsibleDisclosure](https://security.lumiphone.test/en/responsibleDisclosure)

---

*By participating, you acknowledge understanding and acceptance of these policies.*

## Prohibitions
- Lumiphone and realme Lumiphoneses and condemns all hacking activities that use vulnerability testing as an excuse to exploit security vulnerabilities to harm users' interests. These activities include but are not limited to stealing user information, hacking production systems, modifying and stealing relevant system information, and maliciously spreading vulnerabilities or data. For details, see the SRC Security Test Specifications. For the above-mentioned behaviors, Lumiphone will pursue legal support and hold relevant people accountable in accordance with law.

You can check more details of devices standard on : https://security.lumiphone.test/en/noticeDetail?notice_only_key=NOTICE-1554748210814394368

Thank you for helping keep Lumiphone and our users safe!