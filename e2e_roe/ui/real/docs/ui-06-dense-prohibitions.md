At VF Corporation, we take security and privacy very seriously. If you believe that you have found a security vulnerability that affects any VF Corporation asset, please report it to us. You may report a vulnerability using the disclosure platform. Reports that fall within scope of this VF Corporation Vulnerability Disclosure Program Policy (the “Policy”) may be eligible to receive a +1 count on their public profile under “Thanks Received” and be listed on VF Corporation’s the disclosure platform webpage under “Hackers Thanked.” We appreciate your efforts in helping protect customer trust and make VF Corporation more secure.

#**What is the VF Corporation Reporting Disclosure Program?**

 - This Policy describes the VF Corporation Vulnerability Disclosure Program, an initiative driven and managed by VF’s Information Security, Privacy and Legal teams to incentivize the responsible, ethical disclosure of vulnerabilities relating to VF information and technology systems.


 - The VF Corporation Vulnerability Disclosure Program accepts reports of bugs that provide a potential attacker with the ability to compromise the integrity, availability or confidentiality of VF Corporation services or information technology infrastructure. Please see below for specific submission criteria. If you believe you've found a qualifying security vulnerability in a VF Corporation web site, please submit a report in accordance with the guidelines below that includes a detailed description of your discovery with clear, concise, reproducible steps or a working proof-of-concept. 


 - When investigating vulnerabilities, avoid altering existing files, file permissions, reading sensitive information (e.g., /etc/shadow) or disrupting services. Do not utilize an identified vulnerability to pivot to other hosts or services. If sensitive information or personal information is encountered, immediately cease activities and report via the disclosure platform portal, where triage and VF Corporation personnel can assist.

#**Who Can Participate in the Program?**

 - Security researchers authorized by the disclosure platform who discover a potential security finding within VF assets using ethical and lawful means are encouraged to report it via the Program, unless the circumstances described under the caption “Ineligible Participants” below apply. VF employees and contractors, as well as their immediate family members, are not eligible to participate in the Program, and should disclose any findings directly to VF Global Cyber and Information Security (GCIS). 


 - We value the positive impact of your work and thank you in advance for your contribution.

#**Assets In Scope:**

The following wildcards are in scope of the program:

- *.northline-apparel.test
- *.northline-apparel.test
- *.northline-apparel.test
- *.northline-apparel.test
- *.northline-apparel.test


#**Assets Out of Scope:**
 - Anything not listed in the Assets In Scope section above. 
 - Any asset listed as out of scope in the Hacker One platform.
 - If you have any question about what is in scope, please ask.

#**Qualifying Vulnerabilities:**

The VF Corporation Security Team is interested in the following types of vulnerabilities:

 - Cross-Site Scripting (XSS) With Meaningful Impact
 - Cross-Site Request Forgery (CSRF) With Meaningful Impact
 - Remote Code Execution (RCE)
 - Unauthorized Cross-Tenant Data Tampering or Access (for multi-tenant services)
 - Authentication/Authorization Bypass (Broken Access Control)	
 - Privilege Escalation	
 - Insecure Direct Object References
 - Injection Vulnerabilities
 - Cache Poisoning
 - Server-Side Request Forgery
 - Authentication Vulnerabilities
 - Server-Side Code Execution
 - Significant Security Misconfiguration (when not caused by user)
 - Subdomain Takeover
 - Directory Traversal 
 - Remote and Local File Inclusion
 - Information Disclosure

VF Corporation reserves the right to reject any submission, in our sole discretion. Submissions that require manipulation of data, network access, or physical attack against VF Corporate offices or data centers and/or social engineering of our service desk, employees or contractors will not be accepted. 

#**Non-Qualifying Vulnerabilities**

The following submissions are not accepted by VF Global Cyber and Information Security for the purposes of the Program:

 - Security Best Practices i.e. Security Headers etc.
 - Social Engineering, Phishing
 - Open redirects (unless you can demonstrate additional security impact)
 - Physical Attacks
 - Missing Cookie Flags
 - CSRF with minimal impact i.e. Login CSRF, Logout CSRF, etc.
 - Content Spoofing
 - Stack Traces, Path Disclosure, Directory Listings
 - SSL/TLS best practices
 - Banner Grabbing
 - CSV Injection with no demonstrable security impact
 - Reflected File Download
 - Reports on Out of dated browsers
 - DOS/DDOS
 - Host header Injection with no demonstrable security impact
 - Scanner Outputs
 - Vulnerabilities on Third-Party Products
 - User Enumeration
 - Password Complexity
 - Non Impactful HTTP Methods

#**Limitations**

You are not authorized to test any asset, domain, or IP address listed as outside the scope of the Program. 

 - Reports of security findings outside the scope of this Program will be ineligible for reputation increase within the program.


- Zero-day vulnerabilities (vulnerabilities that were not previously known to the security community) are not eligible for reputation increase unless you identify a zero-day vulnerability on an in-scope system more than five days after the zero-day vulnerability was disclosed to the security community.


 - Vulnerabilities that are already known and being tracked by our internal team at the time of your report will not be eligible for reputation increase.


 - VF operates many brands and businesses, and our systems have many similarities across our platforms. A vulnerability that exists on one of our platforms/systems might exist on other VF platforms/systems. We consider findings such as these to be a single finding, eligible for a single reputation increase. (An example of this would be a vulnerability that exists on www.northline-apparel.test/path/testapi that also exists on www.northline-apparel.test/path/testapi. Reporting a vulnerability for one of these URLs would make the same finding for the other URL ineligible for award.)


- You may not violate any law in connection with this Program.

#**Rules of Engagement**

- You must provide details of the vulnerability finding, including information needed to reproduce and validate the report.


- Do not attempt to conduct post-exploitation, including modification or destruction of data, or interruption or degradation of VF services.


- Do not attempt to perform brute-force attacks, denial-of-service attacks, compromise or testing of existing accounts that you did not create.


- Do not attempt to access personal information/data. If personal information/data is inadvertently accessed, then for the purposes of reporting, remove or obscure personal information/data in screenshots in a manner which cannot be reversed, and do not retain, save, copy, transfer, or otherwise use any personal information/data. Immediately disclose the access of personal information/data to us. You may be asked to sign a statement, under oath, affirming that you have not accessed any personal information/data and/or that you have not retained, saved, copied, transferred, or otherwise used any personal information/data.


- Do not knowingly modify persistent data stores through authenticated access or risky application exploitation.


- Do not attempt to target VF employees, customers, or consumers, including by any social engineering attack, phishing attack or physical attack.


- Do not perform physical attacks against any VF facility.


- Do not threaten or try to extort VF. You must not make ransom requests or otherwise act in bad faith. You should simply report the vulnerability to us. Actions taken in bad faith, including any ransom demand, will be reported to law enforcement authorities.


- Do not save, copy, transfer, or otherwise use any VF data beyond the minimum required to meet the requirements of the Program. Continuing to access VF data or any third-party data, including but not limited to personal information, may be considered actions taken in bad faith.


- You may use only assets that you explicitly own or have properly and lawfully licensed.


- If reports of the same finding are received from multiple authorized the disclosure platform participants, only the first to report will be eligible for reputation increase.


- Do not share publicly or privately any details or descriptions of your findings with any third party.

#**Testing**

When testing, you must identify your testing traffic such that it can be differentiated from normal business operations and malicious actors. Please do the following when participating in the Program:

- Where possible, register accounts using your <username>+x@northline-apparel.test addresses. (see https://docs.disclosure-platform.test/en/articles/8404308-hacker-email-alias)


- Provide your IP address in the bug report. We will keep this data private and only use it to review logs related to your testing activity. We ask for this data to assist our Incident Response team with noise reduction when conducting an investigation.


- Include a custom HTTP User-Agent in all your traffic. Burp and other proxies allow the easy automatic modification of headers to all outbound requests:

       - Example (VFC-VDP): `Mozilla/5.0 (X11; VFC-VDP; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/198.51.100.0/24 Safari/537.36`

- Consider a custom HTTP header, if modifying the User Agent is not feasible. Report to us what header you set so we can identify it easily:

    - Identifier: Your Username

    - Format: X-VFC-VDP: Researcher-<username>

    - Example: X-VFC-VDP: Researcher-vfjohn

- Limit scanning and testing to a maximum of five requests per second, per host.

#**Additional Program Policies**

 - Please provide detailed reports with reproducible steps. If the report is not detailed enough to reproduce the issue, the issue may not be marked as triaged, and we will request additional information.


- Submit one vulnerability per report unless you need to chain vulnerabilities to provide impact.


- When duplicates occur, we only triage the first report received (provided that it can be fully reproduced).


- Multiple vulnerabilities caused by one underlying issue will be treated as one valid report.

#**Legal Safe Harbor**

- VF Corporation will not bring any legal action against anyone for complying with this Policy in good faith. This includes any claim under the Digital Millennium Copyright Act (DMCA) for circumventing technological measures to protect the services and applications eligible under this policy. As long as you comply with this policy, we consider your security research to be "authorized" under the Computer Fraud and Abuse Act. These terms do not provide you with authorization to access company data or another person's personal information/data or account. We waive any restrictions in our applicable Terms of Service and Acceptable Use Policy that would prohibit your participation in the Program, for the limited purpose of your security research under this Policy.


- VF cannot authorize any activity on third-party products or guarantee that other persons or entities will not pursue legal action against you. VF is not responsible for your liability from actions performed on third parties.


- Do not do anything illegal or unethical. You are responsible for complying with all applicable laws, restrictions, regulations, etc.

#**Ineligible Participants** 

You may not participate in the Program, and we will not award reputation, if any of the following apply:

- You are on the US Treasury Department's Specially Designated Nationals and Blocked Persons List.


- You are a citizen or a resident of a nation subject to international sanctions or embargoes which prohibit us from making a payment, such as the US Office of Foreign Asset Controls list of sanctions programs.


- You are a sanctioned party in the European Union according to an applicable act in the context of the EU Common Foreign and Security Policy and Cyber Diplomacy Toolbox, including, without limitation, Council Decision (CFSP) 2019/797, as subsequently modified by Council Decision (CFSP) 2020/1127.


- Any Anti-Money Laundering Law (AML) prohibits us from making an award, such as FINCEN regulations or the EU 6AMLD.


- You are associated with any person or entity on the Unreliable Entity List maintained by China's Ministry of Commerce. 


- Any public policy of a competent jurisdiction prohibits or discourages us from making an award.


- You are associated with any organized crime enterprise.


- Any applicable law prohibits us from making an award.
