# Charming Kitten

*Last Updated: November 28, 2024*

## 1. Basic Information

- **First Seen**: 2012
- **Source Country**: Islamic Republic of Iran
- **Threat Actor Type**: Nation-State Sponsored
- **Linked Organization**: Islamic Revolutionary Guard Corps Intelligence Organization (IRGC-IO)
- **Objectives**: Espionage, Intelligence collection

## 2. Description

Charming Kitten, also known as APT35 and APT42, is a state-sponsored cyber espionage group attributed to Iran's Islamic Revolutionary Guard Corps Intelligence Organization (IRGC-IO). Active since at least 2014, Charming Kitten focuses on intelligence collection and espionage activities against a wide range of targets, including government entities, academia, human rights activists, journalists, and organizations in sectors such as telecommunications and technology. The group is notorious for its sophisticated spear-phishing campaigns, social engineering tactics, and exploitation of known vulnerabilities to gain unauthorized access to target systems.

## 3. Aliases

| Alias                    | Organization                                                                                                      |
|--------------------------|-------------------------------------------------------------------------------------------------------------------|
| **APT42**                | Mandiant                                                                                                           |
| **APT35**                | Check Point Research, Google Threat Analysis Group                                                                 |
| **Ballistic Bobcat**     | ESET                                                                                                               |
| **CALANQUE**             | Google Threat Analysis Group                                                                                       |
| **CharmingCypress**      | Volexity                                                                                                           |
| **Charming Kitten**      | Clearsky, CERT-FA, Bitdefender                                                                                     |
| **COBALT ILLUSION**      | Secureworks                                                                                                        |
| **ITG18**                | IBM                                                                                                                |
| **Magic Hound**          | MITRE, Unit 42, Cyble                                                                                              |
| **Mint Sandstorm**       | Microsoft                                                                                                          |
| **PHOSPHORUS**           | Previously used by Microsoft, The DFIR Report, Deep Instinct, Cybereason                                           |
| **TAG-56**               | Previously used by Recorded Future                                                                                 |
| **TA453**                | Proofpoint                                                                                                         |
| **TunnelVision**         | eSentire, SentinelOne                                                                                              |
| **Yellow Garuda**        | PwC                                                                                                                |

### Sub-groups

| Sub-group Name      | By Organization                                                                               |
|---------------------|-----------------------------------------------------------------------------------------------|
| **Nemesis Kitten**  | CrowdStrike                                                                                   |
| **Storm-0270**      | Microsoft (formerly tracked as DEV-0270)                                                      |

## 4. Targeting

- **Targeted Countries**: Afghanistan, Belgium, Brazil, Canada, Egypt, France, Iran, Iraq, Israel, Jordan, Kuwait, Morocco, Pakistan, Saudi Arabia, Spain, Syria, Turkey, UAE, UK, USA, Venezuela, Yemen and Gaza.
- **Targeted Sectors**: Defense, Education, Energy, Financial, Government, Healthcare, IT, Manufacturing, NGOs, Oil and gas, Technology, Telecommunications and that are either based or have business interests in Saudi Arabia, and ClearSky, HBO, civil and human rights activists and journalists.
- **Motivation**: State-Sponsored

## 5. Tools Used
| Tool Name             | Type and Description                                                                              |
|-----------------------|---------------------------------------------------------------------------------------------------|
| **7-Zip**             | Tool, Archiving Utility used for compressing and encrypting files                                 |
| **AnvilEcho**         | Malware, Remote Access Trojan                                                                     |
| **BASICSTAR**         | Malware, Backdoor                                                                                 |
| **BlackSmith**        | Malware, Toolset used in phishing campaigns                                                       |
| **ChromeHistoryView** | Tool, Browser History Viewer used for data extraction                                             |
| **CommandCam**        | Tool, Command-line Webcam Image Grabber                                                           |
| **CWoolger**          | Malware, Credential Stealer                                                                       |
| **DistTrack**         | Malware, Wiper (associated with Shamoon)                                                          |
| **DownPaper**         | Malware, Downloader used for fetching additional payloads                                         |
| **FireMalv**          | Malware, Credential Theft and Keylogging                                                          |
| **FRP**               | Tool, Port Forwarding Utility                                                                     |
| **Ghambar**           | Malware, Backdoor                                                                                 |
| **GoProxy**           | Tool, Proxy Server Utility                                                                        |
| **Havij**             | Tool, Automated SQL Injection Application                                                         |
| **HYPERSCRAPE**       | Malware, Tool for stealing data from webmail accounts                                             |
| **Leash**             | Malware, Backdoor                                                                                 |
| **Matryoshka RAT**    | Malware, Remote Access Trojan with layered functionality                                          |
| **MediaPl**           | Malware, Media Player used as a decoy while installing malware                                    |
| **Mimikatz**          | Tool, Credential Dumping                                                                          |
| **MischiefTut**       | Malware, Likely used for educational purposes in attacks                                          |
| **MPKBot**            | Malware, Botnet Trojan                                                                            |
| **NETWoolger**        | Malware, Network Information Gathering Tool                                                       |
| **NOKNOK**            | Malware, Backdoor                                                                                 |
| **PINEFLOWER**        | Malware, Credential Harvester                                                                     |
| **PowerLess Backdoor**| Malware, PowerShell-based Backdoor                                                               |
| **POWERSTAR**         | Malware, Updated version with enhanced capabilities                                               |
| **PsList**            | Tool, Process Listing Utility                                                                     |
| **PupyRAT**           | Malware, Cross-platform Remote Access Trojan                                                      |
| **RATHOLE**           | Malware, Backdoor                                                                                 |
| **Sponsor**           | Malware, Backdoor used in recent campaigns                                                        |
| **sqlmap**            | Tool, Automated SQL Injection and Database Takeover Tool                                          |
| **TDTESS**            | Malware, Likely an acronym for a custom tool used by the group                                    |
| **WinRAR**            | Tool, Archiving Utility used for compressing and encrypting files                                 |
| **Living off the Land** | Technique, Utilizing legitimate tools for malicious purposes                                    |

Also listed at [MITRE.](https://attack.mitre.org/groups/G0059/#:~:text=discovery.%5B17%5D-,Software,-ID)

## 6. Exploited Vulnerabilities

| CVE                                            | CVSS Score      | Description                                                                           |
|------------------------------------------------|-----------------|---------------------------------------------------------------------------------------|
| [CVE-2022-47966](https://nvd.nist.gov/vuln/detail/CVE-2022-47966) | 9.8 (Critical)   | Zoho ManageEngine Multiple Products Remote Code Execution Vulnerability               |
| [CVE-2023-27350](https://nvd.nist.gov/vuln/detail/CVE-2023-27350) | 9.8 (Critical)   | PaperCut MF/NG Improper Access Control Vulnerability                                  |
| [CVE-2022-47986](https://nvd.nist.gov/vuln/detail/CVE-2022-47986) | 9.8 (Critical)   | IBM Aspera Faspex Code Execution Vulnerability                                        |
| **Log4Shell Vulnerabilities**                  |                 |                                                                                       |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | 10.0 (Critical)  | Apache Log4j2 Remote Code Execution Vulnerability (Log4Shell)                         |
| [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046) | 9.0 (Critical)   | Apache Log4j2 Deserialization of Untrusted Data Vulnerability                         |
| [CVE-2018-13379](https://nvd.nist.gov/vuln/detail/CVE-2018-13379) | 9.8 (Critical)   | Fortinet FortiOS SSL VPN Path Traversal Vulnerability                                 |
| **ProxyLogon Vulnerabilities**                 |                 |                                                                                       |
| [CVE-2021-26855](https://nvd.nist.gov/vuln/detail/CVE-2021-26855) | 9.8 (Critical)   | Microsoft Exchange Server Remote Code Execution Vulnerability                         |
| [CVE-2021-26857](https://nvd.nist.gov/vuln/detail/CVE-2021-26857) | 7.8 (High)       | Microsoft Exchange Server Remote Code Execution Vulnerability                         |
| [CVE-2021-26858](https://nvd.nist.gov/vuln/detail/CVE-2021-26858) | 7.8 (High)       | Microsoft Exchange Server Remote Code Execution Vulnerability                         |
| [CVE-2021-27065](https://nvd.nist.gov/vuln/detail/CVE-2021-27065) | 7.8 (High)       | Microsoft Exchange Server Remote Code Execution Vulnerability                         |
| **ProxyShell Vulnerabilities**                 |                 |                                                                                       |
| [CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473) | 9.1 (Critical)   | Microsoft Exchange Server Remote Code Execution Vulnerability                         |
| [CVE-2021-34523](https://nvd.nist.gov/vuln/detail/CVE-2021-34523) | 9.8 (Critical)   | Microsoft Exchange Server Privilege Escalation Vulnerability                          |
| [CVE-2021-31207](https://nvd.nist.gov/vuln/detail/CVE-2021-31207) | 6.6 (Medium)     | Microsoft Exchange Server Security Feature Bypass Vulnerability                       |

## 7. Campaigns

| Name                       | Overview                                                                                 | References                                                 |
|----------------------------|------------------------------------------------------------------------------------------|------------------------------------------------------------|
| **Operation SpoofedScholars** | Targeting of academics and researchers with phishing campaigns.                        | [Proofpoint](#10-references)                               |
| **Operation BadBlood**     | Credential phishing campaigns targeting medical research personnel.                      | [Proofpoint](#10-references)                               |
| **Fake Interview Campaign**| Use of fake interviews to trick victims into revealing sensitive information.            | [CERT-FA](#10-references)                                  |
| **BellaCiao Campaign**     | Deployment of new malware for espionage activities.                                       | [Bitdefender](#10-references)                              |
| **Operation FoulShadow**   | Exploitation of Log4Shell vulnerabilities for initial access.                            | [Microsoft](#10-references)                                |
| **BlackSmith Campaign**    | Use of new malware toolset in phishing attacks.                                           | [Proofpoint](#10-references)                               |

## 8. TTP Matrix

Please refer to Charming Kitten's [MITRE ATT&CK TTP Matrix here.](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0059%2FG0059-enterprise-layer.json)

## 9. Patterns and Observed Behaviors

- **Activity Patterns**: Extensive use of spear-phishing and social engineering tactics, often impersonating trusted entities or individuals to lure targets.
- **Behavioral Observations**: Rapid adaptation to new vulnerabilities, such as Log4Shell and ProxyShell, for gaining initial access. Utilization of custom malware and living-off-the-land techniques to evade detection.

## 10. References

This reference list features news reporting, actionable intelligence, detailed analysis reports, and in-depth research.

### 2024

- **September 27, 2024**:
  - **FBI**: [Iranian Cyber Actors Targeting Personal Accounts to Support Operations](https://www.ic3.gov/Media/News/2024/240927.pdf) (PDF)
  - **U.S. Department of Justice**: [Three IRGC Cyber Actors Indicted for ‘Hack-and-Leak’ Operation Designed to Influence the 2024 U.S. Presidential Election](https://www.justice.gov/opa/pr/three-irgc-cyber-actors-indicted-hack-and-leak-operation-designed-influence-2024-us)
  - **U.S. Treasury**: [Treasury Sanctions Iranian Regime Agents Attempting to Interfere in U.S. Elections](https://home.treasury.gov/news/press-releases/jy2621)
  - **U.S. State Department**: [United States Sanctions Iran-Backed Malicious Cyber Actors That Have Attempted to Influence U.S. Elections](https://www.state.gov/united-states-sanctions-iran-backed-malicious-cyber-actors-that-have-attempted-to-influence-u-s-elections/)
  - **Rewards for Justice**: [IRGC Hackers](https://rewardsforjustice.net/rewards/irgc-hackers/)
- **August 28, 2024** – **Mandiant**: [I Spy With My Little Eye: Uncovering an Iranian Counterintelligence Operation](https://cloud.google.com/blog/topics/threat-intelligence/uncovering-iranian-counterintelligence-operation/) (note: weak overlap)
- **August 23, 2024** – **Meta**: [Taking Action Against Malicious Accounts in Iran](https://about.fb.com/news/2024/08/taking-action-against-malicious-accounts-in-iran/)
- **August 20, 2024** – **Proofpoint**: [Best Laid Plans: TA453 Targets Religious Figure with Fake Podcast Invite Delivering New BlackSmith Malware Toolset](https://www.proofpoint.com/us/blog/threat-insight/best-laid-plans-ta453-targets-religious-figure-fake-podcast-invite-delivering)
- **August 20, 2024** – **Recorded Future**: [GreenCharlie Infrastructure Linked to US Political Campaign Targeting](https://go.recordedfuture.com/hubfs/reports/cta-ir-2024-0820.pdf) (PDF)
- **August 19, 2024** – **CISA**: [Joint ODNI, FBI, and CISA Statement on Iranian Election Influence Efforts](https://www.cisa.gov/news-events/news/joint-odni-fbi-and-cisa-statement-iranian-election-influence-efforts) (Note: not explicitly identified)
- **August 14, 2024** – **Google Threat Analysis Group (TAG)**: [Iranian backed group steps up phishing campaigns against Israel, U.S.](https://blog.google/threat-analysis-group/iranian-backed-group-steps-up-phishing-campaigns-against-israel-us/)
- **August 14, 2024** – **Harfang Lab**: [Cyclops: a likely replacement for BellaCiao](https://harfanglab.io/insidethelab/cyclops-replacement-bellaciao/)
- **August 08, 2024** – **Microsoft Threat Analysis Center**: [Iran Targeting 2024 US Election](https://blogs.microsoft.com/on-the-issues/2024/08/08/iran-targeting-2024-us-election/)
- **May 22, 2024** – **Cyble**: [Threat Actor Profile: Magic Hound](https://cyble.com/threat-actor-profiles/magic-hound/)
- **May 10, 2024** – **New Jersey Cybersecurity & Communications Integration Cell (NJ-CCIC)**: [Recent Observed Iranian State-Sponsored Cyber Threat Group Activity](https://www.cyber.nj.gov/Home/Components/News/News/1314/214) (**ATTRIBUTION to IRGC-IO**)
- **May 01, 2024** – **Mandiant**: [Uncharmed: Untangling Iran's APT42 Operations](https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations)
- **February 13, 2024** – **Volexity**: [CharmingCypress: Innovating Persistence](https://www.volexity.com/blog/2024/02/13/charmingcypress-innovating-persistence/)
- **January 17, 2024** – **Microsoft**: [New TTPs observed in Mint Sandstorm campaign targeting high-profile individuals at universities and research orgs](https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/)

### 2023

- **November 09, 2023** – **Microsoft**: [Microsoft shares threat intelligence at CYBERWARCON 2023](https://www.microsoft.com/en-us/security/blog/2023/11/09/microsoft-shares-threat-intelligence-at-cyberwarcon-2023/#iran-role-in-the-israel-hamas-war)
- **September 11, 2023** – **ESET**: [Sponsor with batch-filed whiskers: Ballistic Bobcat’s scan and strike backdoor](https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/)
- **June 28, 2023** – **Volexity**: [Charming Kitten Updates POWERSTAR with an InterPlanetary Twist](https://www.volexity.com/blog/2023/06/28/charming-kitten-updates-powerstar-with-an-interplanetary-twist/)
- **July 06, 2023** – **Proofpoint**: [Welcome to New York: Exploring TA453's Foray into LNKs and Mac Malware](https://www.proofpoint.com/us/blog/threat-insight/welcome-new-york-exploring-ta453s-foray-lnks-and-mac-malware)
- **April 26, 2023** – **Bitdefender**: [Unpacking BellaCiao: A Closer Look at Iran’s Latest Malware](https://www.bitdefender.com/blog/businessinsights/unpacking-bellaciao-a-closer-look-at-irans-latest-malware/)
- **April 18, 2023** – **Microsoft**: [Nation-state threat actor Mint Sandstorm refines tradecraft to attack high-value targets](https://www.microsoft.com/en-us/security/blog/2023/04/18/nation-state-threat-actor-mint-sandstorm-refines-tradecraft-to-attack-high-value-targets/)
- **March 09, 2023** – **Secureworks**: [COBALT ILLUSION Masquerades as Atlantic Council Employee](https://www.secureworks.com/blog/cobalt-illusion-masquerades-as-atlantic-council-employee)

### 2022

- **December 14, 2022** – **Proofpoint**: [Would’ve, Could’ve, Should’ve…Did: TA453 Refuses to be Bound by Expectations](https://www.proofpoint.com/us/blog/threat-insight/ta453-refuses-be-bound-expectations)
- **December 12, 2022** – **SOCRadar**: [Dark Web Profile: APT42 – Iranian Cyber Espionage Group](https://socradar.io/dark-web-profile-apt42-iranian-cyber-espionage-group/)
- **November 29, 2022** – **Recorded Future**: [Suspected Iran-Nexus TAG-56 Uses UAE Forum Lure for Credential Theft Against US Think Tank](https://go.recordedfuture.com/hubfs/reports/cta-2022-1129.pdf) (PDF)
- **September 27, 2022** – **Avertium**: [An In-Depth Look at APT35 aka Charming Kitten](https://www.avertium.com/resources/threat-reports/in-depth-look-at-apt35-aka-charming-kitten)
- **September 14, 2022** – **U.S. Treasury**: [Treasury Sanctions IRGC-Affiliated Cyber Actors for Roles in Ransomware Activity](https://home.treasury.gov/news/press-releases/jy0948) (**ATTRIBUTION to IRGC**, links “Tunnel Vision” to Charming Kitten)
- **September 13, 2022** – **Proofpoint**: [Look What You Made Me Do: TA453 Uses Multi-Persona Impersonation to Capitalize on FOMO](https://www.proofpoint.com/us/blog/threat-insight/ta453-uses-multi-persona-impersonation-capitalize-fomo)
- **September 09, 2022** – **CERT-FA**: [Charming Kitten: “Can We Have A Meeting?”](https://blog.certfa.com/posts/charming-kitten-can-we-wave-a-meeting/)
- **September 07, 2022** – **Mandiant**: [APT42: Crooked Charms, Cons, and Compromises](https://www.mandiant.com/sites/default/files/2022-09/apt42-report-mandiant.pdf) (PDF)
- **September 07, 2022** – **Microsoft**: [Profiling DEV-0270: PHOSPHORUS’ ransomware operations](https://www.microsoft.com/en-us/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/)
- **August 23, 2022** – **Google Threat Analysis Group (TAG)**: [New Iranian APT data extraction tool](https://blog.google/threat-analysis-group/new-iranian-apt-data-extraction-tool/)
- **July 22, 2022** – **PwC**: [Old cat, new tricks, bad habits](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/old-cat-new-tricks.html)
- **June 01, 2022** – **Deep Instinct**: [Iranian Threat Actor Continues to Develop Mass Exploitation Tools](https://www.deepinstinct.com/blog/iranian-threat-actor-continues-to-develop-mass-exploitation-tools)
- **March 30, 2022** – **Recorded Future**: [Social Engineering Remains Key Tradecraft for Iranian APTs](https://go.recordedfuture.com/hubfs/reports/cta-2022-0330.pdf) (PDF)
- **March 21, 2022** – **The DFIR Report**: [PHOSPHORUS Automates Initial Access Using ProxyShell](https://thedfirreport.com/2022/03/21/phosphorus-automates-initial-access-using-proxyshell/)
- **March 09, 2022** – **eSentire**: [Exploitation of VMware Horizon Servers by TunnelVision Threat Actor](https://www.esentire.com/blog/exploitation-of-vmware-horizon-servers-by-tunnelvision-threat-actor)
- **February 17, 2022** – **SentinelOne**: [Log4j2 In The Wild | Iranian-Aligned Threat Actor “TunnelVision” Actively Exploiting VMware Horizon](https://www.sentinelone.com/labs/log4j2-in-the-wild-iranian-aligned-threat-actor-tunnelvision-actively-exploiting-vmware-horizon/)
- **February 01, 2022** – **Cybereason**: [PowerLess Trojan: Iranian APT Phosphorus Adds New PowerShell Backdoor for Espionage](https://www.cybereason.com/blog/research/powerless-trojan-iranian-apt-phosphorus-adds-new-powershell-backdoor-for-espionage)
- **January 11, 2022** – **Check Point Research**: [APT35 exploits Log4j vulnerability to distribute new modular PowerShell toolkit](https://research.checkpoint.com/2022/apt35-exploits-log4j-vulnerability-to-distribute-new-modular-powershell-toolkit/)

### 2021

- **November 16, 2021** – **Microsoft**: [Evolving trends in Iranian threat actor activity – MSTIC presentation at CyberWarCon 2021](https://www.microsoft.com/en-us/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021/)
- **November 15, 2021** – **The DFIR Report**: [Exchange Exploit Leads to Domain Wide Ransomware](https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/)
- **October 14, 2021** – **Google Threat Analysis Group (TAG)**: [Countering threats from Iran](https://blog.google/threat-analysis-group/countering-threats-iran/)
- **August 04, 2021** – **IBM**: [ITG18: Operational security errors continue to plague sizable Iranian threat group](https://securityintelligence.com/posts/itg18-operational-security-errors-plague-iranian-threat-group/)
- **July 13, 2021** – **Proofpoint**: [Operation SpoofedScholars: A Conversation with TA453](https://www.proofpoint.com/us/blog/threat-insight/operation-spoofedscholars-conversation-ta453)
- **March 30, 2021** – **Proofpoint**: [BadBlood: TA453 Targets US and Israeli Medical Research Personnel in Credential Phishing Campaigns](https://www.proofpoint.com/us/blog/threat-insight/badblood-ta453-targets-us-and-israeli-medical-research-personnel-credential)
- **January 08, 2021** – **CERT-FA**: [Charming Kitten’s Christmas Gift](https://blog.certfa.com/posts/charming-kitten-christmas-gift/)

### 2020

- **October 28, 2020** – **Microsoft**: [Cyberattacks target international conference attendees](https://blogs.microsoft.com/on-the-issues/2020/10/28/cyberattacks-phosphorus-t20-munich-security-conference/)
- **August 27, 2020** – **ClearSky**: [The Kittens Are Back in Town 3](https://www.clearskysec.com/the-kittens-are-back-in-town-3/) (PDF)
- **July 16, 2020** – **IBM**: [New Research Exposes Iranian Threat Group Operations](https://securityintelligence.com/posts/new-research-exposes-iranian-threat-group-operations/)
- **January 30, 2020** – **CERT-FA**: [Fake Interview: The New Activity of Charming Kitten](https://blog.certfa.com/posts/fake-interview-the-new-activity-of-charming-kitten/)

### 2019

- **October 07, 2019** – **ClearSky**: [The Kittens Are Back in Town 2 – Charming Kitten Campaign Keeps Going on, Using New Impersonation Methods](https://www.clearskysec.com/the-kittens-are-back-in-town-2/)
- **October 04, 2019** – **Microsoft**: [Recent cyberattacks require us all to be vigilant](https://blogs.microsoft.com/on-the-issues/2019/10/04/recent-cyberattacks-require-us-all-to-be-vigilant/)
- **September 15, 2019** – **ClearSky**: [The Kittens Are Back in Town Charming Kitten – Campaign Against Academic Researchers](https://www.clearskysec.com/the-kittens-are-back-in-town/)
- **March 17, 2019** – **Microsoft**: [New steps to protect customers from hacking](https://blogs.microsoft.com/on-the-issues/2019/03/27/new-steps-to-protect-customers-from-hacking/)

### 2018

- **December 13, 2018** – **CERT-FA**: [The Return of The Charming Kitten](https://blog.certfa.com/posts/the-return-of-the-charming-kitten/)

### 2017

- **December 05, 2017** – **ClearSky**: [Charming Kitten: Iranian Cyber Espionage Against Human Rights Activists, Academic Researchers and Media Outlets](https://www.clearskysec.com/charmingkitten/) (PDF)
- **February 06, 2017** – **Iran Threats**: [iKittens: Iranian Actor Resurfaces with Malware for Mac (MacDownloader)](https://iranthreats.github.io/resources/macdownloader-macos-malware/)

### 2016

- **November 11, 2016** – **Iran Threats**: [Fictitious Profiles and WebRTC’s Privacy Leaks Used to Identify Iranian Activists](https://iranthreats.github.io/resources/webrtc-deanonymization/)
- **April 27, 2016** – **Kaspersky**: [Freezer Paper around Free Meat](https://securelist.com/freezer-paper-around-free-meat/74503/)
