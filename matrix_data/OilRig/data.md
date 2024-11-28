# OilRig

*Last Updated: November 28, 2024*

## 1. Basic Information

- **First Seen**: 2014
- **Source Country**: Islamic Republic of Iran
- **Threat Actor Type**: Nation-State Sponsored
- **Linked Organization**: Ministry of Intelligence and Security (MOIS)
- **Objectives**: Espionage, Sabotage, Information Theft

## 2. Description

OilRig, also known as APT34, is a cyber espionage group attributed to Iran's Ministry of Intelligence and Security (MOIS). Active since at least 2014, OilRig primarily targets organizations in the Middle East, focusing on sectors such as government, energy, financial services, and telecommunications. The group's operations are characterized by sophisticated phishing campaigns, exploitation of known vulnerabilities, and the development of custom malware tools to achieve their objectives of espionage and sabotage.

## 3. Aliases

| Alias               | Organization                                                                                               |
|---------------------|------------------------------------------------------------------------------------------------------------|
| **APT34**           | Check Point Research, FireEye, Intezer, NSA, NSFOCUS, Trend Micro                                          |
| **CHRYSENE**        | Dragos                                                                                                     |
| **Cobalt Gypsy**    | Secureworks                                                                                                |
| **Cobalt Lyceum**   | Secureworks                                                                                                |
| **Crambus**         | Symantec                                                                                                   |
| **Earth Simnavaz**  | Trend Micro                                                                                                |
| **Hazel Sandstorm** | Microsoft                                                                                                  |
| **Helix Kitten**    | CrowdStrike, Wikipedia                                                                                     |
| **HEXANE**          | Dragos (linked to Lyceum by Kaspersky)                                                                     |
| **ITG13**           | IBM                                                                                                        |
| **Lyceum**          | Kaspersky, Secureworks                                                                                     |
| **OilRig**          | ClearSky, Cyble, ESET, Kaspersky, Malpedia, MITRE, Unit 42                                                 |
| **TA452**           | Proofpoint                                                                                                 |
| **Yellow Maero**    | PwC                                                                                                        |
| **Europium**        | previously used by Microsoft                                                                               |
| **Greenbug**        | ClearSky, Symantec                                                                                         |
| **TG-2889**         | formerly used by Secureworks                                                                               |

### Sub-groups

| Sub-group Name (By Microsoft)      | Aliases                                                                             |
|------------------------------------|-------------------------------------------------------------------------------------|
| **DEV-0842**                       | Void Manticore (Check Point Research)                                               |
| **DEV-0861**                       | Scarred Manticore (Check Point Research) / UNC1860 (Mandiant)                       |
| **DEV-0166**                       | IntrudingDivisor (Unit 42)                                                          |
| **DEV-0133**                       | None                                                                                |

## 4. Targeting

- **Targeted Countries**: Albania, Azerbaijan, Bahrain, China, Egypt, Iraq, Israel, Jordan, Kuwait, Lebanon, Mauritius, Oman, Pakistan, Qatar, Saudi Arabia, Turkey, UAE, UK, USA.
- **Targeted Sectors**: Aviation, Chemical, Defense, Education, Energy, Financial, Government, High-Tech, IT, Hospitality, Oil and gas, Telecommunications.
- **Motivation**: State-Sponsored

## 5. Tools Used
| Tool Name           | Type                                                                                     |
|---------------------|------------------------------------------------------------------------------------------|
| **Alma Communicator**     | Malware, DNS Tunneling Trojan                                                      |
| **BONDUPDATER**           | Malware, Backdoor                                                                  |
| **certutil**              | Tool, Living off the Land, File Downloading                                        |
| **Clayslide**             | Malware, Exploit Delivery                                                          |
| **DistTrack**             | Malware, Wiper (Associated with Shamoon)                                           |
| **DNSExfiltrator**        | Tool, Data Exfiltration via DNS                                                    |
| **DNSpionage**            | Malware, DNS Tunneling, Backdoor                                                   |
| **Dustman**               | Malware, Wiper                                                                     |
| **Fox Panel**             | Tool, Command and Control Framework                                                |
| **GoogleDrive RAT**       | Malware, Remote Access Trojan                                                      |
| **Helminth**              | Malware, Backdoor                                                                  |
| **ISMAgent**              | Malware, Remote Access Trojan                                                      |
| **ISMDoor**               | Malware, Backdoor                                                                  |
| **ISMInjector**           | Malware, Injector                                                                  |
| **Jason**                 | Malware, Backdoor                                                                  |
| **Karkoff**               | Malware, Data Exfiltration Tool                                                    |
| **LaZagne**               | Tool, Credential Stealer                                                           |
| **LIONTAIL**              | Malware, Backdoor                                                                  |
| **LONGWATCH**             | Malware, Keylogger                                                                 |
| **Mimikatz**              | Tool, Credential Dumping                                                           |
| **MrPerfectInstaller**    | Malware, Installer for Payloads                                                    |
| **Nautilus**              | Malware, Backdoor                                                                  |
| **Neuron**                | Malware, Remote Access Trojan                                                      |
| **OopsIE**                | Malware, Backdoor                                                                  |
| **PICKPOCKET**            | Malware, Credential Stealer                                                        |
| **Plink**                 | Tool, SSH Tunneling                                                                |
| **POWBAT**                | Malware, PowerShell Backdoor                                                       |
| **PowerExchange**         | Malware, Backdoor                                                                  |
| **POWRUNER**              | Malware, PowerShell-based Backdoor                                                 |
| **PsList**                | Tool, System Reconnaissance                                                        |
| **QUADAGENT**             | Malware, Backdoor                                                                  |
| **RDAT**                  | Malware, Backdoor                                                                  |
| **RGDoor**                | Malware, IIS Backdoor                                                              |
| **Saitama**               | Malware, Backdoor                                                                  |
| **SideTwist**             | Malware, Backdoor                                                                  |
| **SpyNote RAT**           | Malware, Android Remote Access Trojan                                              |
| **StoneDrill**            | Malware, Wiper                                                                     |
| **ThreeDollars**          | Malware, Downloader                                                                |
| **TONEDEAF**              | Malware, Backdoor                                                                  |
| **TONEDEAF 2.0**          | Malware, Updated Backdoor                                                          |
| **TwoFace**               | Malware, Webshell                                                                  |
| **VALUEVAULT**            | Malware, Credential Stealer                                                        |
| **Webmask**               | Malware, Webshell                                                                  |
| **WinRAR**                | Tool, Archiving Utility                                                            |
| **ZeroCleare**            | Malware, Wiper                                                                     |
| **Living off the Land**   | Technique, Utilizing Legitimate Tools for Malicious Purposes                       |

Also listed at [MITRE.](https://attack.mitre.org/groups/G0049/#:~:text=machines.%5B24%5D-,Software,-ID)

## 6. Exploited Vulnerabilities

| CVE                                        | CVSS Score      | Description                                                           |
|--------------------------------------------|-----------------|-----------------------------------------------------------------------|
| [CVE-2024-30088](https://nvd.nist.gov/vuln/detail/CVE-2024-30088) | 7.0 (High)       | Windows Kernel Elevation of Privilege Vulnerability                   |
| [CVE-2019-0604](https://nvd.nist.gov/vuln/detail/CVE-2019-0604)   | 9.8 (Critical)   | Microsoft SharePoint Remote Code Execution Vulnerability              |
| [CVE-2017-11882](https://nvd.nist.gov/vuln/detail/CVE-2017-11882) | 7.8 (High)       | Microsoft Office Memory Corruption Vulnerability                      |
| [CVE-2017-0199](https://nvd.nist.gov/vuln/detail/CVE-2017-0199)   | 7.8 (High)       | Microsoft Office and WordPad Remote Code Execution Vulnerability      |

## 7. Campaigns

| Name                      | Overview                                                                                         | References                                                 |
|---------------------------|--------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| **Earth Simnavaz**        | Advanced cyberattacks against UAE and Gulf regions by deploying new malware variants.            | [Trend Micro](#10-references)                              |
| **UNC1860**               | Hidden operations in Middle Eastern networks linked to Iranian threat actors.                    | [Mandiant](#10-references)                                 |
| **Void Manticore**        | Destructive activities targeting Israel's infrastructure and organizations.                      | [Check Point Research](#10-references)                     |
| **Scarred Manticore**     | Targeted attacks against Middle Eastern government infrastructure.                               | [Check Point Research](#10-references)                     |
| **DNSpionage**            | Campaign using DNS tunneling for C2 communications, targeting the Middle East.                   | [Cisco Talos](#10-references)                              |
| **Operation Saitama**     | Phishing attacks targeting the Jordanian government with new backdoor malware.                   | [Malwarebytes](#10-references)                             |
| **Lyceum Campaign**       | Targeting Middle Eastern organizations with new malware and updated toolsets.                    | [Kaspersky](#10-references)                                |

## 8. TTP Matrix

- Please refer to OilRig's [MITRE ATT&CK TTP Matrix here.](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0049%2FG0049-enterprise-layer.json)
- Industrial Control System (ICS) TTPs mapped to [MITRE.](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0049%2FG0049-ics-layer.json)

## 9. Patterns and Observed Behaviors

- **Activity Patterns**: Use of spear-phishing emails with malicious attachments exploiting known vulnerabilities in Microsoft Office and SharePoint.
- **Behavioral Observations**: Leveraging DNS tunneling and custom backdoors for stealthy command and control communications. Development of custom malware and frequent updates to toolsets to avoid detection.

## 10. References

This reference list features news reporting, actionable intelligence, detailed analysis reports, and in-depth research.


### 2024

- **October 11, 2024** – **Trend Micro**: [Earth Simnavaz (aka APT34) Levies Advanced Cyberattacks Against UAE and Gulf Regions](https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks-uae-gulf-regions.html)
- **September 19, 2024** – **Mandiant**: [UNC1860 and the Temple of Oats: Iran's Hidden Hand in Middle Eastern Networks](https://cloud.google.com/blog/topics/threat-intelligence/unc1860-iran-middle-eastern-networks/)
- **September 11, 2024** – **Check Point Research**: [Targeted Iranian Attacks Against Iraqi Government Infrastructure](https://research.checkpoint.com/2024/iranian-malware-attacks-iraqi-government/)
- **May 20, 2024** – **Check Point Research**: [Bad Karma, No Justice: Void Manticore Destructive Activities in Israel](https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/)

### 2023

- **December 20, 2023** – **Security Scorecard**: [A detailed analysis of the Menorah malware used by APT34](https://securityscorecard.com/research/a-detailed-analysis-of-the-menorah-malware-used-by-apt34/)
- **December 14, 2023** – **ESET**: [OilRig’s persistent attacks using cloud service-powered downloaders](https://www.welivesecurity.com/en/eset-research/oilrig-persistent-attacks-cloud-service-powered-downloaders/)
- **October 31, 2023** – **Check Point Research**: [From Albania to the Middle East: The Scarred Manticore is Listening](https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/) (AFFILIATED WITH MOIS)
- **October 19, 2023** – **Symantec**: [Crambus: New Campaign Targets Middle Eastern Government](https://symantec-enterprise-blogs.security.com/threat-intelligence/crambus-middle-east-government)
- **September 29, 2023** – **Trend Micro**: [APT34 Deploys Phishing Attack With New Malware](https://www.trendmicro.com/en_us/research/23/i/apt34-deploys-phishing-attack-with-new-malware.html)
- **September 21, 2023** – **ESET**: [OilRig’s Outer Space and Juicy Mix: Same ol’ rig, new drill pipes](https://www.welivesecurity.com/en/eset-research/oilrigs-outer-space-juicy-mix-same-ol-rig-new-drill-pipes/)
- **August 30, 2023** – **NSFOCUS**: [APT34 Unleashes New Wave of Phishing Attack with Variant of SideTwist Trojan](https://nsfocusglobal.com/apt34-unleashes-new-wave-of-phishing-attack-with-variant-of-sidetwist-trojan/)
- **May 09, 2023** – **ESET**: [ESET APT Activity Report Q4 2022–Q1 2023](https://www.welivesecurity.com/2023/05/09/eset-apt-activity-report-q42022-q12023/), specifically on page 8 in [PDF](https://web-assets.esetstatic.com/wls/2023/05/eset_apt_activity_report_q42022_q12023.pdf)
- **May 08, 2023** – **Kaspersky**: [Kaspersky experts warn of increased IT supply chain attacks by OilRig APT in the Middle East and Turkiye](https://me-en.kaspersky.com/about/press-releases/kaspersky-experts-warn-of-increased-it-supply-chain-attacks-by-oilrig-apt-in-the-middle-east-and-turkiye)
- **February 02, 2023** – **Trend Micro**: [New APT34 Malware Targets The Middle East](https://www.trendmicro.com/en_us/research/23/b/new-apt34-malware-targets-the-middle-east.html)

### 2022

- **September 08, 2022** – **Microsoft**: [Microsoft investigates Iranian attacks against the Albanian government](https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/) (ATTRIBUTION TO MOIS)
- **May 10, 2022** – **Malwarebytes**: [APT34 targets Jordan Government using new Saitama backdoor](https://www.threatdown.com/blog/apt34-targets-jordan-government-using-new-saitama-backdoor/)

### 2021

- **October 18, 2021** – **Kaspersky**: [Lyceum group reborn](https://securelist.com/lyceum-group-reborn/104586/)
- **April 08, 2021** – **Check Point Research**: [Iran’s APT34 Returns with an Updated Arsenal](https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/)

### 2020

- **July 22, 2020** – **Unit 42**: [OilRig Targets Middle Eastern Telecommunications Organization and Adds Novel C2 Channel with Steganography to Its Inventory](https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/)
- **May 19, 2020** – **Symantec**: [Sophisticated Espionage Group Turns Attention to Telecom Providers in South Asia](https://symantec-enterprise-blogs.security.com/threat-intelligence/greenbug-espionage-telco-south-asia)
- **March 02, 2020** – **Telsy**: [APT34 (aka OilRig, aka Helix Kitten) attacks Lebanon government entities with MailDropper implants](https://www.telsy.com/en/apt34-aka-oilrig-attacks-lebanon-government-entities-with-maildropper-implant/)
- **January 30, 2020** – **Intezer**: [New Iranian Campaign Tailored to US Companies Utilizes an Updated Toolset](https://intezer.com/blog/research/new-iranian-campaign-tailored-to-us-companies-uses-updated-toolset/)

### 2019

- **December 17, 2019** – **Kaspersky**: [OilRig’s Poison Frog – old samples, same trick](https://securelist.com/oilrigs-poison-frog/95490/)
- **December 04, 2019** – **IBM**: [New Destructive Wiper ZeroCleare Targets Energy Sector in the Middle East](https://securityintelligence.com/posts/new-destructive-wiper-zerocleare-targets-energy-sector-in-the-middle-east/)
- **November 09, 2019** – **NSFOCUS**: [APT34 Event Analysis Report](https://nsfocusglobal.com/apt34-event-analysis-report/)
- **October 21, 2019** – **National Security Agency**: [Turla Group Exploits Iranian APT To Expand Coverage Of Victims](https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_TURLA_20191021%20VER%203%20-%20COPY.PDF) (PDF)
- **August 27, 2019** – **Secureworks**: [LYCEUM Takes Center Stage in Middle East Campaign](https://www.secureworks.com/blog/lyceum-takes-center-stage-in-middle-east-campaign)
- **July 18, 2019** – **FireEye**: [Hard Pass: Declining APT34's Invite to Join Their Professional Network](https://cloud.google.com/blog/topics/threat-intelligence/hard-pass-declining-apt34-invite-to-join-their-professional-network/)
- **July 16, 2019** – **BGD e-GOV CIRT**: [[DNSPIONAGE] – FOCUS ON INTERNAL ACTIONS](https://www.cirt.gov.bd/dnspionage-focus-on-internal-actions/)
- **May 15, 2019** – **Proofpoint**: [Threat Actor Profile: TA542, From Banker to Malware Distribution Service](https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta542-banker-malware-distribution-service)
- **May 06, 2019** – **NSFOCUS**: [Analysis of File Disclosure by APT34](https://nsfocusglobal.com/analysis-of-file-disclosure-by-apt34/)
- **April 30, 2019** – **Unit 42**: [Behind the Scenes with OilRig](https://unit42.paloaltonetworks.com/behind-the-scenes-with-oilrig/)
- **April 16, 2019** – **Unit 42**: [DNS Tunneling in the Wild: Overview of OilRig’s DNS Tunneling](https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/)

### 2018

- **November 27, 2018** – **Cisco Talos**: [DNSpionage Campaign Targets Middle East](https://blog.talosintelligence.com/dnspionage-campaign-targets-middle-east/) (attributed by FireEye on July 18, 2019)
- **November 16, 2018** – **Unit 42**: [Analyzing OilRig's Ops Tempo from Testing to Weaponization to Delivery](https://unit42.paloaltonetworks.com/unit42-analyzing-oilrigs-ops-tempo-testing-weaponization-delivery/)
- **September 12, 2018** – **Unit 42**: [OilRig Uses Updated BONDUPDATER to Target Middle Eastern Government](https://unit42.paloaltonetworks.com/unit42-oilrig-uses-updated-bondupdater-target-middle-eastern-government/)
- **September 04, 2018** – **Unit 42**: [OilRig targets a Middle Eastern Government and Adds Evasion Techniques to OopsIE](https://unit42.paloaltonetworks.com/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/)
- **July 25, 2018** – **Unit 42**: [OilRig Targets Technology Service Provider and Government Agency with QUADAGENT](https://unit42.paloaltonetworks.com/unit42-oilrig-targets-technology-service-provider-government-agency-quadagent/)
- **February 23, 2018** – **Unit 42**: [OopsIE! OilRig Uses ThreeDollars to Deliver New Trojan](https://unit42.paloaltonetworks.com/unit42-oopsie-oilrig-uses-threedollars-deliver-new-trojan/)
- **February 23, 2018** – **Booz Allen**: [Researchers Discover New variants of APT34 Malware](https://www.boozallen.com/s/insight/blog/dark-labs-discovers-apt34-malware-variants.html)
- **January 25, 2018** – **Unit 42**: [OilRig uses RGDoor IIS Backdoor on Targets in the Middle East](https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/)

### 2017

- **December 15, 2017** – **Unit 42**: [Introducing the Adversary Playbook: First up, OilRig](https://unit42.paloaltonetworks.com/unit42-introducing-the-adversary-playbook-first-up-oilrig/)
- **December 11, 2017** – **Unit 42**: [OilRig Performs Tests on the TwoFace Webshell](https://unit42.paloaltonetworks.com/unit42-oilrig-performs-tests-twoface-webshell/)
- **December 07, 2017** – **FireEye**: [New Targeted Attack in the Middle East by APT34, a Suspected Iranian Threat Group, Using CVE-2017-11882 Exploit](https://cloud.google.com/blog/topics/threat-intelligence/targeted-attack-in-middle-east-by-apt34/)
- **November 08, 2017** – **Unit 42**: [OilRig Deploys “ALMA Communicator” – DNS Tunneling Trojan](https://unit42.paloaltonetworks.com/unit42-oilrig-deploys-alma-communicator-dns-tunneling-trojan/)
- **October 24, 2017** – **ClearSky**: [Iranian Threat Agent Greenbug Impersonates Israeli High-Tech and Cyber Security Companies](https://www.clearskysec.com/greenbug/)
- **October 09, 2017** – **Unit 42**: [OilRig Group Steps Up Attacks with New Delivery Documents and New Injector Trojan](https://unit42.paloaltonetworks.com/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/)
- **September 26, 2017** – **Unit 42**: [Striking Oil: A Closer Look at Adversary Infrastructure](https://unit42.paloaltonetworks.com/unit42-striking-oil-closer-look-adversary-infrastructure/)
- **August 28, 2017** – **ClearSky**: [Recent ISMAgent Samples and Infrastructure by Iranian Threat Group GreenBug](https://www.clearskysec.com/ismagent/)
- **July 27, 2017** – **Unit 42**: [OilRig Uses ISMDoor Variant; Possibly Linked to Greenbug Threat Group](https://unit42.paloaltonetworks.com/unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group/)
- **July 27, 2017** – **Secureworks**: [The Curious Case of Mia Ash: Fake Persona Lures Middle Eastern Targets](https://www.secureworks.com/research/the-curious-case-of-mia-ash)
- **April 27, 2017** – **Unit 42**: [OilRig Actors Provide a Glimpse into Development and Testing Efforts](https://unit42.paloaltonetworks.com/unit42-oilrig-actors-provide-glimpse-development-testing-efforts/)
- **March 31, 2017** – **LogRhythm Labs**: [OilRig Campaign Analysis](https://www.content.shi.com/SHIcom/ContentAttachmentImages/SharedResources/PDFs/lr-041017-oilrig-report2.pdf) (PDF, TLP:WHITE)
- **February 15, 2017** – **Secureworks**: [Iranian PupyRAT Bites Middle Eastern Organizations](https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations)
- **January 05, 2017** – **ClearSky**: [Iranian Threat Agent OilRig Delivers Digitally Signed Malware, Impersonates University of Oxford](https://www.clearskysec.com/oilrig/)

### 2016

- **October 04, 2016** – **Unit 42**: [OilRig Malware Campaign Updates Toolset and Expands Targets](https://unit42.paloaltonetworks.com/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/)
- **May 26, 2016** – **Unit 42**: [The OilRig Campaign: Attacks on Saudi Arabian Organizations Deliver Helminth Backdoor](https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/)

### 2015

- **October 07, 2015** – **Secureworks**: [Hacker Group Creates Network of Fake LinkedIn Profiles](https://www.secureworks.com/research/suspected-iran-based-hacker-group-creates-network-of-fake-linkedin-profiles)