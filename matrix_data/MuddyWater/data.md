# MuddyWater

*Last Updated: November 21, 2024*

## 1. Basic Information
- **First Seen**: 2017
- **Source Country**: Islamic Republic of Iran
- **Threat Actor Type**: Nation-State Sponsored
- **Linked Organization**: Ministry of Intelligence and Security (MOIS)
- **Objective**: Intelligence Gathering, Espionage, Information Theft

## 2. Description
MuddyWater is a cyber espionage group assessed to be state-sponsored by Iran’s Ministry of Intelligence and Security (MOIS). Active since 2017, it predominantly targets Middle Eastern countries, employing a variety of TTPs to achieve intelligence gathering and espionage objectives.

## 3. Aliases
| Alias               | Organization                                          |
|---------------------|-------------------------------------------------------|
| MuddyWater          | Check Point, Cisco Talos Intelligence, MITRE, Clearsky Security |
| Seedworm            | [Symantec](https://www.security.com/threat-intelligence/seedworm-espionage-group) |
| TEMP.Zagros         | [FireEye (Mandiant)](https://cloud.google.com/blog/topics/threat-intelligence/iranian-threat-group-updates-ttps-in-spear-phishing-campaign) |
| Static Kitten       | [CrowdStrike](https://www.crowdstrike.com/adversaries/static-kitten/) |
| Mango Sandstorm     | [Microsoft](https://learn.microsoft.com/en-us/defender-xdr/microsoft-threat-actor-naming) |
| Boggy Serpens       | [Palo Alto Networks (Unit42)](https://unit42.paloaltonetworks.com/threat-actor-groups-tracked-by-palo-alto-networks-unit-42/) |
| TA450               | [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/security-brief-ta450-uses-embedded-links-pdf-attachments-latest-campaign)                                            |
| Cobalt Ulster       | [SecureWorks](https://www.secureworks.com/research/threat-profiles/cobalt-ulster) |
| ATK 51              | [Thales](https://cds.thalesgroup.com/en/node/675) |
| T-APT-14            | Tencent                                               |
| ITG17               | [IBM](https://exchange.xforce.ibmcloud.com/threat-group/guid:95d4aadc7e81451dbe784905c2a22cb1) |
| Yellow Nix          | [PwC](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/muddy-advanced-persistent-teacher.html) |
| Mercury             | [formerly used by Microsoft](https://learn.microsoft.com/en-us/defender-xdr/microsoft-threat-actor-naming) |
| NTSTATS             | N/A                                                   |
| POWERSTATS          | N/A                                                   |
| SectorD02           | N/A                                                   |

## 4. Targeting
- **Targeted Countries**: Afghanistan, Armenia, Austria, Azerbaijan, Bahrain, Belarus, Egypt, Georgia, India, Iran, Israel, Jordan, Kuwait, Laos, Lebanon, Mali, Netherlands, Oman, Pakistan, Portugal, Qatar, Russia, Saudi Arabia, Sudan, Tajikistan, Tanzania, Thailand, Tunisia, Turkey, UAE, Ukraine, USA
- **Targeted Sectors**: Aviation, Defense, Education, Energy, Financial, Food & Agriculture, Gaming, Government, Healthcare, High-Tech, IT, Media, NGOs, Oil & Gas, Shipping & Logistics, Telecommunications, Transportation
- **Motivation**: State-Sponsored

## 5. Tools Used
| Tool Name                    | Type                                                                                    |
|------------------------------|-----------------------------------------------------------------------------------------|
| BugSleep                     | Malware, Backdoor                                                                       |
| ChromeCookiesView            | Tool, Reconnaissance, Info stealer                                                      |
| chrome-passwords             | Malware, Credential stealer                                                             |
| CLOUDSTATS                   | Malware, Backdoor                                                                       |
| Cobalt Strike                | Tool, Backdoor, Vulnerability scanner, Keylogger, Tunneling, Loader, Exfiltration       |
| CrackMapExec                 | Tool, Vulnerability scanner                                                             |
| DELPHSTATS                   | Malware, Backdoor                                                                       |
| EmpireProject                | Tool, Backdoor                                                                          |
| FruityC2                     | Tool, Backdoor                                                                          |
| Koadic                       | Backdoor, Vulnerability scanner, Loader                                                 |
| LaZagne                      | Credential stealer                                                                      |
| Meterpreter                  | Loader                                                                                  |
| Mimikatz                     | Credential stealer, Keylogger                                                           |
| MuddyC2Go                    | Backdoor                                                                                |
| Mudwater                     | Reconnaissance, Backdoor, Exfiltration, Downloader                                      |
| MZCookiesView                | Reconnaissance, Info stealer                                                            |
| PhonyC2                      | Backdoor                                                                                |
| Powermud                     | Backdoor, Tunneling                                                                     |
| PowerSploit                  | Reconnaissance, Backdoor, Info stealer, Exfiltration                                    |
| POWERSTATS                   | Backdoor                                                                                |
| PowGoop                      | Loader                                                                                  |
| PRB-Backdoor                 | Backdoor                                                                                |
| QUADAGENT                    | Backdoor, Tunneling                                                                     |
| Secure Socket Funneling      | Tunneling, Remote command                                                               |
| SHARPSTATS                   | Backdoor, Info stealer                                                                  |
| Shootback                    | Backdoor, Tunneling                                                                     |
| Smbmap                       | Reconnaissance                                                                          |
| Living off the Land          | Technique, Execution, Persistence, Privilege Escalation, Lateral Movement, Defense Evasion, Credential Dumping, Fileless Attack, Data Collection, Exfiltration, Remote Command Execution |


## 6. Exploited Vulnerabilities
| CVE                | CVSS Score      | Description                                                           |
|--------------------|-----------------|-----------------------------------------------------------------------|
| [CVE-2023-27350](https://nvd.nist.gov/vuln/detail/CVE-2023-27350)   | 9.8 (Critical)  | PaperCut MF/NG Improper Access Control Vulnerability                  |
| [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046)   | 9.0 (Critical)  | Apache Log4j2 Remote Code Execution Vulnerability                     |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)   | 10.0 (Critical) | Apache Log4j2 Remote Code Execution Vulnerability                     |
| [CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)     | 10.0 (Critical) | Netlogon Elevation of Privilege Vulnerability                         |
| [CVE-2020-0688](https://nvd.nist.gov/vuln/detail/CVE-2020-0688)     | 8.8 (High)      | Microsoft Exchange Validation Key Remote Code Execution Vulnerability |
| [CVE-2017-0199](https://nvd.nist.gov/vuln/detail/CVE-2017-0199)     | 7.8 (High)      | Microsoft Office/WordPad Remote Code Execution Vulnerability          |

## 7. Campaigns
| Name                    | Overview                                               | References                           |
|-------------------------|--------------------------------------------------------|--------------------------------------|
| **Earth Vetala**        | Earth Vetala Cyberespionage Campaign targeting multiple sectors. |[1](https://www.trendmicro.com/en_us/research/21/c/earth-vetala---muddywater-continues-to-target-organizations-in-t.html), [2](https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies)                    |
| **BlackWater**          | BLACKWATER Cyberespionage Campaign focused on Middle Eastern countries. |[1](https://blog.talosintelligence.com/recent-muddywater-associated-blackwater/)             |
| **Operation Quicksand** | Targeting government and military organizations in the Middle East. | [1](https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf), [2](https://unit42.paloaltonetworks.com/thanos-ransomware/)                        |
| **ShroudedSnooper**     | Campaign focused on disguising operations through covert channels. | [1](https://blog.talosintelligence.com/introducing-shrouded-snooper/)                         |

## 8. TTP Matrix
Please refer to Muddywater's [TTP Matrix here.](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0069%2FG0069-enterprise-layer.json).

## 9. Patterns and Observed Behaviors
- **Activity Patterns**: Timing of attacks often coincides with regional geopolitical events.
- **Behavioral Observations**: Reuse of tools such as Cobalt Strike, with an increase in encrypted command and control (C2) communications.

## 10. References
This reference list features news reporting, actionable intelligence, detailed analysis reports, and in-depth research. (Not only news, but also references to malware analysis reports and APT-relevant research.)
| Date         | Source                           | Details                                                                                                                                                                                                                 |
|--------------|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Oct-30-2024  | Cisco Talos                      | [Writing a BugSleep C2 server and detecting its traffic with Snort (malware analysis)](https://blog.talosintelligence.com/writing-a-bugsleep-c2-server/)                                                                |
| Oct-22-2024  | k3yp0d                           | [Something phishy is happening in Armenia (independent researcher)](https://k3yp0d.blogspot.com/2024/10/something-phishy-is-happening-in-armenia.html)                                                                  |
| Jul-15-2024  | Sekoia                           | [MuddyWater replaces Atera by custom MuddyRot implant in a recent campaign](https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/)                                          |
| Jul-15-2024  | Check Point Research             | [New BugSleep Backdoor Deployed in Recent MuddyWater Campaigns](https://research.checkpoint.com/2024/new-bugsleep-backdoor-deployed-in-recent-muddywater-campaigns/)                                                    |
| May-14-2024  | ESET Research                    | [ESET APT Activity Report Q4 2023–Q1 2024](https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2023-q1-2024/)                                                                                   |
| Apr-24-2024  | Broadcom                         | [Seedworm exploits Atera Agent in a spear-phishing Campaign](https://www.broadcom.com/support/security-center/protection-bulletin/seedworm-exploits-atera-agent-in-a-spear-phishing-campaign)                           |
| Apr-22-2024  | HarfangLab                       | [Increased activity from Iran sponsored APT MuddyWater, targeting Middle East, African & European organisations.](https://harfanglab.io/en/press/increased-activity-from-iran-sponsored-apt-muddywater/)                |
| Apr-08-2024  | Unit 42                          | [Boggy Serpens (MuddyWater) Use of AutodialDLL](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-Boggy-Serpens-use-of-AutodialDLL.txt)                                                     |
| Apr-07-2024  | Broadcom                         | [Seedworm distributing remote administration management software agents](https://www.broadcom.com/support/security-center/protection-bulletin/seedworm-distributing-remote-administration-management-software-agents)   |
| Mar-29-2024  | Malwation                        | [New MuddyWater Campaigns After Operation Swords of Iron](https://www.malwation.com/blog/new-muddywater-campaigns-after-operation-swords-of-iron)                                                                       |
| Mar-21-2024  | Proofpoint                       | [Security Brief: TA450 Uses Embedded Links in PDF Attachments in Latest Campaign](https://www.proofpoint.com/us/blog/threat-insight/security-brief-ta450-uses-embedded-links-pdf-attachments-latest-campaign)           |
| Mar-07-2024  | Israel National Cyber Directorate| [An active phishing campaign in Israeli territory – the Iranian attack group MuddyWater (written in Hebrew)](https://www.gov.il/he/pages/alert_1718)                                                                    |
| Dec-19-2023  | Symantec                         | [Seedworm: Iranian Hackers Target Telecoms Orgs in North and East Africa](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/iran-apt-seedworm-africa-telecoms)                                   |
| Nov-08-2023  | Deep Instinct                    | [MuddyC2Go – Latest C2 Framework Used by Iranian APT MuddyWater Spotted in Israel](https://www.deepinstinct.com/blog/muddyc2go-latest-c2-framework-used-by-iranian-apt-muddywater-spotted-in-israel)                    |
| Nov-01-2023  | Deep Instinct                    | [MuddyWater eN-Able spear-phishing with new TTPs](https://www.deepinstinct.com/blog/muddywater-en-able-spear-phishing-with-new-ttps)                                                                                    |
| Jun-29-2023  | Deep Instinct                    | [PhonyC2: Revealing a New Malicious Command & Control Framework by MuddyWater](https://www.deepinstinct.com/blog/phonyc2-revealing-a-new-malicious-command-control-framework-by-muddywater)                             |
| May-08-2023  | Bleeping Computer                | [Microsoft: Iranian hacking groups join Papercut attack spree](https://www.bleepingcomputer.com/news/security/microsoft-iranian-hacking-groups-join-papercut-attack-spree/)                                             |
| May-06-2023  | Microsoft                        | [(Twitter) Observed Iranian state-sponsored threat actors Mint Sandstorm (PHOSPHORUS) & Mango Sandstorm (MERCURY) exploiting CVE-2023-27350](https://twitter.com/MsftSecIntel/status/1654610012457648129)               |
| May-02-2023  | ESET Research                    | [APT groups muddying the waters for MSPs](https://www.welivesecurity.com/2023/05/02/apt-groups-muddying-waters-msps/)                                                                                                   |
| Apr-18-2023  | Group-IB                         | [SimpleHarm: Tracking MuddyWater’s infrastructure](https://www.group-ib.com/blog/muddywater-infrastructure/)                                                                                                            |
| Apr-07-2023  | Microsoft                        | [MERCURY and DEV-1084: Destructive attack on hybrid environment](https://example.com/microsoft-mercury-dev1084)                                                                                                         |
| Dec-08-2022  | Deep Instinct                    | [New MuddyWater Threat: Old Kitten; New Tricks](https://www.deepinstinct.com/blog/new-muddywater-threat-old-kitten-new-tricks)                                                                                          |
| Sep-09-2022  | U.S. Treasury                    | [Treasury Sanctions Iranian Ministry of Intelligence and Minister for Malign Cyber Activities](https://home.treasury.gov/news/press-releases/jy0941)                                                                    |
| Aug-25-2022  | Microsoft                        | [MERCURY leveraging Log4j 2 vulnerabilities in unpatched systems to target Israeli organizations](https://www.microsoft.com/en-us/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/) |
| Jun-21-2022  | Lab52                            | [MuddyWater’s “light” first-stager targeting Middle East](https://lab52.io/blog/muddywaters-light-first-stager-targetting-middle-east/)                                                                                 |
| May-11-2022  | NTT Security                     | [Analysis of an Iranian APTs “E400” PowGoop variant reveals dozens of control servers dating back to 2020](https://www.security.ntt/blog/analysis-of-an-iranian-apts-e400-powgoop-variant) |
| Mar-14-2022  | EclecticIQ                       | [MuddyWater APT attributed to Iranian Ministry of Intelligence and Security, and the Increasing Global Ransomware Threat](https://blog.eclecticiq.com/muddywater-apt-attributed-to-iranian-ministry-of-intelligence-and-security-and-the-increasing-global-ransomware-threat) |
| Mar-10-2022  | Cisco Talos                      | [Iranian linked conglomerate MuddyWater comprised of regionally focused subgroups](https://blog.talosintelligence.com/iranian-supergroup-muddywater/)                                                                   |
| Feb-24-2022  | CISA                             | [Iranian Government-Sponsored Actors Conduct Cyber Operations Against Global Government and Commercial Networks](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a)                                   |
| Feb-24-2022  | NCSC-UK                          | [Malware Analysis  Report: Small Sieve (PDF)](https://www.ncsc.gov.uk/files/NCSC-Malware-Analysis-Report-Small-Sieve.pdf)                                                                                               |
| Jan-31-2022  | Cisco Talos                      | [Iranian APT MuddyWater targets Turkish users via malicious PDFs, executables](https://blog.talosintelligence.com/iranian-apt-muddywater-targets-turkey/)                                                               |
| Jan-13-2022  | Picus                            | [TTPs and IOCs Used by MuddyWater APT Group in Latest Attack Campaign](https://www.picussecurity.com/resource/blog/ttp-ioc-used-by-muddywater-apt-group-attacks)                                                        |
| Jan-12-2022  | USCYBERCOM                       | [Iranian intel cyber suite of malware uses open source tools](https://www.cybercom.mil/Media/News/Article/2897570/iranian-intel-cyber-suite-of-malware-uses-open-source-tools/)                                         |
| Jan-12-2022  | SentinelOne                      | [Wading Through Muddy Waters: Recent Activity of an Iranian State-Sponsored Threat Actor](https://www.sentinelone.com/labs/wading-through-muddy-waters-recent-activity-of-an-iranian-state-sponsored-threat-actor/)     |
| Dec-14-2021  | Symantec                         | [Espionage Campaign Targets Telecoms Organizations across Middle East and Asia](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/espionage-campaign-telecoms-asia-middle-east)                  |
| Mar-05-2021  | Trend Micro                      | [Earth Vetala – MuddyWater Continues to Target Organizations in the Middle East](https://www.trendmicro.com/en_us/research/21/c/earth-vetala---muddywater-continues-to-target-organizations-in-t.html)                  |
| Feb-10-2021  | Anomali                          | [Probable Iranian Cyber Actors, Static Kitten, Conducting Cyberespionage Campaign Targeting UAE and Kuwait Government Agencies](https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies) |
| Oct-21-2020  | Symantec                         | [Seedworm: Iran-Linked Group Continues to Target Organizations in the Middle East](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-apt-iran-middle-east)                              |
| Oct-15-2020  | Clearsky                         | [Operation Quicksand](https://www.clearskysec.com/operation-quicksand/) |
| Feb-26-2020  | Secureworks                      | [Business as Usual for Iranian Operations Despite Increased Tensions](https://www.secureworks.com/blog/business-as-usual-for-iranian-operations-despite-increased-tensions)                                             |
| Jun-09-2019  | Trend Micro                      | [New MuddyWater Activities Uncovered (PDF)](https://documents.trendmicro.com/assets/white_papers/wp_new_muddywater_findings_uncovered.pdf)                                                                              |
| Jun-06-2019  | Clearsky                         | [Iranian APT group ‘MuddyWater’ Adds Exploits to Their Arsenal](https://www.clearskysec.com/muddywater2/)                                                                                                               |
| May-29-2019  | Group-IB                         | [Catching fish in muddy waters](https://www.group-ib.com/blog/muddywater/)                                                                                                                                              |
| May-20-2019  | Cisco Talos                      | [Recent MuddyWater-associated BlackWater campaign shows signs of new anti-detection techniques](https://blog.talosintelligence.com/recent-muddywater-associated-blackwater/)                                            |
| Apr-29-2019  | Kaspersky                        | [I know what you did last summer, MuddyWater blending in the crowd](https://securelist.com/muddywaters-arsenal/90659/)                                                                                                  |
| Apr-15-2019  | Clearsky                         | [Iranian APT MuddyWater Attack Infrastructure Targeting Kurdish Political Groups and Organizations in Turkey](https://www.clearskysec.com/muddywater-targets-kurdish-groups-turkish-orgs/)                              |
| Apr-10-2019  | Check Point                      | [The Muddy Waters of APT Attacks](https://research.checkpoint.com/2019/the-muddy-waters-of-apt-attacks/)                                                                                                                |
| Mar-07-2019  | NSHC                             | [SectorD02 PowerShell Backdoor Analysis](https://redalert.nshc.net/2019/03/07/sectord02-powershell-backdoor-analysis/)                                                                                                  |
| Dec-10-2018  | Symantec                         | [Seedworm: Group Compromises Government Agencies, Oil & Gas, NGOs, Telecoms, and IT Firms](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-espionage-group?es_p=8239106)              |
| Nov-30-2018  | Trend Micro                      | [New PowerShell-based Backdoor, MuddyWater Similarities](https://www.trendmicro.com/en_us/research/18/k/new-powershell-based-backdoor-found-in-turkey-strikingly-similar-to-muddywater-tools.html)                      |
| Nov-28-2018  | Clearsky                         | [MuddyWater Operations in Lebanon and Oman](https://www.clearskysec.com/muddywater-operations-in-lebanon-and-oman/)                                                                                                     |
| Oct-10-2018  | Kaspersky                        | [MuddyWater expands operations](https://securelist.com/muddywater/88059/) |
| Jun-14-2018  | Trend Micro                      | [Potential MuddyWater Campaign uses PRB-Backdoor](https://www.trendmicro.com/en_us/research/18/f/another-potential-muddywater-campaign-uses-powershell-based-prb-backdoor.html)                                         |
| Mar-13-2018  | FireEye                          | [Iranian Threat Group Updates Tactics, Techniques and Procedures in Spear Phishing Campaign](https://cloud.google.com/blog/topics/threat-intelligence/iranian-threat-group-updates-ttps-in-spear-phishing-campaign/)    |
| Mar-12-2018  | Trend Micro                      | [Potential MuddyWater Campaign Seen in the Middle East](https://www.trendmicro.com/en_us/research/18/c/campaign-possibly-connected-muddywater-surfaces-middle-east-central-asia.html) |
| Mar-10-2018  | Security 0wnage                  | [A Quick Dip into MuddyWater's Recent Activity](https://sec0wn.blogspot.com/2018/03/a-quick-dip-into-muddywaters-recent.html)                                                                                           |
| Feb-01-2018  | Security 0wnage                  | [Burping on MuddyWater](https://sec0wn.blogspot.com/2018/02/burping-on-muddywater.html) |
| Nov-14-2017  | Unit 42                          | [Muddying the Water: Targeted Attacks in the Middle East](https://unit42.paloaltonetworks.com/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/)                                                           |
| Oct-04-2017  | Security 0wnage                  | [Continued Activity targeting the Middle East](https://sec0wn.blogspot.com/2017/10/continued-activity-targeting-middle-east.html)                                                                                       |

