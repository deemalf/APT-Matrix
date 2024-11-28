# Earth Baku (APT41)

*Last Updated: November 28, 2024*

## 1. Basic Information

- **First Seen**: Not specified
- **Source Country**: People's Republic of China
- **Threat Actor Type**: Nation-State Sponsored
- **Linked Organization**: Loosely connected private contractors operating on behalf of China’s Ministry of State Security (MSS). Some have worked at Chengdu 404 Network Technology.
- **Objectives**: Espionage, Information theft, Financial crime

## 2. Description

Earth Baku, also known as APT41, is a state-sponsored cyber threat group attributed to the People's Republic of China. The group consists of loosely connected private contractors operating on behalf of China’s Ministry of State Security (MSS), with some members having worked at Chengdu 404 Network Technology Company Ltd. Active since at least 2012, Earth Baku focuses on espionage, information theft, and financial crime. The group is notorious for its sophisticated cyber capabilities, including exploiting zero-day vulnerabilities, conducting supply chain attacks, and blending state-sponsored espionage with financially motivated cybercrime activities.

## 3. Aliases

| Alias                    | Organization                                                                                                      |
|--------------------------|-------------------------------------------------------------------------------------------------------------------|
| **APT41**                | FBI, CISA, Cisco, EDTA, FireEye, Mandiant, Kaspersky, Malpedia, Unit 42, Zscaler                                   |
| **Axiom**                | Note: Treated as a separate threat actor                                                                           |
| **BARIUM**               | Formerly used by Microsoft                                                                                         |
| **Blackfly**             | Symantec                                                                                                           |
| **Brass Typhoon**        | Microsoft                                                                                                          |
| **Bronze Atlas**         | SecureWorks                                                                                                        |
| **Double Dragon**        | Wikipedia                                                                                                          |
| **Earth Baku**           | Trend Micro                                                                                                        |
| **Grayfly**              | Symantec                                                                                                           |
| **Red Kelpie**           | PwC (?)                                                                                                            |
| **RedEcho**              | Different threat actor from Recorded Future, possible overlaps                                                     |
| **Redfly**               | Not used by Symantec, but linked via ShadowPad malware                                                             |
| **RedGolf**              | Officially used by Recorded Future                                                                                 |
| **SparklingGoblin**      | ESET                                                                                                               |
| **TG-2633**              | Formerly used by SecureWorks                                                                                       |
| **Wicked Panda**         | Used by CrowdStrike to track espionage                                                                             |
| **Wicked Spider**        | Used by CrowdStrike to track cybercrime                                                                            |
| **Winnti**, **Winnti Group** | Kaspersky, ESET, Cybereason, PwC                                                                              |

### Subgroups

| Sub-group Name      | By Organizations                                                                      |
|---------------------|-----------------------------------------------------------------------------------------------|
| **Earth Longzhi**   | Trend Micro                                                                                   |
| **Earth Freybug**   | Trend Micro                                                                                   |
| **Lead**            | Formerly used by Microsoft                                                                    |
| **Leopard Typhoon** | Microsoft                                                                                     |
| **Vanadinite**      | Dragos                                                                                        |

## 4. Identified Members

- **Zhang Haoran (张浩然)**: FBI Most Wanted
- **Tan Dailin (谭戴林)**: FBI Most Wanted
- **Jiang Lizhi (蒋立志)**: FBI Most Wanted
- **Qian Chuan (钱川)**: FBI Most Wanted
- **Fu Qiang (付强)**: FBI Most Wanted

### Associated Company

- **Chengdu Si Lingsi (404) Network Technology Company Ltd. (成都市肆零肆网络科技有限公司)**

## 5. Targeting

- **Targeted Countries**: Various, including the United States, India, Taiwan, and countries in Europe and Asia.
- **Targeted Sectors**: Government, Telecommunications, Technology, Finance, Healthcare, Energy, Education, and others.
- **Motivation**: State-Sponsored and Financial Crime

## 6. Tools Used

- **ShadowPad**: Modular backdoor commonly used by Chinese threat actors.
- **Cobalt Strike**: Commercial penetration testing tool used maliciously.
- **Winnti Malware**: Malware family associated with APT41.
- **Speculoos Backdoor**: Malware used in global intrusion campaigns.
- **KEYPLUG**: Malware used for espionage and data theft.
- **Skip-2.0**: A Microsoft SQL Server backdoor.
- **Messagetap**: Malware used to intercept SMS messages.
- **LightSpy**: Advanced espionage framework targeting mobile devices.
- **MoonWalk and DodgeBox**: Updated arsenal of tools used by APT41.

*Note: This list is non-exhaustive and may be updated.*

## 7. Vulnerabilities Exploited

| CVE                                            | CVSS Score      | Description                                                                           | Sources                             |
|------------------------------------------------|-----------------|---------------------------------------------------------------------------------------|-------------------------------------|
| [CVE-2018-0824](https://nvd.nist.gov/vuln/detail/CVE-2018-0824) | 7.5 (High)       | Microsoft COM for Windows Remote Code Execution Vulnerability                         | Cisco                               |
| [CVE-2017-0199](https://nvd.nist.gov/vuln/detail/CVE-2017-0199) | 7.8 (High)       | Microsoft Office and WordPad Remote Code Execution Vulnerability                      | Clearsky, Fortinet, FireEye         |
| [CVE-2019-3396](https://nvd.nist.gov/vuln/detail/CVE-2019-3396) | 9.8 (Critical)   | Atlassian Confluence Server and Data Center Server-Side Template Injection Vulnerability | FireEye, Fortinet               |
| [CVE-2015-1641](https://nvd.nist.gov/vuln/detail/CVE-2015-1641) | 7.8 (High)       | Microsoft Office Memory Corruption Vulnerability                                      | Fortinet                            |
| [CVE-2012-0158](https://nvd.nist.gov/vuln/detail/CVE-2012-0158) | 8.8 (High)       | Microsoft MSCOMCTL.OCX Remote Code Execution Vulnerability                            | Fortinet, FireEye                   |
| [CVE-2017-11882](https://nvd.nist.gov/vuln/detail/CVE-2017-11882) | 7.8 (High)       | Microsoft Office Memory Corruption Vulnerability                                      | FireEye                             |
| [CVE-2019-19781](https://nvd.nist.gov/vuln/detail/CVE-2019-19781) | 9.8 (Critical)   | Citrix ADC, Gateway, and SD-WAN WANOP Appliance Code Execution Vulnerability          | U.S. DOJ, FireEye, Fortinet         |
| [CVE-2019-11510](https://nvd.nist.gov/vuln/detail/CVE-2019-11510) | 10.0 (Critical)  | Ivanti Pulse Connect Secure Arbitrary File Read Vulnerability                         | U.S. DOJ                            |
| [CVE-2019-16920](https://nvd.nist.gov/vuln/detail/CVE-2019-16920) | 9.8 (Critical)   | D-Link Multiple Routers Command Injection Vulnerability                               | U.S. DOJ                            |
| [CVE-2019-16278](https://nvd.nist.gov/vuln/detail/CVE-2019-16278) | 9.8 (Critical)   | Nostromo 1.9.6 Directory Traversal/Remote Command Execution Vulnerability             | U.S. DOJ                            |
| [CVE-2019-1652](https://nvd.nist.gov/vuln/detail/CVE-2019-1652) | 7.2 (High)       | Cisco Small Business Routers Improper Input Validation Vulnerability                  | U.S. DOJ, FireEye                   |
| [CVE-2019-1653](https://nvd.nist.gov/vuln/detail/CVE-2019-1653) | 7.5 (High)       | Cisco Small Business RV320 and RV325 Routers Information Disclosure Vulnerability     | U.S. DOJ, FireEye                   |
| [CVE-2020-10189](https://nvd.nist.gov/vuln/detail/CVE-2020-10189) | 9.8 (Critical)   | Zoho ManageEngine Desktop Central File Upload Vulnerability                           | U.S. DOJ, FireEye, Fortinet         |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | 10.0 (Critical)  | Apache Log4j2 Remote Code Execution Vulnerability (Log4Shell)                         | Mandiant                            |
| [CVE-2021-44207](https://nvd.nist.gov/vuln/detail/CVE-2021-44207) | 8.1 (High)       | Acclaim USAHERDS Hard-Coded Credentials Vulnerability                                 | Mandiant                            |

## 8. Campaigns

| Name                       | Overview                                                                                 | References                                                 |
|----------------------------|------------------------------------------------------------------------------------------|------------------------------------------------------------|
| **Operation ShadowHammer** | Supply chain attack on ASUS Live Update utility to distribute malware                    | [Kaspersky](#11-references)                                |
| **Operation CuckooBees**   | Massive Chinese Intellectual Property Theft Operation targeting defense and tech sectors | [Cybereason](#11-references)                               |
| **Messagetap Campaign**    | SMS message interception targeting telecom providers                                     | [FireEye](#11-references)                                  |
| **Speculoos Campaign**     | Global intrusion campaign exploiting vulnerabilities for initial access                  | [Unit 42](#11-references)                                  |
| **Earth Baku Campaign**    | Cyberespionage campaign targeting Indo-Pacific countries                                 | [Trend Micro](#11-references)                              |

## 9. Tactics, Techniques, and Procedures (TTPs)

Earth Baku's TTPs are mapped to the [MITRE ATT&CK Framework](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0096%2FG0096-enterprise-layer.json). Detailed mappings are available in the references.

## 10. Patterns and Observed Behaviors

- **Activity Patterns**: Exploitation of zero-day vulnerabilities, supply chain attacks, use of stolen code-signing certificates, deployment of sophisticated malware families, blending espionage and financially motivated operations.
- **Behavioral Observations**: Rapid adaptation to new vulnerabilities; targeting multiple sectors and countries; use of advanced evasion techniques; leveraging legitimate tools for malicious purposes.

## 11. References

This reference list features news reporting, actionable intelligence, detailed analysis reports, and in-depth research.

### 2024

- **November 12, 2024** – **BlackBerry**: [LightSpy: APT41 Deploys Advanced DeepData Framework In Targeted Southern Asia Espionage Campaign](https://blogs.blackberry.com/en/2024/11/lightspy-apt41-deploys-advanced-deepdata-framework-in-targeted-southern-asia-espionage-campaign)
- **August 04, 2024** – **Trend Micro**: [A Dive into Earth Baku’s Latest Campaign](https://www.trendmicro.com/en_us/research/24/h/earth-baku-latest-campaign.html)
- **August 01, 2024** – **Cisco Talos**: [APT41 likely compromised Taiwanese government-affiliated research institute with ShadowPad and Cobalt Strike](https://blog.talosintelligence.com/chinese-hacking-group-apt41-compromised-taiwanese-government-affiliated-research-institute-with-shadowpad-and-cobaltstrike-2/)
- **July 18, 2024** – **Mandiant**: [APT41 Has Arisen From the DUST](https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust)
- **July 11, 2024** – **Zscaler**: [MoonWalk: A deep dive into the updated arsenal of APT41 | Part 2](https://www.zscaler.com/blogs/security-research/moonwalk-deep-dive-updated-arsenal-apt41-part-2)
- **July 10, 2024** – **Zscaler**: [DodgeBox: A deep dive into the updated arsenal of APT41 | Part 1](https://www.zscaler.com/blogs/security-research/dodgebox-deep-dive-updated-arsenal-apt41-part-1)
- **June 10, 2024** – **Technical University of Zurich (ETH Zurich)**: [From Vegas to Chengdu: Hacking Contests, Bug Bounties, and China’s Offensive Cyber Ecosystem](https://css.ethz.ch/content/dam/ethz/special-interest/gess/cis/center-for-securities-studies/pdfs/CyberDefenseReport_%20From%20Vegas%20to%20Chengdu.pdf) (Research paper, PDF)
- **May 29, 2024** – **Natto Thoughts**: [APT41’s Reconnaissance Techniques and Toolkit: Nmap and What Else?](https://nattothoughts.substack.com/p/apt41s-reconnaissance-techniques)
- **May 22, 2024** – **Natto Thoughts**: [Front Company or Real Business in China’s Cyber Operations](https://nattothoughts.substack.com/p/front-company-or-real-business-in)
- **April 02, 2024** – **Trend Micro**: [Earth Freybug Uses UNAPIMON for Unhooking Critical APIs](https://www.trendmicro.com/en_us/research/24/d/earth-freybug.html) (APT41 subgroup)
- **February 28, 2024** – **Natto Thoughts**: [i-SOON: Kicking off the Year of the Dragon with Good Luck … or Not](https://nattothoughts.substack.com/p/i-soon-kicking-off-the-year-of-the) (More about association of i-SOON to Chengdu 404)

### 2023

- **October 27, 2023** – **Natto Thoughts**: [i-SOON: Another Company in the APT41 Network](https://nattothoughts.substack.com/p/i-soon-another-company-in-the-apt41)
- **September 22, 2023** – **Mandiant**: [Threat Trends: Unraveling WyrmSpy and DragonEgg Mobile Malware with Lookout](https://www.mandiant.com/resources/podcasts/threat-trends-wyrmspy-dragonegg-malware)
- **September 12, 2023** – **Symantec**: [Redfly: Espionage Actors Continue to Target Critical Infrastructure](https://symantec-enterprise-blogs.security.com/threat-intelligence/critical-infrastructure-attacks) (Tenuous link via ShadowPad trojan)
- **July 19, 2023** – **Lookout**: [Lookout Attributes Advanced Android Surveillanceware to Chinese Espionage Group APT41](https://www.lookout.com/threat-intelligence/article/wyrmspy-dragonegg-surveillanceware-apt41)
- **May 02, 2023** – **Trend Micro**: [Attack on Security Titans: Earth Longzhi Returns With New Tricks](https://www.trendmicro.com/en_us/research/23/e/attack-on-security-titans-earth-longzhi-returns-with-new-tricks.html) (APT41 subgroup)
- **April 01, 2023** – **Google Cloud/Threat Analysis Group (TAG)**: [April 2023 Threat Horizons Report](https://services.google.com/fh/files/blogs/gcat_threathorizons_full_apr2023.pdf) (PDF, page 9: HOODOO Uses Public Tooling, Google Workspace to Target Taiwanese Media)
- **March 30, 2023** – **Recorded Future**: [With KEYPLUG, China’s RedGolf Spies On, Steals From Wide Field of Targets](https://go.recordedfuture.com/hubfs/reports/cta-2023-0330.pdf) (PDF)
- **February 28, 2023** – **Symantec**: [Blackfly: Espionage Group Targets Materials Technology](https://symantec-enterprise-blogs.security.com/threat-intelligence/blackfly-espionage-materials)

### 2022

- **November 09, 2022** – **Trend Micro**: [Hack the Real Box: APT41’s New Subgroup Earth Longzhi](https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html) (APT41 subgroup)
- **October 18, 2022** – **Symantec**: [Spyder Loader: Malware Seen in Recent Campaign Targeting Organizations in Hong Kong](https://symantec-enterprise-blogs.security.com/threat-intelligence/spyder-loader-cuckoobees-hong-kong)
- **September 22, 2022** – **U.S. Health and Human Services (HHS)**: [APT41 and Recent Activity](https://www.hhs.gov/sites/default/files/apt41-recent-activity.pdf) (PDF)
- **September 14, 2022** – **ESET**: [You never walk alone: The SideWalk backdoor gets a Linux variant](https://www.welivesecurity.com/2022/09/14/you-never-walk-alone-sidewalk-backdoor-linux-variant/)
- **August 22, 2022** – **Mandiant**: [APT41 (Double Dragon): A Dual Espionage and Cyber Crime Operation](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf) (PDF)
- **August 18, 2022** – **Group-IB**:
  - [APT41 World Tour 2021 on a tight schedule](https://www.group-ib.com/blog/apt41-world-tour-2021/)
  - [Inflexible schedule: Group-IB reveals malicious APT41 campaigns involving new tactics and tools](https://www.group-ib.com/media-center/press-releases/apt41-2/)
- **July 24, 2022** – **Intrusion Truth**: [Chinese APTs: Interlinked networks and side hustles](https://intrusiontruth.wordpress.com/2022/07/24/chinese-apts-interlinked-networks-and-side-hustles/)
- **July 23, 2022** – **Intrusion Truth**: [The people behind Chengdu 404](https://intrusiontruth.wordpress.com/2022/07/23/the-people-behind-chengdu-404/)
- **July 22, 2022** – **Intrusion Truth**: [Chengdu 404](https://intrusiontruth.wordpress.com/2022/07/22/chengdu-404/)
- **July 21, 2022** – **Intrusion Truth**: [The old school hackers behind APT41](https://intrusiontruth.wordpress.com/2022/07/21/the-old-school-hackers-behind-apt41/)
- **July 20, 2022** – **Intrusion Truth**: [APT41: A Case Study](https://intrusiontruth.wordpress.com/2022/07/20/apt41/)
- **May 02, 2022** – **Cybereason**:
  - [Operation CuckooBees: Cybereason Uncovers Massive Chinese Intellectual Property Theft Operation](https://www.cybereason.com/blog/operation-cuckoobees-cybereason-uncovers-massive-chinese-intellectual-property-theft-operation)
  - [Operation CuckooBees: A Winnti Malware Arsenal Deep-Dive](https://www.cybereason.com/blog/operation-cuckoobees-a-winnti-malware-arsenal-deep-dive)
  - [Operation CuckooBees: Deep-Dive into Stealthy Winnti Techniques](https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques)
- **March 08, 2022** – **Mandiant**: [Does This Look Infected? A Summary of APT41 Targeting U.S. State Governments](https://cloud.google.com/blog/topics/threat-intelligence/apt41-us-state-governments)
- **February 15, 2022** – **Secureworks**: [ShadowPad Malware Analysis](https://www.secureworks.com/research/shadowpad-malware-analysis)
- **January 20, 2022** – **Kaspersky**: [MoonBounce: the dark side of UEFI firmware](https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/)

### 2021

- **October 05, 2021** – **BlackBerry**: [Drawing a Dragon: Connecting the Dots to Find APT41](https://blogs.blackberry.com/en/2021/10/drawing-a-dragon-connecting-the-dots-to-find-apt41)
- **September 21, 2021** – **Recorded Future**: [China-Linked Group TAG-28 Targets India’s “The Times Group” and UIDAI (Aadhaar) Government Agency With Winnti Malware](https://www.recordedfuture.com/blog/china-linked-tag-28-targets-indias-the-times-group), available as [PDF](https://go.recordedfuture.com/hubfs/reports/cta-2021-0921.pdf)
- **September 09, 2021** – **Symantec**: [Grayfly: Chinese Threat Actor Uses Newly-discovered Sidewalk Malware](https://symantec-enterprise-blogs.security.com/threat-intelligence/grayfly-china-sidewalk-malware)
- **August 24, 2021** – **ESET**: [The SideWalk may be as dangerous as the CROSSWALK](https://www.welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/)
- **August 24, 2021** – **Trend Micro**: [APT41 Resurfaces as Earth Baku With New Cyberespionage Campaign](https://www.trendmicro.com/en_us/research/21/h/apt41-resurfaces-as-earth-baku-with-new-cyberespionage-campaign.html)
  - [Earth Baku: An APT Group Targeting Indo-Pacific Countries With New Stealth Loaders and Backdoor](https://documents.trendmicro.com/assets/white_papers/wp-earth-baku-an-apt-group-targeting-indo-pacific-countries.pdf) (PDF)
- **August 20, 2021** – **CISA**: [Chinese State-Sponsored Cyber Operations: Observed TTPs](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200b)
- **July 08, 2021** – **Recorded Future**: [Chinese State-Sponsored Activity Group TAG-22 Targets Nepal, the Philippines, and Taiwan Using Winnti and Other Tooling](https://www.recordedfuture.com/research/chinese-group-tag-22-targets-nepal-philippines-taiwan)
- **July 01, 2021** – **Avast**: [Backdoored Client from Mongolian CA MonPass](https://decoded.avast.io/luigicamastra/backdoored-client-from-mongolian-ca-monpass/)
- **June 10, 2021** – **Group-IB**: [Big airline heist](https://www.group-ib.com/blog/colunmtk-apt41/)
- **April 29, 2021** – **NTT**: [The Operations of Winnti group](https://hello.global.ntt/-/media/ntt/global/insights/white-papers/the-operations-of-winnti-group.pdf) (PDF)
- **March 16, 2021** – **Dragos**: [New ICS Threat Activity Group: VANADINITE](https://www.dragos.com/blog/industry-news/new-ics-threat-activity-group-vanadinite/)
- **March 10, 2021** – **Intezer**: [New Linux Backdoor RedXOR Likely Operated by Chinese Nation-State Actor](https://intezer.com/blog/malware-analysis/new-linux-backdoor-redxor-likely-operated-by-chinese-nation-state-actor/)
- **March 08, 2021** – **Mazaher Kianpour**: [Socio-Technical Root Cause Analysis of Cyber-enabled Theft of the U.S. Intellectual Property — The Case of APT41](https://arxiv.org/pdf/2103.04901) (PDF)
- **February 28, 2021** – **Recorded Future**: [China-linked Group RedEcho Targets the Indian Power Sector Amid Heightened Border Tensions](https://www.recordedfuture.com/research/redecho-targeting-indian-power-sector), majority in [PDF](https://go.recordedfuture.com/hubfs/reports/cta-2021-0228.pdf)
- **January 14, 2021** – **Positive Technologies**: [Higaisa or Winnti? APT41 backdoors, old and new](https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/)

### 2020

- **November 11, 2020** – **Microsoft**: [Hunting for Barium using Azure Sentinel](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/hunting-for-barium-using-azure-sentinel/ba-p/1875913)
- **October 20, 2020** – **CISA**: [Potential for China Cyber Response to Heightened U.S.–China Tensions](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-275a)
- **September 29, 2020** – **Positive Technologies**: [ShadowPad: new activity from the Winnti group](https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/shadowpad-new-activity-from-the-winnti-group/)
- **September 18, 2020** – **Trend Micro**: [U.S. Justice Department Charges APT41 Hackers over Global Cyberattacks](https://www.trendmicro.com/en_us/research/20/i/u-s--justice-department-charges-apt41-hackers-over-global-cyberattacks.html)
- **September 17, 2020** – **Symantec**: [APT41: Indictments Put Chinese Espionage Group in the Spotlight](https://symantec-enterprise-blogs.security.com/threat-intelligence/apt41-indictments-china-espionage)
- **September 16, 2020** – **U.S. Department of Justice**: [Seven International Cyber Defendants, Including “Apt41” Actors, Charged In Connection With Computer Intrusion Campaigns Against More Than 100 Victims Globally](https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer) (**ATTRIBUTION**)
  - Indictment: [United States of America v. Zhang Haoran, Tan Dailin](https://www.justice.gov/opa/press-release/file/1317216/dl) (PDF)
- **September 16, 2020** – **FBI FLASH**: [Indictment of China-Based Cyber Actors Associated with APT 41 for Intrusion Activities](https://www.ic3.gov/Media/News/2020/201103-2.pdf) (PDF)
- **June 11, 2020** – **Zscaler**: [The Return of the Higaisa APT](https://www.zscaler.com/blogs/security-research/return-higaisa-apt)
- **June 04, 2020** – **Malwarebytes**: [New LNK attack tied to Higaisa APT discovered](https://www.threatdown.com/blog/higaisa/)
- **May 21, 2020** – **ESET**: [No “Game over” for the Winnti Group](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/)
- **May 06, 2020** – **Trend Micro**: [Targeted Ransomware Attack Hits Taiwan Organizations](https://www.trendmicro.com/en_us/research/20/e/targeted-ransomware-attack-hits-taiwanese-organizations.html)
- **April 20, 2020** – **QuoIntelligence**: [WINNTI GROUP: Insights From the Past](https://quointelligence.eu/2020/04/winnti-group-insights-from-the-past/)
- **April 13, 2020** – **Unit 42**: [APT41 Using New Speculoos Backdoor to Target Organizations Globally](https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/)
- **March 25, 2020** – **FireEye**: [This Is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits](https://cloud.google.com/blog/topics/threat-intelligence/apt41-initiates-global-intrusion-campaign-using-multiple-exploits)
- **February ??, 2020** – **PwC**: [Cyber Threats 2019: A Year in Retrospect](https://www.pwc.co.uk/cyber-security/assets/cyber-threats-2019-retrospect.pdf) (PDF, page 10)
- **January 31, 2020** – **ESET**: [Winnti Group targeting universities in Hong Kong](https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/)
- **January 31, 2020** – **Tagesschau** (German news): [Deutsches Chemieunternehmen gehackt](https://web.archive.org/web/20200131231012/https://www.tagesschau.de/investigativ/ndr/hackerangriff-chemieunternehmen-101.html) (German language, archived link)

### 2019

- **October 31, 2019** – **FireEye**: [MESSAGETAP: Who’s Reading Your Text Messages?](https://cloud.google.com/blog/topics/threat-intelligence/messagetap-who-is-reading
