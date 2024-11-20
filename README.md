# APT Matrix

## Overview

**APT Matrix** is an open-source resource that provides structured intelligence on Advanced Persistent Threat (APT) groups, currently focusing on those active in or targeting the Middle East. This project began as a submission for Black Hat MEA 2024 and aims to expand globally in the future, continually enhancing and updating the matrix to support a broader scope of threat intelligence needs.

The matrix addresses the lack of accessible, unified tools that map TTPs and observed behaviors of APT groups, particularly those of regional focus, and is designed to assist CTI analysts, cybersecurity specialists, and SOC teams in effective threat attribution and analysis.

## Purpose and Use Cases

This matrix serves as a centralized resource for:
- **Threat Attribution**: Mapping TTPs and behavioral patterns to specific APT groups.
- **SOC Integration**: Assisting SOC teams with intelligence for alerting and threat detection.
- **Incident Analysis**: Providing historical context to support rapid incident response.

## APT Groups Included

| #  | Group Name               | Origin Country | Link to Profile                                   |
|----|---------------------------|----------------|---------------------------------------------------|
| 1  | MuddyWater               | Iran           | [MuddyWater Profile](./matrix_data/MuddyWater/data.md) |
| 2  | OilRig (APT34)           | Iran           | [OilRig Profile](./matrix_data/OilRig/data.md)         |
| 3  | Charming Kitten (APT35)  | Iran           | [Charming Kitten Profile](./matrix_data/CharmingKitten/data.md) |
| 4  | Earth Baku (APT41)       | China          | [Earth Baku Profile](./matrix_data/EarthBaku/data.md)  |
| 5  | Fancy Bear (APT28)       | Russia         | [Fancy Bear Profile](./matrix_data/FancyBear/data.md)  |
| 6  | Cozy Bear (APT29)        | Russia         | [Cozy Bear Profile](./matrix_data/CozyBear/data.md)    |

## Repository Structure

This repository is organized into the following components:

- **Root Directory**: Contains this README with essential information and links.
- **matrix_data/**: Houses subdirectories for each APT group, with each group’s data stored in a `data.md` file that details TTPs, tools, targeted sectors, campaigns, and references.

## Example Group Profile Structure

Each APT group profile in `matrix_data/` follows a standardized format for consistency. Sections typically include:
1. **Basic Information**: Origin, targeted sectors, motivation, and linked organizations.
2. **Aliases**: Known aliases and sources.
3. **Targeting**: Targeted countries and sectors.
4. **Description**: Summary of the group’s known activities and behavior.
5. **Tools Used**: List of tools, malware families, and exploits.
6. **Exploited Vulnerabilities**: CVEs associated with the group’s campaigns.
7. **Campaigns**: Notable campaigns, with brief descriptions.
8. **TTP Matrix**: Common TTPs used by the group.
9. **Patterns and Observed Behaviors**: Behavioral insights and observed patterns.
10. **Activity Over Time**: Timeline of known activities and operations.
11. **References**: Links to sources and research articles.

## Future Development

While the current focus is on Middle Eastern APT groups, the goal is to incrementally expand this matrix to cover APTs from other regions, enhancing its value as a global OSINT resource. 

## Acknowledgments

Big thanks to the **Black Hat MEA 2024** community for the inspiration – and to **Ali, the GOAT,** for the awesome idea that started it all!
