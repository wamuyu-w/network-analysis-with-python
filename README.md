# 📊 Threat Intelligence IP Analyzer

This project performs geolocation and threat intelligence analysis on a list of malicious IP addresses using:

- [AbuseIPDB](https://www.abuseipdb.com/)
- [VirusTotal](https://www.virustotal.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- MITRE ATT&CK Mapping (via OTX tags)

## 🔍 Features

- Queries malicious IPs from AbuseIPDB, VirusTotal, and AlienVault OTX.
- Extracts and correlates:
  - Abuse confidence score
  - VirusTotal malicious detection count
  - MITRE ATT&CK Techniques (from OTX tags)
  - Malware families, threat tags, references, and WHOIS data
- Outputs results to a CSV (`IP_ANALYSIS.csv`) for further analysis.

## 📁 Example Output

| IP            | AbuseIPDB Score | VirusTotal Malicious Count | Malware Families | Threat Tags     | MITRE IDs      | WHOIS Country | WHOIS Email        |
|---------------|------------------|-----------------------------|------------------|------------------|----------------|----------------|---------------------|
| 27.81.7.52    | 85               | 12                          | Emotet, Trickbot | botnet, trojan   | T1071, T1059   | RU             | example@mail.com    |


## However, for version one, all OTX data is displayed and not grouped into specific tags

## Current Output
| IP            | AbuseIPDB Score  | VirusTotal Malicious Count  | OTX Data                | 
|---------------|------------------|-----------------------------|-------------------------|
| 27.81.7.52    | 85               | 12                          | Emotet, Trickbot        | 
