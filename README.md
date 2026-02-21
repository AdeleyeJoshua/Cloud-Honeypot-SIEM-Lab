#  Azure Cloud Honeypot & SIEM (Microsoft Sentinel) Lab

##  Overview
In this project, I deployed a deliberately vulnerable Windows Virtual Machine in Microsoft Azure to act as a honeypot, attracting live cyberattacks from around the world. I configured Azure Log Analytics and Microsoft Sentinel (SIEM) to ingest the security logs, utilizing Kusto Query Language (KQL) to map the attacker's IPs to geographic locations and visualize the threat data in real-time.

Over a 48-hour period, the honeypot captured and analyzed over **55,000 failed RDP login attempts**.


<img width="1361" height="734" alt="Screenshot 2026-02-14 152307" src="https://github.com/user-attachments/assets/0d5f117d-ca96-4379-a447-fe963244d274" />

##  Tech Stack & Skills Highlighted
- **Cloud Infrastructure:** Microsoft Azure (Virtual Machines, Network Security Groups)
- **SIEM & Log Management:** Microsoft Sentinel, Log Analytics Workspace
- **Data Analysis & Querying:** Kusto Query Language (KQL)
- **Security Concepts:** Threat Intelligence, Honeypots, RDP Brute Force, Incident Detection

##  Architecture & Implementation
1. **Infrastructure as a Target:** Deployed a Windows 10 VM in Azure. Disabled the local firewall and configured the Network Security Group (NSG) to allow all inbound traffic (specifically RDP on port 3389) to make it highly discoverable.
2. **Log Aggregation:** Connected the VM to a Log Analytics Workspace to collect Windows Security Events (specifically Event ID 4625: Failed Logon).
3. **Data Enrichment:** Imported a GeoIP database via Sentinel Watchlists to map incoming attacker IP addresses to their physical country locations.
4. **Threat Visualization:** Wrote custom KQL queries to parse the raw log data and populate an interactive Attack Map Dashboard in Microsoft Sentinel.
5. **Incident Response:** Configured analytic rules in Microsoft Defender to trigger high-severity alerts upon detecting brute-force thresholds, ultimately isolating the most aggressive threat actors via NSG rules.

<img width="1364" height="685" alt="Screenshot 2026-02-14 143648" src="https://github.com/user-attachments/assets/057b96ba-e171-4b3f-a367-fb65b2423b9c" />


##  The Telemetry & Findings
Within minutes of exposure, automated botnets discovered the server. Here is the 48-hour breakdown:
* **Total Failed Logins:** 55,322
* **Attacker Origins:** 23 unique countries represented
* **Top Attacking Country:** The Netherlands (21,280 attempts)

<img width="1365" height="653" alt="Screenshot 2026-02-14 152900" src="https://github.com/user-attachments/assets/f443455a-eb8c-454a-a29b-8ae5614bd96b" />


* **Targeted Accounts:** Dictionary attacks heavily utilized default usernames such as `\ADMINISTRATOR`, `\MANAGER`, `\USER1`, and `\BACKUP`.


<img width="1363" height="651" alt="Screenshot 2026-02-14 151759" src="https://github.com/user-attachments/assets/e16ea70e-1f84-453a-af20-6f7d53f750fd" />

##  Cloud Cost Analysis
One of the goals of this project was to build a highly capable SIEM environment utilizing cloud resources efficiently. Total cost of running the infrastructure for the 48-hour period: **$6.60**.

<img width="1365" height="651" alt="Screenshot 2026-02-14 150903" src="https://github.com/user-attachments/assets/a189f984-f07e-4b93-a156-f1cdc2ec215e" />


##  KQL Query Snippet
Here is a sample of the Kusto Query Language (KQL) used to join the security events with the GeoIP watchlist and aggregate the attacks by country:

```kusto
let GeoIPDB_FULL = _Getwatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize AttackCount = count() by IpAddress, countryname
| order by AttackCount desc
