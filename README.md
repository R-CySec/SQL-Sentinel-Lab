# SQL-Sentinel-Lab
---
## 🖥️Lab Environment & Technical Scope

**Environment Context:** Built and configured within a custom Microsoft Azure virtual lab following architecture guidance from Log(N) Pacific.

**Core Competencies & Knowledge Demonstrated:**

- **Cross-Layer Telemetry Synthesis:** Correlated database-level audit logs (MySQLAudit_CL) with host-level Microsoft Defender for Endpoint (MDE) Live Response forensic packages to establish root cause and incident scope.

- **Host Forensic Differential Analysis:** Conducted baseline vs. post-breach differential analysis across active network sockets, process execution lists, service definitions, Autoruns, Prefetch files, and extracted Windows Security Event telemetry to prove zero host OS compromise.g

- **Log Analytics & Threat Hunting:** Authored KQL queries to isolate external brute-force patterns, identify exfiltrated database objects, and extract actionable Indicators of Compromise (IOCs).

- **Attack Surface Reduction (ASR) & Remediation:** Implemented an outside-in perimeter hardening workflow using Azure Network Security Groups (NSGs), host firewalls, local account purges, and network access restrictions.

- **Technical & Executive Documentation:** Translated complex telemetry into a structured enterprise incident response report detailing timeline, impact assessment, containment, and recommendations.
---
# Incident Response Report: Data Extortion & Database Ransomware Event

## Executive Summary
Between August 24 and August 26, 2026, a threat actor successfully compromised the database server `oak-sd-fs01` by brute-forcing exposed remote MySQL ports. After gaining root access, the attacker exfiltrated multiple production databases, dropped them to cause total data loss, and left a database-level ransom note named `recover_your_data`.

Parallel host forensic analysis using Microsoft Defender for Endpoint (MDE) Live Response packages (`Pre-Breach` vs. `Post-Breach`) confirmed external authentication activity and an established RDP connection attempt. However, DFIR telemetry verified that no host OS compromise, persistence installation, unauthorized process execution, or lateral movement occurred. Attacker impact was strictly confined to the database layer.

The incident was successfully mitigated following system isolation, host malware scanning, local administrative account purging, local firewall and Network Security Group (NSG) perimeter hardening, and the complete disallowance of public MySQL network logons.

---
## Incident Details
* **Detection Date/Time:** August 26, 2026 (Investigation Window: Aug 24 - Aug 26, 2026)
* **Classification:** Data Extortion / Database Ransomware (Critical Severity)
* **Affected Systems:** `oak-sd-fs01` (MySQL Database Server)
* **DFIR Telemetry Baseline:** `Pre-Breach Investigation Pacakge.zip` (Collected: ~2026-08-24 10:08:47Z)
* **DFIR Telemetry Comparison:** `Post-Breach Investigation Package.zip` (Collected: ~2026-08-26 08:25:25Z)

### KQL Hunt Query (Affected Host Verification)
```kusto
MySQLAudit_CL
| distinct "oak-sd-fs01"
````

![[Pasted image 20260827103056.png]]

## Impact Assessment

- **Confidentiality:** Compromised. The threat actor executed `SELECT *` statements across core database tables (i.e., `store`, `staff_list`, `city`, `country`) to exfiltrate proprietary data.
- **Integrity:** Severely Impacted. Multiple production databases (`sakila`, `world`, `oak_corp_01`) were completely dropped by the attacker.
- **Availability:** Critical Loss. Dropped databases caused operational downtime for services reliant on `oak-sd-fs01`.
- **Host Operating System:** Not Compromised. MDE differential artifact analysis confirmed zero unauthorized local account creations, zero malicious services, and zero unapproved executable executions on the underlying Windows host.
- **Business Impact:** High. Data theft combined with service interruption caused immediate risk of compliance breaches and operational disruption prior to containment.

### KQL Hunt Query (Impact Assessment and IOC Extraction)

```
let START_TIME = todatetime("2026-08-24T09:53:54.8094584Z");
let END_TIME = todatetime("2026-08-26T09:04:28.7383427Z");

// SQL Server
let MyDevice = "oak-sd-fs01";
let FailedConnections =

MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;

MySQLAudit_CL
| where TimeGenerated between (START_TIME .. END_TIME)
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend RawData = replace_string(RawData, "\t", " ")
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```

![[Pasted image 20260827103755.png]]

![[Pasted image 20260827103818.png]]

## Host & Endpoint Forensic Analysis

Differential forensic analysis between the pre-breach baseline and post-breach MDE packages yielded the following artifact breakdown:

- **Network & Remote Access (RDP):** An established RDP connection was identified in the post-breach telemetry (`10.2.0.15:3389` ← `160.30.160.205:58149`). The baseline package recorded only internal RDP traffic (`10.0.8.11:32824`).
    
- **Host Authentication Logs:** Security event logs captured broad external NTLM authentication failures targeting OS-level accounts (`Administrator`, `USER`, `SYSTEM`, `AZUREUSER`) from multiple public IPs (`160.30.160.205`, `144.76.201.165`, `14.23.40.253`, `80.94.95.83`, `45.40.82.16`). Telemetry confirms these host OS logons failed or produced no successful host-level shell access.
    
- **Persistence & Autoruns:** No malicious persistence mechanisms were established. Scheduled tasks remained unchanged at 302 tasks. HKU Run key variations were evaluated as benign user-hive session differences.
    
- **Execution & Processes:** No malicious executables, web shells, or unauthorized processes were identified. Process additions were limited to standard system binaries (`sppsvc.exe` - Windows Software Protection service).
    
- **Prefetch & Services:** 26 new Prefetch entries were generated, all correlating with normal Windows, MDE, and collection activities. Core system services and local group memberships remained unchanged.
    
**Conclusion:** Host telemetry proves attackers failed to pivot from the database service to the Windows operating system.

## Indicators of Compromise

|**Type**|**Indicator**|**Description / Context**|
|---|---|---|
|**IP Address**|`213.209.159.115`|External source of database brute-force and successful `root` login.|
|**IP Address**|`77.90.185.30`|External source of repeated database brute-force and successful `root` logins (Aug 24 & Aug 26).|
|**IP Address**|`64.89.163.77`|Initial access IP (Aug 24) that executed initial `root` login, exfiltration, and DROP DATABASE queries.|
|**IP Address**|`77.90.185.21`|External source of database brute-force logins.|
|**IP Address**|`160.30.160.205`|External source of established RDP connection and host `Administrator` authentication attempts.|
|**IP Address**|`144.76.201.165`|External source of NTLM authentication attempts against host OS accounts.|
|**IP Address**|`14.23.40.253`|External source of NTLM authentication attempts against host OS accounts.|
|**IP Address**|`80.94.95.83`|External source of NTLM authentication attempts against host OS accounts.|
|**IP Address**|`45.40.82.16`|External source of NTLM authentication attempts against host OS accounts.|
|**Database**|`recover_your_data`|Extortion table created on the server by the attacker.|
|**URL**|`http://spoo[.]me/mysql`|Site found in ransom note.|
|**E-mail**|`ak+24gld@onionmail.org`|Threat actor email found in ransom note.|
|**Bitcoin Wallet**|`bc1qxlczqha6s7kcdlyaky27h75jzv8tmfgqtrcvfw`|Bitcoin address found in ransom note.|
|**Ransom Victim ID**|`24GLD`|Victim ID found in ransom note.|

## Timeline

- **August 24, 2026 10:08:47 AM UTC:** Pre-Breach MDE Live Response package collection initiated (`Pre-Breach Investigation Pacakge.zip`) establishing baseline host state.
    
- **August 24, 2026 12:59:43 PM UTC:** Threat actor initiated access from IP `64.89.163.165` with a failed `root` login attempt (`SQL Audit Query.csv`).
    
- **August 24, 2026 12:59:53 PM UTC:** **[Initial Access]** Threat actor successfully authenticated as `root` from IP `64.89.163.165` via TCP/IP (`SQL Audit Query.csv`).
    
- **August 24, 2026 01:00:00 PM - 01:00:34 PM UTC:** Threat actor executed `SELECT *` exfiltration commands across `store`, `staff_list`, `city`, and `country` tables, followed by `DROP DATABASE` queries against `oak_corp_01`, `world`, and `sakila` (`SQL Server Queries.csv`).
    
- **August 24, 2026 04:11:08 PM - 11:16:11 PM UTC:** Subsequent brute-force probes and successful `root` logons occurred from IPs `77.90.185.30` and `77.90.185.21` (`SQL Audit Query.csv`).
    
- **August 25 - August 26, 2026:** Database server remained exposed over the public internet during the lab testing period, leading to ongoing automated external probe attempts.
    
- **August 26, 2026 08:25:25 AM UTC:** Post-Breach MDE Live Response package collection initiated (`Post-Breach Investigation Package.zip`), capturing external NTLM attempts and established RDP connection state from `160.30.160.205`.
    
- **August 26, 2026 09:02:50 AM - 09:51:10 AM UTC:** Secondary wave of external brute-force login attempts occurred from IPs `213.209.159.115` and `77.90.185.30` targeting `sa`, `admin`, and `root` accounts (`SQL Audit Query.csv`).
    
- **August 26, 2026 10:43:40 AM UTC:** Attacker queried the extortion database/table `recover_your_data` (`SQL Server Queries.csv`).
    
- **August 26, 2026:** SOC Analyst isolated host and initiated full containment, eradication, and recovery workflow.
## Root Cause / Attack Vector

The primary attack vector was an externally exposed MySQL service on `oak-sd-fs01` running over the public internet without IP access controls. The attacker conducted password brute-forcing against common management accounts (`sa`, `admin`, `root`) until gaining administrative access to the database engine. Concurrent external scanning targeting exposed Remote Desktop Protocol (RDP) services was also detected at the network boundary.

### KQL Hunt Query (Attack Vector Verification)

```
let START_TIME = todatetime("2026-08-24T09:53:54.8094584Z");
let END_TIME = todatetime("2026-08-26T09:04:28.7383427Z");
//MySQL Server Filtering Queries
let MyDevice = "oak-sd-fs01"; // set your own device name
MySQLAudit_CL
| where TimeGenerated between (START_TIME .. END_TIME)
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| extend ActionType = "Query"
| extend Query = split(RawData, "Query")[1]
| project TimeGenerated, DeviceName, ActionType, Query, RawData
| order by TimeGenerated desc
```

![[Pasted image 20260828115529.png]]

## Response Actions

- **Containment:**
    - Isolated the VM from the network to halt ongoing unauthorized activity and block exfiltration.
- **Eradication:**
    - **System Malware Scan:** Executed a full malware scan using Windows Defender to verify that no persistence mechanism, web shells, or secondary malware were left behind.
    - **Default Account Purge:** Removed the local `administrator` account via Computer Management (`compmgmt.msc`).
    - **Guest Account Status:** Disabled `Guest` account.
    - **Local Account Hardening:** Enforced strong, high-entropy password credentials for active local accounts, based on [NIST 2025 Guidance](https://www.nist.gov/cybersecurity-and-privacy/how-do-i-create-good-password).
    - **MySQL Administrative Security:** Disabled the network-accessible MySQL `root` account.
- **Recovery & System Hardening (Outside-In Control):**
    - **NSG Perimeter Hardening:** Hardened the VM’s Network Security Group (NSG) to block untrusted external inbound database access.
    - **Host Firewall Activation:** Enabled Windows Firewall (`wf.msc`) for localized access control.
    - **Disallow Public MySQL Logons:** Blocked external logons to the MySQL Server over the public internet.
    - **System Operational Restoration:** Powered on the VM and removed the VM from isolation after completing all security checks.
## Evidence

| **File Name**                           | **Details**                                                                                                   | **Date**    |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ----------- |
| `SQL Audit Query.csv`                   | Log of authentication events showing external brute-forcing and unauthorized root connections.                | Aug-26-2026 |
| `SQL Server Queries.csv`                | Log of executed database queries showing data selection, table drops, and ransom table verification[cite: 3]. | Aug-26-2026 |
| `DeviceLogonEvents.csv`                 | Host logon events analyzed to isolate network authentication vectors[cite: 3].                                | Aug-26-2026 |
| `Pre-Breach Investigation Pacakge.zip`  | MDE Live Response Baseline package collected prior to database exfiltration (~10:08:47Z).                     | Aug-24-2026 |
| `Post-Breach Investigation Package.zip` | MDE Live Response Post-incident package collected following compromise (~08:25:25Z)[cite: 5].                 | Aug-26-2026 |
| `Security.evtx`                         | Windows Security Event Log extracted from MDE package showing external NTLM logon failures[cite: 5].          | Aug-26-2026 |
| `ActiveNetConnections.txt`              | Network socket state showing established RDP connection from `160.30.160.205`[cite: 5].                       | Aug-26-2026 |

## Lessons Learned / Recommendations

1. **Enforce Zero Public Database Exposure:** Disallow direct public internet routing to port 3306 via NSGs and host firewalls.
2. **Restrict Remote Management Access (RDP):** Block direct public internet access to RDP (port 3389) via NSG rules, requiring VPN with MFA for remote administration.
3. **Hardened Base Image Standards:** Automatically remove or disable standard default accounts (`administrator`, `Guest`) across all newly provisioned systems.
4. **Database Remote Access Restrictions:** Disable remote `root` logins entirely, requiring local socket connections or encrypted VPN tunnels for management.
5. **Automated Brute-Force Blocking:** Deploy automated lockouts and IP blocklists to suppress high-frequency failed logon attempts across both database and OS authentication endpoints.

