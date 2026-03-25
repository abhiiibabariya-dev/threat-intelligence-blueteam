# Threat Hunting Playbooks

## Methodology: Hypothesis-Driven Hunting

```
1. Form Hypothesis → 2. Plan Data Sources → 3. Execute Queries → 4. Analyze Results → 5. Document Findings → 6. Create Detection Rules
```

---

## Hunt 1: Ransomware Pre-Encryption Activity

**Hypothesis:** An attacker is staging for ransomware deployment by deleting shadow copies and disabling recovery.

**Data Sources:** Endpoint process logs, Sysmon, Windows Security Events

**Splunk SPL:**
```spl
index=sysmon EventCode=1
(CommandLine="*vssadmin*delete*shadow*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*/set*recoveryenabled*no*" OR CommandLine="*wbadmin*delete*catalog*")
| stats count by Computer, User, CommandLine, ParentImage
| sort -count
```

**Sentinel KQL:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete","bcdedit /set recoveryenabled no","wbadmin delete catalog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

---

## Hunt 2: APT Persistence via Scheduled Tasks

**Hypothesis:** An APT actor has established persistence through scheduled tasks executing from unusual paths.

**Splunk SPL:**
```spl
index=wineventlog EventCode=4698
| rex field=TaskContent "<Command>(?<task_command>[^<]+)</Command>"
| where match(task_command, "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\programdata\\\\|http|powershell|cmd\.exe)")
| table _time, Computer, SubjectUserName, TaskName, task_command
```

**Sentinel KQL:**
```kql
SecurityEvent
| where EventID == 4698
| extend TaskCommand = extract("<Command>(.*?)</Command>", 1, EventData)
| where TaskCommand matches regex @"(?i)(\\temp\\|\\appdata\\|http|powershell)"
| project TimeGenerated, Computer, SubjectUserName, TaskCommand
```

---

## Hunt 3: Living-off-the-Land (LOLBAS) Attacks

**Hypothesis:** Attackers are using legitimate Windows binaries for malicious downloads and execution.

**Splunk SPL:**
```spl
index=sysmon EventCode=1
(Image="*\\certutil.exe" CommandLine="*-urlcache*")
OR (Image="*\\bitsadmin.exe" CommandLine="*/transfer*")
OR (Image="*\\mshta.exe" CommandLine="*http*")
OR (Image="*\\regsvr32.exe" CommandLine="*/i:*scrobj*")
OR (Image="*\\rundll32.exe" CommandLine="*javascript*")
| stats count by Image, CommandLine, ParentImage, Computer, User
```

---

## Hunt 4: Lateral Movement via Admin Shares

**Hypothesis:** An attacker is moving laterally using admin shares (C$, ADMIN$) from a compromised workstation.

**Splunk SPL:**
```spl
index=wineventlog EventCode=5140 ShareName IN ("\\\\*\\ADMIN$", "\\\\*\\C$")
| stats dc(Computer) as unique_targets, values(Computer) as targets by IpAddress, SubjectUserName
| where unique_targets > 2
| sort -unique_targets
```

---

## Hunt 5: C2 Beaconing Detection

**Hypothesis:** Malware on internal hosts is beaconing to C2 servers at regular intervals.

**Splunk SPL:**
```spl
index=proxy
| bin _time span=10m
| stats count by src_ip, dest_ip, dest_port, _time
| streamstats window=12 current=f stdev(count) as std, avg(count) as avg by src_ip, dest_ip
| where std < 2 AND avg > 0
| stats count as beacon_intervals, avg(avg) as avg_requests by src_ip, dest_ip, dest_port
| where beacon_intervals > 10
| sort -beacon_intervals
```

---

## Hunt 6: Credential Harvesting (LSASS Access)

**Hypothesis:** Tools like Mimikatz are accessing LSASS memory to extract credentials.

**Splunk SPL:**
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010", "0x1038", "0x1fffff", "0x143a")
NOT SourceImage IN ("*\\csrss.exe", "*\\svchost.exe", "*\\MsMpEng.exe", "*\\lsass.exe")
| stats count by SourceImage, GrantedAccess, Computer
```

---

## Hunt 7: DNS Tunneling

**Hypothesis:** An attacker is exfiltrating data or maintaining C2 through DNS tunneling.

**Splunk SPL:**
```spl
index=dns
| eval query_len=len(query)
| where query_len > 50
| stats count as queries, avg(query_len) as avg_len, dc(query) as unique_queries by src_ip, query_type
| where queries > 100 AND avg_len > 40
```

---

## Hunt 8: Insider Data Theft

**Hypothesis:** A departing employee is downloading sensitive files in bulk before their last day.

**Splunk SPL:**
```spl
index=dlp OR index=proxy
| where action IN ("download", "copy", "upload")
| stats sum(bytes) as total_bytes, dc(filename) as unique_files, values(dest) as destinations by user
| where total_bytes > 1073741824 OR unique_files > 500
| sort -total_bytes
```

---

## Hunt 9: Kerberoasting Activity

**Hypothesis:** An attacker is requesting TGS tickets with RC4 encryption to crack service account passwords.

**Splunk SPL:**
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type IN ("0x17", "0x18")
NOT ServiceName="krbtgt" NOT ServiceName="*$"
| stats count as tgs_requests, dc(ServiceName) as unique_services by Account_Name, Client_Address
| where tgs_requests > 5 OR unique_services > 3
```

---

## Hunt 10: Cloud Infrastructure Abuse

**Hypothesis:** Compromised cloud credentials are being used to spin up crypto mining instances.

**Sentinel KQL:**
```kql
AzureActivity
| where OperationNameValue has_any ("MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "Microsoft.Compute/virtualMachines/write")
| where ActivityStatusValue == "Success"
| summarize VMsCreated = count(), VMSizes = make_set(tostring(parse_json(Properties).responseBody.properties.hardwareProfile.vmSize)) by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where VMsCreated > 3
```

---

## Hunt 11: Supply Chain - Unusual Update Behavior

**Hypothesis:** Legitimate software has been trojanized and is making unusual network connections after updating.

**Splunk SPL:**
```spl
index=sysmon EventCode=3
| where NOT match(DestinationIp, "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)")
| stats dc(DestinationIp) as unique_dests, values(DestinationIp) as dest_ips by Image, Computer
| where unique_dests > 5
| search Image IN ("*\\solarwinds*", "*\\3cx*", "*\\codecov*")
```

---

## Hunt 12: Process Injection (CreateRemoteThread)

**Splunk SPL:**
```spl
index=sysmon EventCode=8
TargetImage IN ("*\\explorer.exe", "*\\svchost.exe", "*\\lsass.exe", "*\\winlogon.exe")
NOT SourceImage IN ("*\\csrss.exe", "*\\services.exe", "*\\svchost.exe")
| stats count by SourceImage, TargetImage, Computer
```

---

## Hunt Success Metrics
- Hunts completed per month: target 4+
- New detections created from hunts: target 2+ per quarter
- Unique MITRE techniques hunted: track coverage
- Time from hunt finding to detection rule: target <1 week
- True positives discovered: track all findings

---

*"Threat hunting is not about finding evil — it's about proving your detections work, or discovering they don't."*
