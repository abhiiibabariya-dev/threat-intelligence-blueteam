# CrowdStrike Falcon Zero-to-Hero Training Guide

## 1. Introduction
CrowdStrike Falcon is a cloud-native endpoint protection platform (EPP/EDR) that uses AI and behavioral analysis for threat detection and response.

## 2. Architecture
- **Falcon Cloud** - SaaS management console, threat graph, AI/ML
- **Falcon Sensor** - Lightweight kernel-mode agent on endpoints
- **Threat Graph** - Petabyte-scale graph database correlating all events
- **Falcon X** - Integrated threat intelligence
- **Falcon Fusion** - Built-in SOAR automation

## 3. Sensor Deployment

### Windows
```powershell
# Silent install with CID
CsSetup.exe /install /quiet /norestart CID=<your-customer-id-with-checksum>

# Verify sensor
sc query csagent
REG QUERY "HKLM\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default" /v AG
```

### Linux
```bash
sudo dpkg -i falcon-sensor_7.0.0-1234_amd64.deb
sudo /opt/CrowdStrike/falconctl -s --cid=<CID>
sudo systemctl start falcon-sensor
sudo falconctl -g --rfm-state  # Verify running
```

## 4. Custom IOA Rules

IOA (Indicators of Attack) detect behavioral patterns:

```yaml
# Custom IOA: Encoded PowerShell Execution
rule_name: "Encoded PowerShell Command"
rule_type: process_creation
severity: high
mitre: T1059.001
conditions:
  image_filename: "powershell.exe|pwsh.exe"
  command_line:
    contains_any: ["-enc", "-EncodedCommand", "-ec"]
action: detect  # detect, detect_and_alert, block
description: "PowerShell executed with encoded command - possible malicious script"
```

### IOA Rule Types
| Type | Detects |
|------|---------|
| Process Creation | New process launch patterns |
| Network Connection | Outbound connections from processes |
| File Write | Suspicious file creation/modification |
| Registry Modification | Persistence via registry |
| DNS Request | Malicious domain lookups |

## 5. Falcon Query Language (FQL)

Used in Event Search and custom dashboards:

```
# Find encoded PowerShell
event_simpleName=ProcessRollup2 AND FileName="powershell.exe" AND CommandLine="*-enc*"

# LSASS access
event_simpleName=ProcessRollup2 AND TargetFileName="*lsass*" AND NOT FileName IN ("csrss.exe","svchost.exe")

# Lateral movement via PsExec
event_simpleName=ServiceStarted AND ServiceFileName="*PSEXESVC*"

# DNS queries to suspicious TLDs
event_simpleName=DnsRequest AND DomainName=("*.tk" OR "*.xyz" OR "*.top" OR "*.buzz")

# File writes to startup
event_simpleName=FileWritten AND FilePath="*\\Start Menu\\Programs\\Startup\\*"
```

## 6. Real Time Response (RTR)

Remote shell access to endpoints:

```bash
# Connect to host
rtr connect -d <device_id>

# List processes
ps

# Get file
get "C:\Users\victim\Desktop\ransom_note.txt"

# Kill process
kill <pid>

# Run script
runscript -CloudFile="CollectArtifacts"

# Network isolation
network contain
network uncontain
```

### RTR Scripts
```powershell
# Collect forensic artifacts
$artifacts = @(
    "$env:SystemRoot\System32\config\SAM",
    "$env:SystemRoot\System32\config\SYSTEM",
    "$env:USERPROFILE\NTUSER.DAT"
)
foreach ($a in $artifacts) {
    if (Test-Path $a) { Copy-Item $a -Destination "C:\CrowdStrike\Collection\" }
}
```

## 7. Falcon X Threat Intelligence

- **Indicators** - IOCs with context (malware family, actor, campaign)
- **Actors** - Threat actor profiles (BEAR=Russia, PANDA=China, KITTEN=Iran, SPIDER=eCrime)
- **Sandbox** - Automated malware analysis
- **Intel Reports** - Detailed threat analysis

## 8. Host Groups & Prevention Policies

```
Host Groups → Create:
  Name: "Domain Controllers"
  Assignment: Dynamic
  Filter: platform_name:"Windows" AND machine_domain:"corp.local" AND ou:"Domain Controllers"

Prevention Policy → Assign to group:
  - Malware: Aggressive
  - Behavioral: Moderate
  - Script: Block suspicious
  - Exploit: Enabled
```

## 9. API (OAuth2)

```bash
# Get token
TOKEN=$(curl -X POST 'https://api.crowdstrike.com/oauth2/token' \
  -d 'client_id=xxx&client_secret=yyy' | jq -r '.access_token')

# Search hosts
curl -H "Authorization: Bearer $TOKEN" \
  'https://api.crowdstrike.com/devices/queries/devices/v1?filter=hostname:"DC01"'

# Get detections
curl -H "Authorization: Bearer $TOKEN" \
  'https://api.crowdstrike.com/detects/queries/detects/v1?filter=status:"new"'

# Contain host
curl -X POST -H "Authorization: Bearer $TOKEN" \
  'https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain' \
  -d '{"ids":["device_id"]}'
```

## 10. Falcon Fusion (SOAR)

Built-in workflow automation:
- Trigger: Detection, incident, or scheduled
- Actions: Contain host, notify, run RTR script, create ticket, update detection
- Conditions: Severity, tactic, host group, time of day

## 11. Use Cases & Hunting Queries

```
# Hunt: Mimikatz variants
event_simpleName=ProcessRollup2 AND (CommandLine="*sekurlsa*" OR CommandLine="*kerberos::list*" OR ImageFileName="*mimikatz*")

# Hunt: Living off the land
event_simpleName=ProcessRollup2 AND ParentBaseFileName IN ("winword.exe","excel.exe") AND FileName IN ("cmd.exe","powershell.exe","mshta.exe")

# Hunt: Persistence via services
event_simpleName=ServiceStarted AND ServiceFileName=("*\\temp\\*" OR "*\\appdata\\*" OR "*cmd.exe*" OR "*powershell*")
```

## 12. Labs

### Lab 1: Deploy Sensor & Verify
1. Install sensor on Windows VM
2. Verify in Falcon console
3. Assign to host group and prevention policy

### Lab 2: Create Custom IOA
1. Create IOA rule for encoded PowerShell
2. Set to detect (not block) initially
3. Run test command on endpoint
4. Verify detection in console

### Lab 3: RTR Investigation
1. Connect to endpoint via RTR
2. List running processes
3. Collect suspicious files
4. Examine network connections

---
*Compatible with CrowdStrike Falcon | Last updated March 2026*
