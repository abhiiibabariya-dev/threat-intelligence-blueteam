# Microsoft Defender for Endpoint Zero-to-Hero Training Guide

## 1. Introduction
Microsoft Defender for Endpoint (MDE) is Microsoft's enterprise EDR platform providing behavioral detection, automated investigation and remediation (AIR), threat & vulnerability management (TVM), and attack surface reduction (ASR).

## 2. Architecture
- **Cloud backend** - Microsoft 365 Defender portal
- **MDE Sensor** - Built into Windows 10/11, Server 2016+
- **Cloud-delivered protection** - Real-time ML analysis
- **EDR** - Behavioral detection and response
- **ASR** - Attack surface reduction rules

## 3. Onboarding Devices
```powershell
# Windows: Download onboarding package from Security Center
# Run the script
.\WindowsDefenderATPOnboardingScript.cmd

# Verify onboarding
sc query sense  # MsSense service should be running

# Check connectivity
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe" -t

# Linux
curl -o MicrosoftDefenderATPOnboardingLinuxServer.py https://...
python MicrosoftDefenderATPOnboardingLinuxServer.py
mdatp health
```

## 4. Advanced Hunting (KQL)

### Process Activity
```kql
// Encoded PowerShell execution
DeviceProcessEvents
| where FileName in ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "-enc"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc

// Office spawning suspicious child
DeviceProcessEvents
| where InitiatingProcessFileName in ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "certutil.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Network Activity
```kql
// Connections to rare external IPs
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize ConnectionCount = count(), Devices = dcount(DeviceName) by RemoteIP, RemotePort
| where ConnectionCount < 5 and Devices == 1
| sort by ConnectionCount

// C2 beaconing pattern
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize Connections = count(), TimeDiffs = make_list(datetime_diff('second', Timestamp, prev(Timestamp))) by DeviceName, RemoteIP, bin(Timestamp, 1h)
```

### File Activity
```kql
// Ransomware indicators - mass file rename
DeviceFileEvents
| where ActionType == "FileRenamed"
| summarize RenamedCount = count() by DeviceName, bin(Timestamp, 5m)
| where RenamedCount > 100
```

### Identity Events
```kql
// Impossible travel
IdentityLogonEvents
| where ActionType == "LogonSuccess"
| summarize Locations = make_set(Location), LocationCount = dcount(Location) by AccountName, bin(Timestamp, 1h)
| where LocationCount > 1
```

## 5. Custom Detection Rules

Create from Advanced Hunting query:
1. Run KQL query → verify results
2. Click "Create detection rule"
3. Configure: name, severity, MITRE mapping, frequency
4. Set alert actions: create incident, isolate device, collect investigation package

## 6. Attack Surface Reduction (ASR)

### Key ASR Rules
| Rule | GUID |
|------|------|
| Block Office apps from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block executable content from email | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` |
| Block process creations from PSExec/WMI | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |
| Block JavaScript/VBScript from launching downloads | `d3e037e1-3eb8-44c8-a917-57927947596d` |

```powershell
# Enable ASR rule (Audit mode)
Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions AuditMode

# Enable (Block mode)
Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled
```

## 7. Automated Investigation & Remediation (AIR)

AIR automatically investigates alerts and takes remediation actions:
- Quarantine file
- Stop process
- Remove persistence
- Isolate device
- Block URL/IP

Configure automation level per device group: Full, Semi (approval needed), None.

## 8. Live Response

```bash
# Connect to device
# From Security Center → Device → Initiate Live Response

# Collect investigation package
collect investigationpackage

# Run script
run PowerShellScript.ps1

# Get file for analysis
getfile "C:\Users\victim\AppData\Local\Temp\malware.exe"

# Remediate
remediate file sha256=abc123...
```

## 9. Threat & Vulnerability Management (TVM)

- **Exposure score** - Organization-wide vulnerability exposure
- **Secure score** - Security configuration posture
- **Software inventory** - All installed software + versions
- **Vulnerability list** - CVEs affecting your environment
- **Security recommendations** - Prioritized remediation actions

## 10. API

```bash
# Get token
TOKEN=$(curl -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d "client_id=$CLIENT_ID&scope=https://api.securitycenter.microsoft.com/.default&client_secret=$SECRET&grant_type=client_credentials" | jq -r '.access_token')

# List alerts
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.securitycenter.microsoft.com/api/alerts?$top=10"

# Isolate machine
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "https://api.securitycenter.microsoft.com/api/machines/$MACHINE_ID/isolate" \
  -d '{"Comment":"Investigating incident","IsolationType":"Full"}'
```

## 11. Labs

### Lab 1: Onboard & Hunt
1. Onboard Windows VM to MDE
2. Run `whoami /all`, `net user /domain`, encoded PowerShell
3. Hunt for these activities in Advanced Hunting

### Lab 2: ASR Rules
1. Enable Office child process block in Audit mode
2. Open Word → run macro that spawns cmd.exe
3. Review ASR audit events
4. Switch to Block mode and retest

### Lab 3: Custom Detection
1. Write KQL for encoded PowerShell
2. Create custom detection rule
3. Trigger and verify alert creation

---
*Compatible with MDE P2 | Last updated March 2026*
