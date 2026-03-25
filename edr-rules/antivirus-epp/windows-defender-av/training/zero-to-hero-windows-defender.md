# Windows Defender Antivirus Zero-to-Hero Guide

## 1. Introduction
Microsoft Defender Antivirus is the built-in EPP for Windows 10/11 and Server. It provides real-time protection, cloud-delivered protection, ASR rules, controlled folder access, and tamper protection.

## 2. Key Features
- **Real-time protection** - Continuous file/process monitoring
- **Cloud-delivered protection (MAPS)** - Cloud ML analysis
- **Attack Surface Reduction (ASR)** - 16+ behavior-blocking rules
- **Controlled Folder Access** - Ransomware protection
- **Network Protection** - Block connections to malicious domains
- **Tamper Protection** - Prevent disabling Defender

## 3. PowerShell Management
```powershell
# Check status
Get-MpComputerStatus

# Update definitions
Update-MpSignature

# Run quick scan
Start-MpScan -ScanType QuickScan

# Run full scan
Start-MpScan -ScanType FullScan

# Add exclusion (use sparingly!)
Add-MpPreference -ExclusionPath "C:\DevTools"
Add-MpPreference -ExclusionProcess "myapp.exe"

# Enable cloud protection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable tamper protection (GPO or Intune recommended)
# Cannot be set via PowerShell when tamper protection is on

# View threat history
Get-MpThreatDetection | Select-Object -First 10
```

## 4. Attack Surface Reduction (ASR) Rules

### Key ASR Rules
| GUID | Rule | Recommendation |
|------|------|---------------|
| `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Block Office from creating child processes | Enable (Block) |
| `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | Block credential stealing from LSASS | Enable (Block) |
| `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Block executable content from email | Enable (Block) |
| `d1e49aac-8f56-4280-b9ba-993a6d77406c` | Block process creation from PSExec/WMI | Audit first |
| `3b576869-a4ec-4529-8536-b80a7769e899` | Block Office from creating executable content | Enable (Block) |
| `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` | Block Office from injecting into other processes | Enable (Block) |
| `d3e037e1-3eb8-44c8-a917-57927947596d` | Block JS/VBS from launching downloaded content | Enable (Block) |
| `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Block execution of potentially obfuscated scripts | Audit first |
| `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` | Block Win32 API calls from Office macros | Audit first |
| `01443614-cd74-433a-b99e-2ecdc07bfc25` | Block executable files that don't meet criteria | Audit first |
| `c1db55ab-c21a-4637-bb3f-a12568109d35` | Block use of copied/impersonated system tools | Audit first |
| `26190899-1602-49e8-8b27-eb1d0a1ce869` | Block Office from creating child processes via COM | Enable (Block) |
| `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` | Block Adobe Reader from creating child processes | Enable (Block) |
| `e6db77e5-3df2-4cf1-b95a-636979351e5b` | Block persistence through WMI event subscription | Enable (Block) |
| `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | Block untrusted/unsigned processes from USB | Enable (Block) |
| `56a863a9-875e-4185-98a7-b882c64b5ce5` | Block abuse of exploited vulnerable signed drivers | Enable (Block) |

### Deploying ASR Rules
```powershell
# Audit mode (recommended first)
Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions AuditMode

# Block mode
Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled

# Check current state
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

### ASR Deployment Strategy
1. **Week 1-2**: Enable ALL rules in Audit mode
2. **Week 3-4**: Review audit events, identify FPs, create exclusions
3. **Week 5+**: Switch low-risk rules to Block mode
4. **Ongoing**: Monitor, tune, enable remaining rules

## 5. Controlled Folder Access
```powershell
# Enable (protects Documents, Desktop, Pictures, etc.)
Set-MpPreference -EnableControlledFolderAccess Enabled

# Add protected folder
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\CriticalData"

# Allow specific app through
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\MyApp\myapp.exe"
```

## 6. Custom Indicators
```powershell
# Via MDE portal or API - block specific hashes/IPs/URLs
# Security Center → Settings → Indicators → Add
# Type: File hash, IP, URL, Certificate
# Action: Allow, Audit, Warn, Block
```

## 7. Group Policy Configuration
```
Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus
  ├── Real-time Protection
  │   ├── Turn on behavior monitoring: Enabled
  │   └── Scan all downloaded files and attachments: Enabled
  ├── MAPS
  │   ├── Join Microsoft MAPS: Advanced
  │   └── Send file samples when further analysis required: Send all samples
  ├── Attack Surface Reduction
  │   └── Configure Attack Surface Reduction rules: [GUIDs + Actions]
  └── Scan
      └── Specify maximum percentage of CPU utilization: 50
```

## 8. Labs
### Lab 1: ASR Rules Deployment
1. Enable all ASR rules in Audit mode
2. Run normal workload for 1 week
3. Review events in Event Viewer (ID 1121, 1122)
4. Create exclusions for FPs
5. Switch to Block mode

### Lab 2: Controlled Folder Access
1. Enable CFA
2. Attempt to modify protected folder from unauthorized app
3. Verify block and alert

---
*Compatible with Windows 10/11 and Server 2016+ | Last updated March 2026*
