# SentinelOne Zero-to-Hero Training Guide

## 1. Introduction
SentinelOne is an autonomous endpoint protection platform using AI-driven behavioral detection. Key features: Storyline (attack visualization), STAR rules (custom detection), Deep Visibility (threat hunting), and automated remediation/rollback.

## 2. Architecture
- **Management Console** - Cloud SaaS multi-tenant
- **Agent** - Kernel-mode + user-mode on endpoints (Windows, Linux, macOS, K8s)
- **Storyline** - Patented attack chain visualization linking related events
- **Static AI** - Pre-execution ML analysis
- **Behavioral AI** - Runtime behavioral detection

## 3. Agent Deployment
```powershell
# Windows silent install
SentinelOneInstaller.exe /SITE_TOKEN="eyJ..." /QUIET

# Linux
sudo dpkg -i SentinelAgent_linux_x86_64.deb
sudo /opt/sentinelone/bin/sentinelctl management token set "eyJ..."
sudo /opt/sentinelone/bin/sentinelctl control start

# Verify
sudo /opt/sentinelone/bin/sentinelctl management status
```

## 4. Deep Visibility (Threat Hunting)
SQL-like query interface for endpoint telemetry:

```sql
-- Encoded PowerShell
EventType = "Process Creation" AND
TgtProcName = "powershell.exe" AND
TgtProcCmdLine ContainsCIS "-enc"

-- LSASS Access
EventType = "Open Remote Process Handle" AND
TgtProcName = "lsass.exe" AND
SrcProcName NOT IN ("csrss.exe","svchost.exe","MsMpEng.exe")

-- Lateral Movement via PsExec
EventType = "Process Creation" AND
SrcProcName = "psexesvc.exe"

-- DNS Tunneling (long queries)
EventType = "DNS" AND
DnsRequest Len > 50 AND
DnsRequest RegExp "^[a-z0-9]{30,}\."

-- Registry Persistence
EventType = "Registry Value Modified" AND
RegistryPath ContainsCIS "\\CurrentVersion\\Run"

-- Scheduled Task Creation
EventType = "Process Creation" AND
TgtProcName = "schtasks.exe" AND
TgtProcCmdLine ContainsCIS "/create"

-- Office Macro Execution
EventType = "Process Creation" AND
SrcProcName In ("winword.exe","excel.exe","powerpnt.exe") AND
TgtProcName In ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")

-- Ransomware Indicators
EventType = "Process Creation" AND
TgtProcCmdLine ContainsCIS AnyCase ("vssadmin delete","wmic shadowcopy delete","bcdedit /set recoveryenabled no")

-- C2 Tunneling Tools
EventType = "Process Creation" AND
TgtProcName In ("chisel.exe","ngrok.exe","plink.exe","cloudflared.exe")

-- Data Staging
EventType = "Process Creation" AND
TgtProcCmdLine ContainsCIS AnyCase ("7z a","rar a","Compress-Archive")
```

## 5. STAR Rules (Custom Detection)
Storyline Active Response rules for automated detection:

```json
{
  "name": "Encoded PowerShell Execution",
  "description": "Detects PowerShell with encoded commands",
  "queryType": "events",
  "query": "EventType = \"Process Creation\" AND TgtProcName = \"powershell.exe\" AND TgtProcCmdLine ContainsCIS \"-enc\"",
  "severity": "High",
  "status": "Active",
  "treatAsThreat": "UNDEFINED",
  "networkQuarantine": false,
  "responseActions": ["DETECT"]
}
```

### STAR Rule Response Actions
| Action | Effect |
|--------|--------|
| DETECT | Generate alert only |
| SUSPICIOUS | Mark as suspicious threat |
| MALICIOUS | Mark as malicious + auto-mitigate |

## 6. Storyline Technology
Every process gets a Storyline ID. Related events (parent → child → network → file → registry) are automatically linked. This provides:
- Full attack chain visualization
- Root cause identification
- Automated grouping of related IOCs
- One-click remediation of entire attack chain

## 7. Remediation & Rollback
| Action | Description |
|--------|-------------|
| **Kill** | Terminate malicious process |
| **Quarantine** | Isolate malicious file |
| **Remediate** | Kill + quarantine + remove persistence |
| **Rollback** | Reverse all changes (Windows VSS-based) - undo ransomware encryption |

## 8. Remote Shell
```bash
# Connect to endpoint from console
# Full PowerShell (Windows) or Bash (Linux) shell
# File upload/download
# Process management
# Network diagnostics
```

## 9. Ranger (Network Discovery)
- Passive network scanning from deployed agents
- Discovers unmanaged/rogue devices
- Identifies IoT/OT devices
- No additional agent or appliance needed

## 10. API
```bash
# Get threats
curl -X GET 'https://console.sentinelone.net/web/api/v2.1/threats?limit=10' \
  -H "Authorization: ApiToken $TOKEN"

# Isolate endpoint
curl -X POST 'https://console.sentinelone.net/web/api/v2.1/agents/actions/disconnect' \
  -H "Authorization: ApiToken $TOKEN" \
  -d '{"filter":{"ids":["agent_id"]}}'

# Run remote script
curl -X POST 'https://console.sentinelone.net/web/api/v2.1/agents/actions/initiate-scan' \
  -H "Authorization: ApiToken $TOKEN" \
  -d '{"filter":{"ids":["agent_id"]}}'
```

## 11. Use Cases
1. Credential dumping (Deep Visibility: LSASS access)
2. Ransomware (auto-detect + rollback)
3. Lateral movement (Storyline: PsExec chain)
4. Fileless malware (behavioral AI detection)
5. LOTL attacks (STAR rule on LOLBAS)
6. Insider threat (data staging detection)
7. Rogue device (Ranger discovery)
8. Phishing payload (Office macro → shell)

## 12. Labs
### Lab 1: Deploy Agent & Verify
1. Install agent on Windows VM
2. Verify in console
3. Run test detection (EICAR)

### Lab 2: Deep Visibility Hunting
1. Run encoded PowerShell on endpoint
2. Hunt in Deep Visibility
3. View Storyline visualization

### Lab 3: STAR Rule
1. Create rule for Office macro execution
2. Test with macro-enabled document
3. Verify STAR alert fires

---
*Compatible with SentinelOne Singularity | Last updated March 2026*
