# VMware Carbon Black Zero-to-Hero Training Guide

## 1. Introduction
Carbon Black (now VMware Carbon Black Cloud) provides endpoint protection with process-level visibility, watchlists, threat feeds, and Live Response for remote investigation.

## 2. Architecture
- **CBC Cloud** - SaaS management console
- **CB Sensor** - Endpoint agent (Windows, Linux, macOS)
- **Enterprise EDR** - Full process recording
- **Endpoint Standard** - NGAV + behavioral EDR
- **Audit & Remediation** - Live Query (osquery-based)

## 3. Sensor Deployment
```bash
# Windows
msiexec /i CbDefense_x64.msi /quiet COMPANY_CODE="XXXXX" CLI_USERS="admin"

# Linux
sudo rpm -i cb-psc-sensor.rpm
sudo /opt/carbonblack/psc/bin/cbagentd -d /opt/carbonblack/psc

# Verify
sc query CbDefense  # Windows
systemctl status cbagentd  # Linux
```

## 4. Process Search
Search all recorded process events:
```
# Encoded PowerShell
process_name:powershell.exe AND cmdline:"-enc"

# LSASS access
crossproc_name:lsass.exe AND -process_name:(csrss.exe OR svchost.exe)

# Office spawning shell
parent_name:(winword.exe OR excel.exe) AND process_name:(cmd.exe OR powershell.exe)

# PsExec lateral movement
parent_name:psexesvc.exe

# Registry persistence
regmod_name:"\\CurrentVersion\\Run\\*"

# DNS to suspicious domain
netconn_domain:*.tk OR netconn_domain:*.xyz

# File write to startup
filemod_name:"*\\Start Menu\\Programs\\Startup\\*"

# Service creation
modload_name:services.exe AND cmdline:"create"
```

## 5. Watchlists
Automated alerting on search criteria:
```json
{
  "name": "Credential Dumping Detection",
  "description": "Detects tools accessing LSASS memory",
  "query": "crossproc_name:lsass.exe AND -process_name:(csrss.exe OR svchost.exe OR MsMpEng.exe)",
  "alert_type": "CB_ANALYTICS",
  "severity": 8,
  "enabled": true
}
```

## 6. Threat Feeds
- **CB Threat Intel** - Built-in threat feeds
- **Alliance Feeds** - Community-shared IOCs
- **Custom Feeds** - Import your own via STIX/TAXII or CSV
- **VirusTotal** - Hash reputation integration

## 7. Live Response
Remote shell access to endpoints:
```bash
# Connect
> session create <sensor_id>

# List processes
> process list

# Kill process
> kill <pid>

# Get file
> get "C:\Users\victim\Desktop\suspicious.exe"

# Execute command
> execfg cmd.exe /c "netstat -an"

# Put file (upload tool to endpoint)
> put "C:\Tools\autoruns.exe"

# Memdump
> memdump <pid>

# Registry
> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

## 8. Audit & Remediation (Live Query)
osquery-based live querying across all endpoints:
```sql
-- Find all listening ports
SELECT pid, port, address, protocol FROM listening_ports WHERE port NOT IN (80, 443, 22);

-- Find scheduled tasks
SELECT name, action, path, enabled FROM scheduled_tasks WHERE enabled = 1;

-- Find startup items
SELECT name, path, source FROM startup_items;

-- Installed software
SELECT name, version, install_date FROM programs WHERE name LIKE '%remote%';
```

## 9. API
```bash
# Search processes
curl -X POST 'https://defense.conferdeploy.net/api/investigate/v2/orgs/{org_key}/processes/search' \
  -H "X-Auth-Token: $API_KEY/$API_ID" \
  -d '{"query":"process_name:powershell.exe AND cmdline:\"-enc\"","rows":10}'

# Get alerts
curl -X POST 'https://defense.conferdeploy.net/api/alerts/v7/orgs/{org_key}/alerts/_search' \
  -H "X-Auth-Token: $API_KEY/$API_ID" \
  -d '{"criteria":{"minimum_severity":5},"rows":10}'
```

## 10. Use Cases & Labs
1. Credential dumping (watchlist on LSASS crossproc)
2. Ransomware (file modification watchlist)
3. Lateral movement (PsExec/WMI parent process)
4. LOTL attacks (LOLBAS watchlist)
5. Phishing (Office macro child process)

### Lab 1: Create Watchlist
1. Build process search for encoded PowerShell
2. Save as watchlist with alerting
3. Test and verify alert

### Lab 2: Live Response Investigation
1. Connect to suspicious endpoint
2. List processes and network connections
3. Collect suspicious files
4. Kill malicious processes

---
*Compatible with VMware Carbon Black Cloud | Last updated March 2026*
