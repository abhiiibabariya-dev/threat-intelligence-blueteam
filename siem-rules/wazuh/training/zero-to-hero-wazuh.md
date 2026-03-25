# Wazuh Zero-to-Hero Training Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Agent Deployment](#agent-deployment)
5. [Rule Syntax](#rule-syntax)
6. [Custom Rules](#custom-rules)
7. [Decoders](#decoders)
8. [Active Response](#active-response)
9. [File Integrity Monitoring](#fim)
10. [Vulnerability Detection](#vulnerability)
11. [SCA](#sca)
12. [OpenSearch Integration](#opensearch)
13. [SOAR Integration](#soar)
14. [API](#api)
15. [Cluster Management](#cluster)
16. [Performance Tuning](#performance)
17. [Use Cases](#use-cases)
18. [Labs](#labs)
19. [Troubleshooting](#troubleshooting)

---

## 1. Introduction

Wazuh is a free, open-source security platform providing unified XDR and SIEM protection. It provides:
- **Threat detection** via rule-based analysis and anomaly detection
- **Integrity monitoring** for files and registry
- **Vulnerability detection** scanning
- **Compliance** (PCI DSS, HIPAA, GDPR, NIST)
- **Incident response** through active response
- **Cloud security** for AWS, Azure, GCP

---

## 2. Architecture

```
┌──────────────────────────────────────────────────┐
│                 Wazuh Dashboard                   │
│          (Kibana/OpenSearch Dashboards)           │
├──────────────────────────────────────────────────┤
│              Wazuh Indexer                         │
│     (OpenSearch - stores alerts & events)         │
├──────────────────────────────────────────────────┤
│              Wazuh Manager                         │
│  (Analysis engine, rules, decoders, API)          │
│  ┌────────┐ ┌──────────┐ ┌─────────────────┐    │
│  │Analysisd│ │Remoted   │ │Vulnerability-    │    │
│  │(rules)  │ │(agent    │ │detector          │    │
│  │         │ │comms)    │ │                   │    │
│  └────────┘ └──────────┘ └─────────────────┘    │
├──────────────────────────────────────────────────┤
│              Wazuh Agents                          │
│  Windows | Linux | macOS | Containers             │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────────┐   │
│  │Logcol│ │Syscheck││Rootchk│ │Vulnerability │   │
│  │lector│ │(FIM)  │ │(root) │ │scanner       │   │
│  └──────┘ └──────┘ └──────┘ └──────────────┘   │
└──────────────────────────────────────────────────┘
```

### Communication
- Agents → Manager: Port **1514** (encrypted, AES)
- API: Port **55000** (HTTPS)
- Dashboard: Port **443** (HTTPS)
- Indexer: Port **9200** (HTTPS)

---

## 3. Installation

### Single Node (Quick Start)
```bash
# Install Wazuh 4.x with the installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

# This installs: Wazuh Manager + Indexer + Dashboard
# Credentials are displayed at the end
```

### Docker Compose
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator
docker-compose up -d
```

### Kubernetes (Helm)
```bash
helm repo add wazuh https://packages.wazuh.com/4.x/helm/
helm install wazuh wazuh/wazuh --namespace wazuh --create-namespace
```

### Package Manager (Detailed)
```bash
# Add repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

# Install manager
apt-get update && apt-get install wazuh-manager

# Start service
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```

---

## 4. Agent Deployment

### Windows
```powershell
# Download and install via MSI
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="10.0.0.100" WAZUH_REGISTRATION_SERVER="10.0.0.100" WAZUH_AGENT_GROUP="windows-servers"

# Start agent
NET START WazuhSvc
```

### Linux
```bash
# Debian/Ubuntu
WAZUH_MANAGER="10.0.0.100" apt-get install wazuh-agent
systemctl start wazuh-agent

# Register manually
/var/ossec/bin/agent-auth -m 10.0.0.100 -G "linux-servers"
```

### macOS
```bash
installer -pkg wazuh-agent-4.7.0-1.pkg -target /
/Library/Ossec/bin/agent-auth -m 10.0.0.100
/Library/Ossec/bin/wazuh-control start
```

### Verify Enrollment
```bash
# On manager
/var/ossec/bin/agent_control -l
# Shows: ID, Name, IP, Status (Active/Disconnected)
```

---

## 5. Rule Syntax

### Rule Structure
```xml
<group name="group_name,">
  <rule id="100100" level="10" frequency="8" timeframe="120">
    <if_sid>parent_rule_id</if_sid>
    <if_matched_sid>match_rule_id</if_matched_sid>
    <same_source_ip/>
    <different_user/>
    <field name="field_name" type="pcre2">regex_pattern</field>
    <match type="pcre2">pattern</match>
    <regex>regex_pattern</regex>
    <srcip>IP</srcip>
    <dstip>IP</dstip>
    <description>Alert description with $(field) variables</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>tag1,tag2,</group>
    <options>alert_by_email,no_log</options>
  </rule>
</group>
```

### Rule Levels
| Level | Severity | Description |
|-------|----------|-------------|
| 0 | Ignored | Rule used for correlation only |
| 1-3 | Low | System notifications |
| 4-7 | Medium | Errors, warnings |
| 8-11 | High | Security alerts |
| 12-14 | Critical | High-severity attacks |
| 15 | Emergency | Immediate action required |

### Key Elements
| Element | Purpose | Example |
|---------|---------|---------|
| `<if_sid>` | Parent rule (child fires after parent) | `<if_sid>5710</if_sid>` |
| `<if_matched_sid>` | Frequency match on rule | `<if_matched_sid>5716</if_matched_sid>` |
| `<same_source_ip/>` | Correlate by source IP | Frequency rule |
| `<different_user/>` | Require different users | Password spray |
| `<field>` | Match decoded field | `<field name="win.eventdata.image">` |
| `<match>` | Match raw log content | `<match>Failed password</match>` |
| `<regex>` | Regex on raw log | `<regex>^Failed</regex>` |
| `<pcre2>` | PCRE2 regex | More powerful patterns |
| `<frequency>` | Event count threshold | `frequency="10"` |
| `<timeframe>` | Time window (seconds) | `timeframe="120"` |

---

## 6. Custom Rules

### Example: Detect Mimikatz
```xml
<!-- Save to /var/ossec/etc/rules/local_rules.xml -->
<group name="mimikatz,credential_access,">
  <rule id="100500" level="15">
    <if_sid>61601</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(mimikatz|sekurlsa|kerberos::list|privilege::debug)</field>
    <description>CRITICAL: Mimikatz execution detected on $(win.eventdata.computer)</description>
    <mitre>
      <id>T1003</id>
    </mitre>
    <group>credential_dumping,critical,</group>
    <options>alert_by_email</options>
  </rule>
</group>
```

### Testing Rules
```bash
# Test rule syntax
/var/ossec/bin/wazuh-logtest

# Paste a log sample and see which rules fire
# Type 'q' to quit

# Restart after adding rules
systemctl restart wazuh-manager
```

### Rule Loading Order
1. `/var/ossec/ruleset/rules/` - Default rules (don't modify)
2. `/var/ossec/etc/rules/local_rules.xml` - Custom rules (your changes here)

---

## 7. Decoders

### Decoder Structure
```xml
<decoder name="custom-app">
  <prematch>^MyApp:</prematch>
  <regex>^MyApp: user=(\S+) action=(\S+) src=(\S+)</regex>
  <order>user, action, srcip</order>
</decoder>
```

### Parent-Child Decoders
```xml
<!-- Parent matches the log source -->
<decoder name="myfw">
  <prematch>^FIREWALL:</prematch>
</decoder>

<!-- Child extracts specific fields -->
<decoder name="myfw-traffic">
  <parent>myfw</parent>
  <regex>src=(\d+.\d+.\d+.\d+) dst=(\d+.\d+.\d+.\d+) port=(\d+) action=(\S+)</regex>
  <order>srcip, dstip, dstport, action</order>
</decoder>
```

### JSON Decoder
```xml
<decoder name="json-app">
  <prematch>^{"timestamp":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### Testing Decoders
```bash
/var/ossec/bin/wazuh-logtest
# Paste log line → shows decoder match and extracted fields
```

---

## 8. Active Response

### Configuration (ossec.conf)
```xml
<!-- Define command -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Link to rule -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100,100101</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### Built-in Scripts
- `firewall-drop` - Block IP via iptables/ipfw
- `host-deny` - Add to /etc/hosts.deny
- `disable-account` - Disable user account
- `restart-wazuh` - Restart agent

---

## 9. File Integrity Monitoring (FIM)

### Configure Syscheck (ossec.conf)
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>600</frequency>

  <!-- Directories to monitor -->
  <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes" realtime="yes">/var/www</directories>

  <!-- Windows directories -->
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  <directories check_all="yes" whodata="yes">C:\Users</directories>

  <!-- Ignore patterns -->
  <ignore>/etc/mtab</ignore>
  <ignore type="sregex">.log$</ignore>

  <!-- Registry monitoring (Windows) -->
  <windows_registry>HKEY_LOCAL_MACHINE\Software</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</windows_registry>
</syscheck>
```

### Whodata (Real-time + Who Changed It)
Uses auditd (Linux) or SACL (Windows) to capture WHO made the change, not just WHAT changed.

---

## 10. Vulnerability Detection

```xml
<!-- Enable in ossec.conf -->
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <min_full_scan_interval>6h</min_full_scan_interval>
  <run_on_start>yes</run_on_start>

  <provider name="canonical">
    <enabled>yes</enabled>
    <os>focal</os>
    <os>jammy</os>
    <update_interval>1h</update_interval>
  </provider>

  <provider name="nvd">
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
```

---

## 11. Security Configuration Assessment (SCA)

Built-in policies check systems against benchmarks:
- CIS Benchmarks (Windows, Linux, macOS)
- PCI DSS
- HIPAA
- NIST 800-53

```xml
<!-- ossec.conf -->
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <policies>
    <policy>cis_ubuntu22-04.yml</policy>
    <policy>pci_dss_v3.2.1.yml</policy>
  </policies>
</sca>
```

---

## 12. OpenSearch Integration

Wazuh ships with a pre-configured OpenSearch stack. Alerts are indexed automatically.

### Custom Index Template
```json
PUT _template/wazuh-custom
{
  "index_patterns": ["wazuh-alerts-*"],
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1
  }
}
```

---

## 13. SOAR Integration (Shuffle)

### Webhook Configuration
```xml
<!-- ossec.conf - Send alerts to Shuffle -->
<integration>
  <name>custom-shuffle</name>
  <hook_url>https://shuffle.local:3443/api/v1/hooks/webhook_id</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

---

## 14. Wazuh API

```bash
# Authenticate
TOKEN=$(curl -u wazuh-wui:wazuh-wui -k -X POST "https://localhost:55000/security/user/authenticate?raw=true")

# List agents
curl -k -X GET "https://localhost:55000/agents?pretty=true" -H "Authorization: Bearer $TOKEN"

# Get agent info
curl -k -X GET "https://localhost:55000/agents/001?pretty=true" -H "Authorization: Bearer $TOKEN"

# Restart agent
curl -k -X PUT "https://localhost:55000/agents/001/restart" -H "Authorization: Bearer $TOKEN"

# Get active rules
curl -k -X GET "https://localhost:55000/rules?pretty=true&limit=10" -H "Authorization: Bearer $TOKEN"
```

---

## 15. Cluster Management

```xml
<!-- Master node -->
<cluster>
  <name>wazuh-cluster</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>secretkey123</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>master-ip</node>
  </nodes>
  <hidden>no</hidden>
  <disabled>no</disabled>
</cluster>
```

---

## 16. Performance Tuning

```xml
<!-- ossec.conf tuning -->
<global>
  <logall>no</logall>
  <memory_size>8192</memory_size>
  <white_list>127.0.0.1</white_list>
</global>

<!-- analysisd tuning -->
<rule_test>
  <threads>4</threads>
  <queue_size>32768</queue_size>
</rule_test>
```

**Tips:**
- Increase `memory_size` for high event volume
- Use `<if_sid>` chaining to reduce rule evaluation
- Set appropriate FIM `frequency` (don't scan every minute)
- Use `<ignore>` for noisy log paths

---

## 17. Labs

### Lab 1: Deploy Manager + 2 Agents
1. Install Wazuh manager on Ubuntu
2. Deploy Windows agent
3. Deploy Linux agent
4. Verify enrollment via API

### Lab 2: Create Custom Detection Rule
1. Write rule to detect `whoami /all` execution
2. Test with wazuh-logtest
3. Trigger from agent and verify alert

### Lab 3: Configure FIM
1. Enable realtime FIM on `/etc/`
2. Modify a file
3. View alert in dashboard

### Lab 4: Active Response
1. Create brute force detection rule
2. Configure firewall-drop active response
3. Test with failed SSH logins
4. Verify IP is blocked

### Lab 5: Vulnerability Scanning
1. Enable vulnerability detection
2. Run scan on Linux agent
3. Review CVE findings in dashboard

---

*Last updated: March 2026 | Compatible with Wazuh 4.x*
