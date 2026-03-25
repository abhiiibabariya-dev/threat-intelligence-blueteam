# Splunk Zero-to-Hero Training Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Data Onboarding](#data-onboarding)
5. [SPL Fundamentals](#spl-fundamentals)
6. [SPL Intermediate](#spl-intermediate)
7. [SPL Advanced](#spl-advanced)
8. [Detection Rules & Alerts](#detection-rules)
9. [Splunk Enterprise Security](#enterprise-security)
10. [Dashboards](#dashboards)
11. [Apps & Add-ons](#apps)
12. [Performance Tuning](#performance)
13. [Clustering & HA](#clustering)
14. [REST API](#api)
15. [Security Use Cases](#use-cases)
16. [Labs & Exercises](#labs)
17. [Certification Path](#certification)

---

## 1. Introduction

Splunk is a data platform for search, monitoring, and analysis of machine-generated data. In security, it serves as a SIEM when paired with Splunk Enterprise Security (ES).

**Key capabilities:**
- Real-time log collection and indexing
- Search Processing Language (SPL) for data analysis
- Alerting and detection rules
- Dashboards and visualizations
- Threat intelligence framework
- Risk-based alerting (RBA)

---

## 2. Architecture

### Core Components

```
┌─────────────────────────────────────────────────────┐
│                  Search Head (SH)                    │
│  Runs searches, serves dashboards, manages KO        │
├─────────────────────────────────────────────────────┤
│                  Indexer (IDX)                        │
│  Indexes data, stores events, responds to searches   │
├─────────────────────────────────────────────────────┤
│            Universal Forwarder (UF)                   │
│  Lightweight agent, collects and forwards data        │
├─────────────────────────────────────────────────────┤
│            Heavy Forwarder (HF)                       │
│  Parses data, routes, filters before indexing         │
├─────────────────────────────────────────────────────┤
│           Deployment Server (DS)                      │
│  Manages forwarder configurations centrally           │
├─────────────────────────────────────────────────────┤
│           Cluster Master / Manager                    │
│  Manages indexer cluster replication                  │
├─────────────────────────────────────────────────────┤
│            License Master                             │
│  Manages license usage across deployment              │
└─────────────────────────────────────────────────────┘
```

### Data Flow
```
Data Sources → Forwarders → Indexers → Search Heads → Users
                  (UF/HF)    (IDX)       (SH)
```

### Key Ports
| Port | Service |
|------|---------|
| 8000 | Splunk Web |
| 8089 | Management/REST API |
| 9997 | Forwarder to Indexer |
| 8080 | Indexer replication |
| 514  | Syslog input |

---

## 3. Installation

### Standalone (Linux)
```bash
# Download and install
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-Linux-x86_64.tgz'
tar xvzf splunk.tgz -C /opt
/opt/splunk/bin/splunk start --accept-license --answer-yes --seed-passwd 'YourPassword123!'

# Enable boot start
/opt/splunk/bin/splunk enable boot-start -user splunk

# Check status
/opt/splunk/bin/splunk status
```

### Universal Forwarder
```bash
# Install UF
wget -O splunkuf.tgz 'https://download.splunk.com/products/universalforwarder/releases/9.2.0/linux/splunkforwarder-9.2.0-Linux-x86_64.tgz'
tar xvzf splunkuf.tgz -C /opt

# Configure forwarding
/opt/splunkforwarder/bin/splunk add forward-server indexer1:9997
/opt/splunkforwarder/bin/splunk add monitor /var/log/
```

### Docker
```bash
docker run -d -p 8000:8000 -p 8089:8089 \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='YourPassword123!' \
  --name splunk splunk/splunk:latest
```

---

## 4. Data Onboarding

### inputs.conf (on forwarder)
```ini
# Monitor a file
[monitor:///var/log/syslog]
disabled = false
index = linux
sourcetype = syslog

# Monitor Windows Event Logs
[WinEventLog://Security]
disabled = 0
index = wineventlog
evt_resolve_ad_obj = 1

# Network input (syslog)
[udp://514]
connection_host = dns
sourcetype = syslog
index = network
```

### props.conf (search-time field extraction)
```ini
[syslog]
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 20
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)

# Field extraction
EXTRACT-src_ip = src=(?<src_ip>\d+\.\d+\.\d+\.\d+)
EXTRACT-dest_ip = dst=(?<dest_ip>\d+\.\d+\.\d+\.\d+)
```

### CIM (Common Information Model)
The CIM normalizes data across sources. Key data models:
- **Authentication** - login events
- **Network_Traffic** - firewall/proxy
- **Endpoint** - process/file events
- **Malware** - AV detections
- **Intrusion_Detection** - IDS/IPS

```spl
# CIM-compliant search (much faster with acceleration)
| tstats count from datamodel=Authentication where Authentication.action="failure" by Authentication.src Authentication.user
```

---

## 5. SPL Fundamentals

### Basic Search
```spl
# Search for failed logins in last 24 hours
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h

# Pipe to commands
index=wineventlog EventCode=4625
| stats count by src_ip, user
| sort -count
| head 20
```

### Essential Commands

#### where (filter with expressions)
```spl
index=firewall
| where bytes_out > 1000000
| where dest_port != 443 AND dest_port != 80
```

#### eval (create/transform fields)
```spl
index=firewall
| eval mb_out = round(bytes_out/1024/1024, 2)
| eval severity = case(
    mb_out > 100, "critical",
    mb_out > 50, "high",
    mb_out > 10, "medium",
    true(), "low"
  )
| table _time src_ip dest_ip mb_out severity
```

#### stats (aggregate)
```spl
index=wineventlog EventCode=4625
| stats count as failed_attempts,
        dc(user) as unique_users,
        values(user) as targeted_users,
        earliest(_time) as first_attempt,
        latest(_time) as last_attempt
  by src_ip
| where failed_attempts > 10
| sort -failed_attempts
```

#### chart / timechart
```spl
# Time-series chart
index=firewall action=blocked
| timechart span=1h count by dest_port limit=10

# Pivot chart
index=wineventlog EventCode=4625
| chart count over src_ip by user
```

#### table, sort, dedup, rename
```spl
index=proxy
| dedup url
| table _time src_ip url status bytes
| rename src_ip as "Source IP", url as "URL"
| sort -bytes
```

#### rex (regex field extraction)
```spl
index=webserver
| rex field=_raw "(?<method>GET|POST|PUT|DELETE)\s+(?<uri>\S+)\s+HTTP"
| stats count by method, uri
```

---

## 6. SPL Intermediate

### Subsearch
```spl
# Find all activity from IPs that had >10 failed logins
index=firewall
  [search index=wineventlog EventCode=4625
   | stats count by src_ip
   | where count > 10
   | fields src_ip
   | rename src_ip as dest_ip]
| stats count by dest_ip, dest_port
```

### lookup
```spl
# Enrich with threat intel lookup
index=firewall
| lookup threat_intel_ip ip as dest_ip OUTPUT threat_category, confidence
| where isnotnull(threat_category)
| table _time src_ip dest_ip dest_port threat_category confidence
```

### join
```spl
# Join authentication with VPN logs
index=wineventlog EventCode=4624
| join type=inner src_ip
  [search index=vpn action=connected
   | fields src_ip, vpn_user, country]
| table _time user src_ip vpn_user country
```

### transaction
```spl
# Group related events into transactions
index=wineventlog (EventCode=4624 OR EventCode=4625 OR EventCode=4634)
| transaction user maxspan=30m maxpause=5m
| where eventcount > 5
| table user, duration, eventcount
```

### append / appendcols
```spl
# Combine results from different indexes
index=wineventlog EventCode=4625
| stats count as failed_logins by src_ip
| append
  [search index=firewall action=blocked
   | stats count as blocked_connections by src_ip]
| stats sum(failed_logins) as failed_logins, sum(blocked_connections) as blocked by src_ip
```

### map (iterate)
```spl
# For each suspicious IP, get recent activity
index=wineventlog EventCode=4625
| stats count by src_ip | where count > 10
| map maxsearches=5 search="search index=firewall src_ip=$src_ip$ | stats count by dest_port"
```

---

## 7. SPL Advanced

### tstats (accelerated data model search)
```spl
# 100x faster than raw search when data models are accelerated
| tstats count from datamodel=Authentication
  where Authentication.action="failure"
  by Authentication.src, Authentication.user, _time span=1h
| rename Authentication.* as *
| where count > 10
```

### datamodel
```spl
# Explore data model structure
| datamodel Authentication search
| fields + Authentication.*
```

### Macros
```ini
# Define in Settings > Advanced Search > Search Macros
# Macro name: get_failed_logins(threshold)
# Definition:
index=wineventlog EventCode=4625
| stats count by src_ip
| where count > $threshold$
```
```spl
# Use the macro
`get_failed_logins(10)`
| lookup geo_ip ip as src_ip OUTPUT country
```

### Event Types and Tags
```spl
# Define event types for CIM compliance
# eventtype: authentication_failure
# search: index=wineventlog EventCode=4625

# Tag event types
# tag: authentication, failure

# Then search by tag
tag=authentication tag=failure
| stats count by src_ip
```

---

## 8. Detection Rules & Alerts

### Creating a Saved Search Alert
```spl
# Brute Force Detection
index=wineventlog EventCode=4625
| stats count as failed_attempts by src_ip, user
| where failed_attempts > 20
| eval severity="high"
| eval mitre_technique="T1110.001"
```

**Alert Configuration:**
- Schedule: Every 5 minutes
- Time Range: Last 15 minutes
- Trigger: Number of results > 0
- Throttle: 1 hour per src_ip
- Actions: Send email, Create notable event, Run script

### Webhook Alert Action
```json
{
  "search_name": "$name$",
  "results_link": "$results_link$",
  "result.src_ip": "$result.src_ip$",
  "result.failed_attempts": "$result.failed_attempts$"
}
```

---

## 9. Splunk Enterprise Security (ES)

### Key Features
- **Notable Events**: Correlated security incidents
- **Risk-Based Alerting (RBA)**: Aggregate risk scores per entity
- **Threat Intelligence Framework**: Ingest and match IOCs
- **Investigation Dashboard**: Analyst workspace
- **MITRE ATT&CK Matrix**: Visual coverage mapping

### Risk-Based Alerting
```spl
# Instead of creating alerts, add risk
# Risk Rule: Encoded PowerShell
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| eval risk_score=40
| eval risk_object=host
| eval risk_object_type="system"
| eval risk_message="Encoded PowerShell execution on " . host
| collect index=risk sourcetype=stash

# Risk Notable: Entity exceeds risk threshold
| tstats sum(All_Risk.calculated_risk_score) as total_risk from datamodel=Risk by All_Risk.risk_object
| where total_risk > 100
```

### Threat Intelligence Framework
```spl
# Search for IOC matches
| tstats count from datamodel=Network_Traffic by All_Traffic.dest
| rename All_Traffic.dest as dest
| lookup threat_intel ip as dest OUTPUT threat_key, description
| where isnotnull(threat_key)
```

---

## 10. Dashboards

### Simple XML Example
```xml
<dashboard>
  <label>SOC Overview</label>
  <row>
    <panel>
      <title>Failed Logins - Last 24h</title>
      <chart>
        <search>
          <query>index=wineventlog EventCode=4625 | timechart span=1h count</query>
          <earliest>-24h</earliest>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
    <panel>
      <title>Top Attackers</title>
      <table>
        <search>
          <query>index=wineventlog EventCode=4625 | stats count by src_ip | sort -count | head 10</query>
          <earliest>-24h</earliest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

---

## 11. Apps & Add-ons

### Essential Security Add-ons
| Add-on | Purpose |
|--------|---------|
| Splunk Add-on for Microsoft Windows | Windows event logs |
| Splunk Add-on for Sysmon | Sysmon data parsing |
| Splunk Add-on for Linux | Linux/Unix logs |
| Splunk Add-on for AWS | AWS CloudTrail, VPC, etc. |
| Splunk Add-on for Microsoft Azure | Azure activity logs |
| SA-CIM | Common Information Model |

---

## 12. Performance Tuning

### Search Optimization Tips
```spl
# BAD: Broad search
index=* error

# GOOD: Specific search
index=webserver sourcetype=access_combined status=500

# Use tstats over raw search when possible
# Use accelerated data models
# Limit time range
# Use fields command early to reduce data
# Avoid wildcards at the start of values
```

### Key Settings
```ini
# server.conf - Indexer tuning
[general]
parallelIngestionPipelines = 2

# limits.conf - Search tuning
[search]
max_searches_per_cpu = 4
dispatch.max_time = 600
```

---

## 13. Clustering & HA

### Indexer Cluster
```bash
# Enable cluster master
splunk edit cluster-config -mode master -replication_factor 2 -search_factor 2 -secret mysecret

# Enable cluster peer (indexer)
splunk edit cluster-config -mode slave -master_uri https://cm:8089 -secret mysecret -replication_port 8080

# Enable search head to use cluster
splunk edit cluster-config -mode searchhead -master_uri https://cm:8089 -secret mysecret
```

### Search Head Cluster
```bash
# Initialize SHC
splunk init shcluster-config -auth admin:password -mgmt_uri https://sh1:8089 -replication_port 8181 -secret shcsecret

# Bootstrap captain
splunk bootstrap shcluster-captain -servers_list "https://sh1:8089,https://sh2:8089,https://sh3:8089" -auth admin:password
```

---

## 14. REST API

```bash
# Search via REST API
curl -k -u admin:password https://localhost:8089/services/search/jobs \
  -d search="search index=wineventlog EventCode=4625 | stats count by src_ip" \
  -d earliest_time="-24h" \
  -d output_mode=json

# Get results
curl -k -u admin:password https://localhost:8089/services/search/jobs/SID/results \
  --get -d output_mode=json -d count=100

# Python SDK
import splunklib.client as client
service = client.connect(host='localhost', port=8089, username='admin', password='password')
results = service.jobs.oneshot("search index=_internal | head 10")
```

---

## 15. Security Use Cases

| # | Use Case | SPL Concept |
|---|----------|-------------|
| 1 | Brute Force Detection | stats count, threshold |
| 2 | Password Spray | dc() unique users |
| 3 | Lateral Movement (RDP) | stats dc(dest) by src |
| 4 | Encoded PowerShell | rex, base64 decode |
| 5 | Data Exfiltration | timechart bytes_out |
| 6 | DNS Tunneling | stats avg(len(query)) |
| 7 | Process Injection | Sysmon EID 8,10 |
| 8 | Ransomware | file extension changes |
| 9 | C2 Beaconing | timechart, stdev |
| 10 | Privilege Escalation | EventCode 4672, 4728 |
| 11 | Log Clearing | EventCode 1102 |
| 12 | Kerberoasting | EventCode 4769 |
| 13 | DCSync | EventCode 4662 |
| 14 | PsExec | Service install 7045 |
| 15 | LOLBAS | Parent-child process |

---

## 16. Labs & Exercises

### Lab 1: Build a Brute Force Detection
1. Ingest Windows Security logs
2. Write SPL to detect >10 failures per source in 5 minutes
3. Create a saved search alert
4. Build a dashboard panel

### Lab 2: Risk-Based Alerting
1. Create 5 risk rules for different MITRE techniques
2. Configure risk scoring thresholds
3. Create a risk notable search
4. Build a risk investigation dashboard

### Lab 3: Threat Intelligence Integration
1. Import a CSV threat feed as a lookup
2. Create a correlation search matching network traffic to IOCs
3. Build an IOC match dashboard

### Lab 4: Build a SOC Dashboard
1. Create panels: alert volume, top attackers, MITRE coverage, response times
2. Add drilldowns to investigation views
3. Use tokens for dynamic filtering

### Lab 5: Data Onboarding
1. Configure a Universal Forwarder for Windows
2. Create custom sourcetype with props.conf
3. Map to CIM data model
4. Verify with tstats

---

## 17. Certification Path

| Level | Certification | Topics |
|-------|--------------|--------|
| 1 | Splunk Core Certified User | Basic SPL, navigation |
| 2 | Splunk Core Certified Power User | Advanced SPL, dashboards, data models |
| 3 | Splunk Core Certified Admin | Installation, configuration, management |
| 4 | Splunk Enterprise Certified Architect | Clustering, distributed deployment |
| 5 | Splunk Enterprise Security Certified Admin | ES configuration, notable events, RBA |

### Recommended Learning Order
1. Splunk Fundamentals 1 (free)
2. Splunk Fundamentals 2
3. Searching & Reporting with Splunk
4. Using Splunk Enterprise Security
5. Administering Splunk Enterprise Security
6. Splunk Enterprise Cluster Administration

---

*Last updated: March 2026 | Compatible with Splunk 9.x*
