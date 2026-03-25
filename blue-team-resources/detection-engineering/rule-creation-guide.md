# Detection Engineering - Rule Creation Guide

## 1. Detection Rule Design Principles

### The Detection Pyramid
```
         /\
        /  \     Behavioral (UEBA, ML anomaly)
       /    \    Hardest to evade, most false positives
      /──────\
     /        \   TTP-based (process chains, API calls)
    /          \  Technique detection, moderate FPs
   /────────────\
  /              \ IOC-based (hashes, IPs, domains)
 /                \ Easy to implement, easy to evade
/──────────────────\
```

**Rule Priority:** TTP-based > Behavioral > IOC-based

### Key Principles
1. **Detect the technique, not the tool** - Mimikatz changes; LSASS access patterns don't
2. **Start broad, then tune** - Deploy with low severity, observe FPs, refine
3. **Context enrichment** - Raw alerts are useless without asset/identity context
4. **Test before deploy** - Validate against known-good and known-bad data
5. **Document everything** - Future you will thank present you

---

## 2. Rule Naming Convention

```
[COMPANY]-[TACTIC]-[NUMBER]: [Brief Description]
```

**Examples:**
- `ACME-CA-001: Brute Force Authentication (>10 failures/5min)`
- `ACME-LM-003: PsExec Service Installation`
- `ACME-EX-002: DNS Tunneling (Long Query Names)`

### MITRE Tactic Codes
| Code | Tactic | Code | Tactic |
|------|--------|------|--------|
| IA | Initial Access | CA | Credential Access |
| EXE | Execution | DIS | Discovery |
| PER | Persistence | LM | Lateral Movement |
| PE | Privilege Escalation | COL | Collection |
| DE | Defense Evasion | EX | Exfiltration |
| C2 | Command & Control | IMP | Impact |

---

## 3. MITRE ATT&CK Mapping Methodology

### Step-by-Step
1. **Identify the behavior** you're detecting
2. **Map to technique** - Find the most specific sub-technique (e.g., T1003.001 not just T1003)
3. **Map to tactic** - A technique may span multiple tactics
4. **Identify data sources** - MITRE lists required data sources per technique
5. **Document detection gaps** - What variations does your rule NOT catch?

### Mapping Template
```yaml
mitre_attack:
  tactic: TA0006 - Credential Access
  technique: T1003 - OS Credential Dumping
  sub_technique: T1003.001 - LSASS Memory
  data_sources:
    - Process: Process Access (Sysmon EID 10)
    - Process: Process Creation (Sysmon EID 1)
  platforms: [Windows]
```

---

## 4. Detection-as-Code

### Directory Structure
```
detection-rules/
├── rules/
│   ├── credential-access/
│   │   ├── CA-001-brute-force.yml
│   │   ├── CA-002-lsass-dump.yml
│   │   └── CA-003-kerberoasting.yml
│   ├── lateral-movement/
│   └── ...
├── tests/
│   ├── CA-001-brute-force-test.yml
│   └── ...
├── pipelines/
│   ├── deploy-splunk.yml
│   └── deploy-sentinel.yml
└── sigma/
    └── converted rules
```

### Sigma Rule Format
```yaml
title: LSASS Memory Dump via Procdump
id: 5afee48e-67dd-4b3a-b21d-4a9cf228e5b7
status: production
level: critical
description: Detects LSASS memory dump using procdump
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: SOC Team
date: 2026/03/01
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'procdump'
      - 'lsass'
  condition: selection
falsepositives:
  - Legitimate memory dump for debugging
```

### Sigma Conversion
```bash
# Convert to Splunk SPL
sigma convert -t splunk -p sysmon rules/CA-002-lsass-dump.yml

# Convert to Sentinel KQL
sigma convert -t microsoft365defender rules/CA-002-lsass-dump.yml

# Convert to Elastic
sigma convert -t elasticsearch rules/CA-002-lsass-dump.yml
```

---

## 5. Testing & Validation

### Test Categories
1. **True Positive (TP)** - Run attack simulation, rule fires ✓
2. **True Negative (TN)** - Normal activity, rule does NOT fire ✓
3. **False Positive (FP)** - Normal activity triggers rule ✗ (tune)
4. **False Negative (FN)** - Attack occurs, rule doesn't fire ✗ (fix)

### Testing Tools
- **Atomic Red Team** - T-numbered test cases matching MITRE
- **Caldera** - Automated adversary emulation
- **Invoke-AtomicRedTeam** - PowerShell execution of atomic tests

```powershell
# Test Kerberoasting detection
Invoke-AtomicTest T1558.003

# Test LSASS dump detection
Invoke-AtomicTest T1003.001
```

---

## 6. Rule Lifecycle

```
Draft → Review → Test → Pilot → Production → Tune → Retire
  │       │       │       │         │          │        │
  │       │       │       │         │          │        └─ Rule no longer relevant
  │       │       │       │         │          └─ Adjust for FPs/FNs
  │       │       │       │         └─ Full deployment
  │       │       │       └─ Deploy to subset (1 week)
  │       │       └─ Validate TP/FP/FN
  │       └─ Peer review
  └─ Initial development
```

---

## 7. Rule Maturity Model

| Level | Name | Criteria |
|-------|------|----------|
| 1 | **Experimental** | New rule, limited testing, high FP rate expected |
| 2 | **Development** | Tested against sample data, basic tuning done |
| 3 | **Pilot** | Running in production (alert-only), FPs being tracked |
| 4 | **Production** | Fully tuned, FP rate < 10%, automated response enabled |
| 5 | **Optimized** | ML-enhanced, threat-intel enriched, minimal FPs |

---

## 8. False Positive Tuning

### Tuning Workflow
1. Track FP rate per rule (target: <10% for production)
2. Categorize FP sources (legitimate admin tools, scheduled tasks, etc.)
3. Add allowlists/exclusions (specific users, hosts, paths)
4. Document every exclusion with justification
5. Review exclusions quarterly

### Common FP Sources
| Detection | Common FP | Tuning |
|-----------|-----------|--------|
| Encoded PowerShell | IT automation scripts | Allowlist by user/host |
| LSASS access | AV/EDR scanning LSASS | Exclude AV process paths |
| Admin share access | GPO deployment | Exclude domain controllers |
| Service installation | Software deployment | Allowlist MSI/SCCM |

---

## 9. Performance Optimization

- **Be specific** - Use exact field matches over wildcards
- **Limit time range** - Smallest effective lookback window
- **Use indexed fields** - Search indexed fields before calculated ones
- **Batch IOC lookups** - Use lookup tables, not inline lists
- **Pre-filter** - Apply cheap filters before expensive operations
- **Accelerate** - Use data model acceleration (Splunk) or materialized views

---

## 10. Metrics & KPIs

| Metric | Target | Description |
|--------|--------|-------------|
| MTTD (Mean Time to Detect) | <1 hour | Time from attack to alert |
| MTTR (Mean Time to Respond) | <4 hours | Time from alert to containment |
| FP Rate | <10% per rule | False positives / total alerts |
| Detection Coverage | >70% MITRE | Techniques with active rules |
| Rule Count | Growing | Total active detection rules |
| Alert Volume | Manageable | Alerts per analyst per day (<50) |
| Automation Rate | >30% | Alerts with automated response |

---

*A good detection rule tells you WHAT happened, WHERE, WHEN, and gives you enough context to decide WHAT TO DO NEXT - all in the first 10 seconds of looking at it.*
