# SOC Alert Triage Guide

## 1. Triage Methodology

### The 5-Minute Triage Framework
Every alert should be triaged within 5 minutes:

1. **READ** (30 sec) - Alert name, severity, source, time
2. **CONTEXT** (1 min) - Who/what is affected? Expected behavior?
3. **ENRICH** (2 min) - Check TI, asset DB, user context, recent alerts
4. **DECIDE** (1 min) - True positive, false positive, or needs investigation?
5. **ACT** (30 sec) - Escalate, close with reason, or investigate

### Decision Tree
```
Alert Received
  ├─ Known FP pattern? → Close (document reason)
  ├─ Matches threat intel? → ESCALATE immediately
  ├─ Critical asset involved? → Priority investigation
  ├─ Privileged account? → Priority investigation
  ├─ Multiple related alerts? → Correlate → Investigate
  └─ Single low-severity? → Standard investigation
```

## 2. Severity Classification Matrix

| Severity | Criteria | SLA | Example |
|----------|----------|-----|---------|
| **P1 - Critical** | Active breach, data exfil, ransomware, critical system compromised | 15 min response | DCSync attack, ransomware encryption |
| **P2 - High** | Confirmed malicious activity, credential theft, lateral movement | 1 hour response | LSASS dump, PsExec on server |
| **P3 - Medium** | Suspicious activity requiring investigation, policy violation | 4 hour response | Encoded PowerShell, new admin account |
| **P4 - Low** | Informational, minor policy deviation, recon activity | 24 hour response | Port scan, system enumeration |

## 3. Alert Prioritization Framework

### Priority Score = Severity × Confidence × Asset Value

| Factor | Score 1 | Score 2 | Score 3 |
|--------|---------|---------|---------|
| **Severity** | Low (1) | Medium (2) | High/Critical (3) |
| **Confidence** | Low - likely FP (1) | Medium (2) | High - TI match (3) |
| **Asset Value** | Workstation (1) | Server (2) | Domain Controller/PII (3) |

**Priority:** 1-3 = Low, 4-9 = Medium, 10-18 = High, 19-27 = Critical

## 4. False Positive Identification

### Common FP Indicators
- Alert from known IT admin during change window
- Scheduled task/GPO deployment triggering process alerts
- AV scanning triggering LSASS access alerts
- Security tools (vulnerability scanners) triggering IDS
- Known software update behavior

### FP Documentation Template
```
Alert: [Rule Name]
FP Reason: [Why this is a false positive]
Evidence: [What confirms it's not malicious]
Recommendation: [Allowlist/tune/accept]
Analyst: [Name] | Date: [Date]
```

## 5. Escalation Procedures

| From | To | When |
|------|----|------|
| L1 Analyst | L2 Analyst | Cannot determine TP/FP in 15 min |
| L2 Analyst | L3/Threat Hunter | Confirmed compromise, needs deep investigation |
| L3 Analyst | IR Manager | Active incident requiring containment |
| IR Manager | CISO | Data breach, regulatory impact, media attention |

## 6. Investigation Checklists by Alert Type

### Brute Force / Authentication Failure
- [ ] Source IP: Internal or external? Known scanner?
- [ ] Target account: Service account? Admin? Regular user?
- [ ] Was there a successful login after failures?
- [ ] Check source IP against TI feeds
- [ ] Check if source IP has other suspicious activity
- [ ] Check if target account had recent password changes

### Suspicious Process Execution
- [ ] What is the parent process? Expected?
- [ ] What is the command line? Encoded? Download cradle?
- [ ] Is the process running from expected path?
- [ ] Is the user expected to run this?
- [ ] Network connections from the process?
- [ ] Child processes spawned?
- [ ] File system changes?

### Malware / EDR Alert
- [ ] What was detected? Hash reputation?
- [ ] Was it blocked or allowed?
- [ ] How did it arrive? (email, web, USB, lateral)
- [ ] Other endpoints with same hash?
- [ ] C2 connections observed?
- [ ] Persistence mechanisms created?

### Data Exfiltration
- [ ] Volume of data transferred?
- [ ] Destination: known cloud service or suspicious IP?
- [ ] User: authorized for this data?
- [ ] Time: during or outside business hours?
- [ ] Data classification of affected files?
- [ ] DLP policy violations?

## 7. Enrichment Workflows

### For IP Addresses
1. Internal/External check (RFC 1918)
2. GeoIP lookup
3. Threat intel (VirusTotal, AbuseIPDB, OTX)
4. Asset database lookup
5. Historical alert check (past 30 days)
6. DNS reverse lookup

### For File Hashes
1. VirusTotal lookup
2. Internal malware sandbox
3. Previous incidents with same hash
4. Signing certificate check
5. First/last seen in environment

### For User Accounts
1. HR status (active, terminated, contractor)
2. Role and access level
3. Recent password change
4. MFA status
5. Recent alert history
6. Peer group comparison

## 8. Documentation Standards

Every closed alert must have:
- **Determination**: TP, FP, or Benign True Positive
- **Evidence**: What confirmed the determination
- **Actions taken**: What was done in response
- **IOCs**: Any indicators extracted
- **Recommendations**: Tuning suggestions, follow-up actions

---

*"When in doubt, escalate. A false escalation costs minutes. A missed true positive costs millions."*
