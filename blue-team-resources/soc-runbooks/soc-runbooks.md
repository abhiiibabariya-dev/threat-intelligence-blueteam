# SOC Runbooks & Standard Operating Procedures

## 1. Daily SOC Operations Checklist

### Morning Shift Start (0700)
- [ ] Review shift handover notes from previous shift
- [ ] Check SIEM dashboard for overnight critical/high alerts
- [ ] Verify all log sources are reporting (no gaps >1 hour)
- [ ] Review threat intel briefing (CISA, US-CERT, industry ISAC)
- [ ] Check security tool health (SIEM, EDR, firewall, proxy)
- [ ] Review open incidents and their status
- [ ] Check scheduled maintenance windows

### Continuous Operations
- [ ] Monitor SIEM alert queue - triage within SLA
- [ ] Process threat intelligence updates
- [ ] Respond to user-reported incidents
- [ ] Update incident tickets with progress
- [ ] Escalate per escalation matrix

### Shift End
- [ ] Complete shift handover document
- [ ] Document any ongoing investigations
- [ ] Update ticket statuses
- [ ] Brief incoming shift on active incidents
- [ ] Log shift metrics (alerts triaged, incidents created, MTTR)

## 2. Shift Handover Template

```
=== SOC SHIFT HANDOVER ===
Date: [Date]
Outgoing Shift: [Analyst Name] ([Time])
Incoming Shift: [Analyst Name] ([Time])

ACTIVE INCIDENTS:
- INC-001: [Brief description] - Status: [Investigating/Contained]
  Action needed: [What next shift should do]

- INC-002: ...

NOTABLE EVENTS:
- [Any significant alerts or trends observed]
- [Any system issues or outages]

PENDING TASKS:
- [ ] [Task 1]
- [ ] [Task 2]

THREAT INTEL:
- [Any new threats relevant to our environment]

TOOL STATUS:
- SIEM: [OK/Issue]
- EDR: [OK/Issue]
- Firewall: [OK/Issue]
```

## 3. Threat Hunting Cadence

| Frequency | Hunt Type | Examples |
|-----------|-----------|---------|
| Daily | IOC sweep | New TI indicators against 24h logs |
| Weekly | TTP hunt | LOLBAS, encoded PowerShell, lateral movement |
| Monthly | Deep dive | APT persistence, supply chain, cloud misconfig |
| Quarterly | Red team replay | Hunt for techniques from last pentest/red team |

## 4. IOC Management Procedures

### New IOC Ingestion
1. Receive IOC from feed/analyst/incident
2. Validate format and quality
3. Deduplicate against existing IOC database
4. Enrich with context (source, confidence, TLP)
5. Add to SIEM threat intel lookup/watchlist
6. Set expiration date based on IOC type:
   - IP addresses: 30 days
   - Domains: 90 days
   - File hashes: 1 year
   - URLs: 60 days
7. Monitor for matches

### IOC Lifecycle
```
Ingest → Validate → Enrich → Deploy → Monitor → Review → Expire/Renew
```

## 5. Vulnerability Management Integration

### Critical/High CVE Response (CVSS ≥ 7.0)
1. Receive CVE notification from vuln scanner/CISA KEV
2. Identify affected assets in CMDB
3. Assess exploitability (public exploit? active exploitation?)
4. Create detection rule for exploitation attempts
5. Coordinate with IT for emergency patching
6. Monitor for exploitation indicators post-patch

## 6. Compliance Monitoring

### PCI DSS Daily Checks
- [ ] Review privileged user activity logs
- [ ] Check for unauthorized access to cardholder data
- [ ] Verify FIM alerts on critical system files
- [ ] Confirm AV definitions are current (<24h old)

### Weekly Compliance Review
- [ ] Access review for sensitive systems
- [ ] Firewall rule change audit
- [ ] Failed login trend analysis
- [ ] Vulnerability scan results review

## 7. Reporting Templates

### Daily SOC Report
```
Date: [Date]
Total Alerts: [Count]
Alerts Triaged: [Count]
New Incidents: [Count]
Incidents Resolved: [Count]
MTTR: [Time]
False Positive Rate: [%]
Top Alert Categories: [List]
Notable Events: [Summary]
```

### Monthly SOC Metrics
- Alert volume trend (by source, severity, category)
- MTTD and MTTR trends
- MITRE ATT&CK technique coverage
- Detection rule changes (added, modified, retired)
- False positive rate by rule
- Analyst workload distribution
- SLA compliance rate

## 8. Tool Health Monitoring

| Tool | Check | Frequency | Alert If |
|------|-------|-----------|----------|
| SIEM | Log ingestion rate | 5 min | Drop >20% |
| SIEM | Search performance | 15 min | Latency >30s |
| EDR | Agent check-in | 1 hour | >5% offline |
| Firewall | Log forwarding | 5 min | No logs >10 min |
| Proxy | Log forwarding | 5 min | No logs >10 min |
| DNS | Query logging | 5 min | No logs >10 min |
| TI Feeds | Feed freshness | 1 hour | >24h stale |

## 9. Escalation Matrix

```
         ┌─────────────────────────────────────┐
Level 4: │ CISO / Executive Management         │ Active breach, regulatory
         ├─────────────────────────────────────┤
Level 3: │ IR Manager / Threat Hunter Lead     │ Confirmed compromise
         ├─────────────────────────────────────┤
Level 2: │ Senior SOC Analyst (L2/L3)          │ Complex investigation
         ├─────────────────────────────────────┤
Level 1: │ SOC Analyst (L1)                    │ Initial triage
         └─────────────────────────────────────┘
```

---

*SOC excellence is built on consistency. Follow the runbooks, document everything, and always ask "what did I miss?"*
