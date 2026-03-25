# IBM QRadar SOAR (Resilient) Zero-to-Hero Training Guide

## 1. Introduction
QRadar SOAR (formerly IBM Resilient) provides incident response automation with playbooks, integrations, and case management tightly integrated with QRadar SIEM.

## 2. Architecture
- **SOAR Platform** - On-prem or cloud
- **Playbooks** - Visual workflow automation
- **Functions** - Python-based integration actions
- **Rules** - Trigger automation on incident events
- **Scripts** - Custom Python/JavaScript logic
- **Integrations** - QRadar, EDR, TI, ticketing, email

## 3. Key Concepts
- **Incidents** - Cases with artifacts, tasks, notes, attachments
- **Artifacts** - IOCs (IP, hash, domain, URL, email)
- **Playbooks** - Automated workflows (visual designer)
- **Functions** - Reusable integration actions (Python)
- **Rules** - Event-driven triggers (on create, on update, on close)
- **Data Tables** - Custom structured data per incident

## 4. Playbook Design
```
Trigger: Incident Created (type = Phishing)
→ Extract Artifacts (IPs, URLs, hashes)
→ For Each Artifact:
  → Function: VirusTotal Lookup
  → Decision: Malicious?
    → Yes: Function: Block at Firewall + Update Severity
    → No: Add Note "Clean"
→ Function: Send Slack Notification
→ Task: Analyst Review
```

## 5. Functions (Python)
```python
# Function: check_ip_reputation
from resilient_lib import RequestsCommon

def check_ip_reputation_function(opts, fn_inputs):
    ip = fn_inputs.get("artifact_value")
    rc = RequestsCommon(opts)
    response = rc.execute("GET", f"https://api.virustotal.com/v3/ip_addresses/{ip}",
                          headers={"x-apikey": opts.get("vt_api_key")})
    result = response.json()
    malicious = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    return {"malicious_count": malicious, "ip": ip}
```

## 6. Rules
```
Rule: Auto-Enrich New Artifacts
Trigger: When artifact is added to incident
Conditions: Artifact type IN (IP Address, DNS Name, URL, Malware MD5 Hash)
Actions: Run playbook "Artifact Enrichment"
```

## 7. QRadar Integration
- Auto-create SOAR incidents from QRadar offenses
- Bidirectional sync (status, notes, artifacts)
- Run AQL queries from SOAR playbooks
- Close offense when SOAR incident resolved

## 8. API
```bash
# Create incident
curl -X POST 'https://soar/rest/orgs/201/incidents' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Brute Force Alert","discovered_date":1711324800000,"incident_type_ids":[6]}'

# Add artifact
curl -X POST 'https://soar/rest/orgs/201/incidents/2301/artifacts' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"IP Address","value":"1.2.3.4","description":"Attacking IP"}'
```

## 9. Labs
### Lab 1: Create Phishing Playbook
1. Create playbook with artifact extraction
2. Add VT enrichment function
3. Configure decision logic and response
4. Test with sample incident

---
*Compatible with QRadar SOAR 51.x | Last updated March 2026*
