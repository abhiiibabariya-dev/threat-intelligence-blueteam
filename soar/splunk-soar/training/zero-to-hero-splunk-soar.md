# Splunk SOAR (Phantom) Zero-to-Hero Training Guide

## 1. Introduction
Splunk SOAR (formerly Phantom) is a Security Orchestration, Automation, and Response platform that automates security workflows, enriches alerts, and orchestrates responses across your security stack.

## 2. Architecture
- **Platform**: On-prem or cloud deployment
- **Apps**: 300+ integrations (EDR, SIEM, firewall, email, TI, ticketing)
- **Playbooks**: Visual drag-and-drop or Python code
- **Containers/Artifacts**: Events and their IOCs
- **Assets**: Configured tool connections (API keys, credentials)
- **Custom Functions**: Reusable Python functions

## 3. Key Concepts

### Containers
A container = an event/incident. Contains artifacts (IOCs like IPs, hashes, URLs).

### Artifacts
Individual indicators within a container. Each has a CEF (Common Event Format) with fields like `sourceAddress`, `destinationAddress`, `fileHash`, `requestURL`.

### Apps & Actions
- **App** = integration with a product (VirusTotal, CrowdStrike, Exchange)
- **Action** = specific operation ("ip reputation", "block hash", "quarantine email")

### Playbooks
Automated workflows that:
1. Trigger on container creation
2. Extract artifacts
3. Run enrichment actions
4. Make decisions based on results
5. Execute response actions
6. Update container status

## 4. Visual Playbook Editor
Drag-and-drop interface for building playbooks:
- **Start** block → trigger conditions
- **Action** blocks → run app actions
- **Decision** blocks → if/else logic
- **Filter** blocks → data filtering
- **Format** blocks → prepare data
- **Code** blocks → custom Python
- **End** block → set status/severity

## 5. Python Playbooks

### Structure
```python
import phantom.rules as phantom

@phantom.playbook_block()
def on_start(container):
    # Entry point
    phantom.act("ip reputation", parameters=[{"ip": "1.2.3.4"}],
                assets=["virustotal"], callback=process_results)

@phantom.playbook_block()
def process_results(action, success, container, results, handle):
    # Handle action results
    for result in results:
        data = result.get("data", {})
        # Process...
```

### Key API Methods
| Method | Purpose |
|--------|---------|
| `phantom.act()` | Run an app action |
| `phantom.get_artifacts()` | Get container artifacts |
| `phantom.add_note()` | Add investigation note |
| `phantom.set_severity()` | Update severity |
| `phantom.set_status()` | Update status |
| `phantom.create_container()` | Create new event |
| `phantom.add_artifact()` | Add IOC to container |
| `phantom.debug()` | Log debug message |
| `phantom.collect2()` | Collect results from previous action |
| `phantom.save_run_data()` | Persist data across blocks |

## 6. Common Playbook Patterns

### Pattern 1: Enrich-Decide-Respond
```
Start → Extract IOCs → Enrich (VT/OTX) → Decision (malicious?) → Block/Alert → End
```

### Pattern 2: Parallel Enrichment
```
Start → Extract IOCs → [VT check | OTX check | Shodan check] → Merge Results → Decision → Respond
```

### Pattern 3: Approval Workflow
```
Start → Enrich → Decision → If Critical: Auto-respond → If Medium: Request approval → Analyst approves → Respond
```

## 7. Asset Configuration
```
Settings → Assets → Configure New Asset
- Product: VirusTotal
- API Key: [your-api-key]
- Test Connectivity: Verify connection works
```

## 8. Custom Functions
Reusable Python functions callable from any playbook:
```python
# Custom function: calculate_risk_score
def calculate_risk_score(vt_score, otx_pulse_count, abuse_reports):
    risk = 0
    risk += min(vt_score * 5, 50)
    risk += min(otx_pulse_count * 10, 30)
    risk += min(abuse_reports * 5, 20)
    return min(risk, 100)
```

## 9. REST API
```bash
# Create container via API
curl -k -u admin:password -X POST https://phantom:8443/rest/container \
  -H "Content-Type: application/json" \
  -d '{"name":"Suspicious IP Alert","label":"events","severity":"medium"}'

# Add artifact
curl -k -u admin:password -X POST https://phantom:8443/rest/artifact \
  -H "Content-Type: application/json" \
  -d '{"container_id":1,"cef":{"sourceAddress":"1.2.3.4"},"label":"ip"}'

# Run playbook
curl -k -u admin:password -X POST https://phantom:8443/rest/playbook_run \
  -d '{"container_id":1,"playbook_id":10}'
```

## 10. Use Cases
1. **Phishing Triage** - Auto-extract IOCs, check reputation, block, quarantine
2. **Malware Containment** - Hash block, endpoint isolation, ticket creation
3. **Ransomware Response** - Isolate, snapshot, disable accounts, notify
4. **Threat Intel Enrichment** - Multi-source IOC enrichment, risk scoring
5. **Credential Compromise** - Password reset, session revoke, MFA enforce
6. **Vulnerability Response** - Scan results → prioritize → assign → track
7. **DDoS Mitigation** - Rate limit, geo-block, CDN activation
8. **Compliance Alert** - Policy violation → evidence collection → reporting

## 11. Labs

### Lab 1: Build Phishing Playbook
1. Create playbook in Visual Editor
2. Add: Extract artifacts → Check VT → Decision → Block or Close
3. Test with sample phishing container

### Lab 2: IOC Enrichment
1. Build multi-source enrichment (VT + OTX + AbuseIPDB)
2. Aggregate results into risk score
3. Auto-escalate based on score

### Lab 3: Custom Python Playbook
1. Write Python playbook from scratch
2. Use phantom.act() for enrichment
3. Implement decision logic
4. Add response actions

---
*Compatible with Splunk SOAR 6.x*
