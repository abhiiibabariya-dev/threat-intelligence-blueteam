# Palo Alto XSOAR (Cortex XSOAR) Zero-to-Hero Training Guide

## 1. Introduction
Cortex XSOAR is Palo Alto Networks' SOAR platform (formerly Demisto). It provides playbook automation, case management, threat intelligence management, and 700+ integrations.

## 2. Architecture
- **XSOAR Server** - Central engine (on-prem or cloud)
- **Engines** - Remote execution points for network-segmented environments
- **War Room** - Real-time investigation workspace per incident
- **Marketplace** - Content packs with playbooks, integrations, dashboards

## 3. Key Concepts
- **Incidents** - Security events to investigate
- **Playbooks** - Automated workflows (YAML or visual editor)
- **Integrations** - Tool connections (700+ available)
- **Scripts** - Python/PowerShell automation scripts
- **Indicators** - IOCs with reputation and relationships
- **Layouts** - Custom incident views
- **War Room** - Chat + actions + evidence per incident

## 4. Playbook Development
### Visual Editor
Drag-and-drop with: Tasks, Conditions, Loops, Sub-playbooks, Manual tasks, Sections

### YAML Format
```yaml
id: phishing-investigation
name: Phishing Investigation
starttaskid: "0"
tasks:
  "0":
    id: "0"
    taskid: start
    type: start
    nexttasks:
      '#none#': ["1"]
  "1":
    id: "1"
    taskid: extract-indicators
    type: regular
    task:
      script: ExtractIndicatorsFromEmailBody
    nexttasks:
      '#none#': ["2"]
  "2":
    id: "2"
    taskid: check-reputation
    type: playbook
    task:
      playbookName: TI - Indicator Enrichment
    nexttasks:
      '#none#': ["3"]
  "3":
    id: "3"
    taskid: decide
    type: condition
    conditions:
      - label: Malicious
        condition:
          - - left: {value: {simple: "indicator.verdict"}}
              operator: isEqualString
              right: {value: {simple: "Malicious"}}
    nexttasks:
      Malicious: ["4"]
      '#default#': ["5"]
```

## 5. Integration Development
```python
# Custom integration template
import demistomock as demisto
from CommonServerPython import *

def check_ip_command():
    ip = demisto.args().get('ip')
    # Call external API
    response = requests.get(f'https://api.example.com/ip/{ip}')
    data = response.json()

    readable = tableToMarkdown('IP Reputation', data)
    return CommandResults(
        readable_output=readable,
        outputs_prefix='CustomTI.IP',
        outputs_key_field='ip',
        outputs=data
    )

def main():
    command = demisto.command()
    if command == 'custom-check-ip':
        return_results(check_ip_command())

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
```

## 6. War Room
- Real-time collaboration per incident
- Chat between analysts
- Run commands inline: `!ip ip=1.2.3.4 using=VirusTotal`
- Evidence collection and notes
- Full audit trail of all actions

## 7. Indicator Management
- Central IOC database
- Auto-enrichment on ingestion
- Relationships between indicators
- Expiration policies
- TI feed integration (TAXII, STIX, CSV)

## 8. Marketplace
Pre-built content packs for common use cases:
- Phishing Investigation
- Malware Investigation
- Access Investigation
- Endpoint Enrichment
- TI Management

## 9. API
```bash
# Create incident
curl -X POST 'https://xsoar/incident' \
  -H "Authorization: $API_KEY" \
  -d '{"name":"Suspicious Activity","type":"Phishing","severity":3}'

# Run command
curl -X POST 'https://xsoar/entry' \
  -H "Authorization: $API_KEY" \
  -d '{"investigationId":"1","data":"!ip ip=1.2.3.4"}'
```

## 10. Labs
### Lab 1: Phishing Playbook
1. Install Phishing content pack
2. Configure email integration
3. Create test phishing incident
4. Run playbook and review results

### Lab 2: Custom Integration
1. Write Python integration for custom TI API
2. Test in War Room with `!command`
3. Incorporate into playbook

---
*Compatible with Cortex XSOAR 8.x | Last updated March 2026*
