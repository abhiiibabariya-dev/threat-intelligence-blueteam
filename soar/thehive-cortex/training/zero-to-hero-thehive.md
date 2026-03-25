# TheHive + Cortex Zero-to-Hero Training Guide

## 1. Introduction
TheHive is an open-source Security Incident Response Platform. Cortex is its companion for observable analysis (analyzers) and automated response (responders). Together they form an open-source SOAR stack.

## 2. Architecture
- **TheHive** - Case management, alert handling, task tracking
- **Cortex** - Observable analysis engine (analyzers + responders)
- **MISP** - Threat intelligence sharing (integrates natively)
- **Elasticsearch** - Backend storage for TheHive

## 3. Installation
```bash
# Docker Compose (recommended)
git clone https://github.com/TheHive-Project/Docker
cd Docker
docker-compose up -d
# TheHive: http://localhost:9000 (admin@thehive.local / secret)
# Cortex: http://localhost:9001
```

## 4. TheHive Concepts
- **Cases** - Investigations with tasks, observables, TTPs
- **Alerts** - Incoming events (from SIEM, email, etc.) that become cases
- **Observables** - IOCs attached to cases (IP, hash, domain, URL, email)
- **Tasks** - Investigation steps assigned to analysts
- **Task Logs** - Evidence and notes per task
- **Templates** - Pre-defined case/task structures
- **Custom Fields** - Extend case metadata

## 5. Cortex Analyzers
Run automated analysis on observables:
| Analyzer | Analyzes | Returns |
|----------|----------|---------|
| VirusTotal | IP, domain, hash, URL | Reputation score, detections |
| AbuseIPDB | IP | Abuse reports, confidence |
| Shodan | IP | Open ports, services, vulns |
| MISP | Any | Related events, attributes |
| OTX | IP, domain, hash | Pulse matches |
| URLhaus | URL, domain | Malware association |
| Yara | File | Rule matches |

### Custom Analyzer
```python
#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer

class CustomTIAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.api_key', None)

    def run(self):
        data = self.get_data()
        data_type = self.data_type  # ip, domain, hash, etc.
        # Call your TI API
        result = {"reputation": "malicious", "confidence": 85}
        self.report(result)

    def summary(self, raw):
        return {"taxonomies": [self.build_taxonomy("malicious", "CustomTI", "Reputation", "malicious")]}

if __name__ == '__main__':
    CustomTIAnalyzer().run()
```

## 6. Cortex Responders
Automated response actions:
```python
#!/usr/bin/env python3
from cortexutils.responder import Responder

class BlockIPResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.firewall_api = self.get_param('config.firewall_api')

    def run(self):
        ip = self.get_data()
        # Call firewall API to block
        requests.post(f'{self.firewall_api}/block', json={"ip": ip})
        self.report({"message": f"Blocked IP {ip}"})

if __name__ == '__main__':
    BlockIPResponder().run()
```

## 7. MISP Integration
- Auto-import alerts from MISP events
- Export case observables to MISP
- Bidirectional IOC sharing
- Attribute correlation

## 8. TheHive4py (Python API)
```python
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable, Alert

api = TheHiveApi('http://thehive:9000', 'API_KEY')

# Create case
case = Case(title='Phishing Investigation', description='Suspicious email reported',
            severity=2, tlp=2, tags=['phishing'])
response = api.create_case(case)

# Add observable
obs = CaseObservable(dataType='ip', data='1.2.3.4', message='Sender IP',
                      tlp=2, tags=['suspicious'])
api.create_case_observable(case_id, obs)

# Create alert (from SIEM)
alert = Alert(title='Brute Force', type='siem', source='Wazuh', sourceRef='alert-123',
              description='10+ failed logins', severity=3)
api.create_alert(alert)
```

## 9. Webhook Integration (Wazuh → TheHive)
```python
# Wazuh integration script: /var/ossec/integrations/custom-thehive.py
import json, requests, sys

alert = json.loads(open(sys.argv[1]).read())
thehive_url = "http://thehive:9000/api/alert"
headers = {"Authorization": "Bearer API_KEY", "Content-Type": "application/json"}

payload = {
    "title": alert["rule"]["description"],
    "description": f"Agent: {alert['agent']['name']}\nRule: {alert['rule']['id']}",
    "type": "wazuh",
    "source": "Wazuh",
    "sourceRef": alert["id"],
    "severity": min(alert["rule"]["level"] // 4, 3) + 1,
    "tags": ["wazuh", f"rule:{alert['rule']['id']}"]
}
requests.post(thehive_url, headers=headers, json=payload)
```

## 10. Labs
### Lab 1: Deploy TheHive + Cortex
1. Docker-compose deployment
2. Configure Cortex analyzers (VirusTotal, AbuseIPDB)
3. Create first case with observables
4. Run analyzers and review results

### Lab 2: Wazuh Integration
1. Configure Wazuh webhook to TheHive
2. Trigger alert from Wazuh
3. Promote alert to case in TheHive
4. Run Cortex analysis on observables

### Lab 3: Custom Analyzer
1. Write Python analyzer for custom TI source
2. Deploy to Cortex
3. Test from TheHive case

---
*Open source: https://thehive-project.org | Last updated March 2026*
