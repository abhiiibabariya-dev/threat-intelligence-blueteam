# Threat Intelligence - Blue Team Toolkit

A collection of tools, rules, and scripts for blue team operations including threat intelligence gathering, IOC management, log analysis, and incident response.

## Structure

```
.
├── ioc/                  # Indicators of Compromise databases
│   ├── feeds.yaml        # Threat intel feed configuration
│   └── ioc_manager.py    # IOC collection and enrichment tool
├── rules/
│   ├── sigma/            # Sigma detection rules for SIEM
│   └── yara/             # YARA rules for malware detection
├── scripts/
│   ├── log_analyzer.py   # Log analysis and anomaly detection
│   ├── network_scan.py   # Network baseline and monitoring
│   └── hash_checker.py   # File hash reputation checker
├── playbooks/            # Incident response playbooks
│   └── ir_checklist.yaml # IR checklist templates
└── config/
    └── settings.yaml     # Global configuration
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure threat intel feeds
cp config/settings.yaml.example config/settings.yaml
# Edit settings.yaml with your API keys

# Collect IOCs from configured feeds
python ioc/ioc_manager.py collect

# Run log analysis
python scripts/log_analyzer.py --input /var/log/syslog

# Check file hashes against threat intel
python scripts/hash_checker.py --hash <sha256>
```

## Features

- **IOC Management**: Aggregate and deduplicate indicators from multiple threat feeds (OTX, AbuseIPDB, VirusTotal, MISP)
- **Sigma Rules**: Detection rules compatible with major SIEMs (Splunk, Elastic, QRadar)
- **YARA Rules**: File scanning rules for common malware families and techniques
- **Log Analysis**: Pattern matching and anomaly detection across syslog, auth logs, and web server logs
- **Network Monitoring**: Baseline comparison and suspicious connection detection
- **Hash Checking**: Multi-source reputation lookup for file hashes
- **IR Playbooks**: Structured incident response checklists mapped to MITRE ATT&CK

## Requirements

- Python 3.9+
- See `requirements.txt` for Python dependencies

## License

MIT
