# BlueShell // Threat Intelligence & Blue Team Operations Platform

> A hacker-themed, open-source security operations platform with detection rules, zero-to-hero training, and automated tools for 14 SIEMs, 4 EDRs, 3 XDRs, and 7 SOAR platforms.

**[Launch BlueShell Web App](https://yourusername.github.io/threat-intelligence-blueteam/)** | **[View on GitHub](https://github.com/yourusername/threat-intelligence-blueteam)**

---

## What is BlueShell?

BlueShell is a comprehensive, community-driven security operations toolkit that provides:

- **500+ Detection Rules** mapped to MITRE ATT&CK across 14 SIEM platforms
- **Zero-to-Hero Training** for every SIEM, EDR, XDR, and SOAR platform
- **Automated Threat Intel Fetcher** that pulls IOCs from 8 OSINT feeds and generates SIEM rules
- **Hacker-themed Web Interface** with terminal emulator, matrix rain, and live threat feed
- **Blue Team Resources** including IR playbooks, SOC runbooks, and threat hunting playbooks

## Live Web App

BlueShell includes a hacker-themed web interface with:
- Matrix rain background with scanline effects
- Interactive terminal (type `help`, `siem`, `fetch`, `mitre`)
- Live threat feed simulation
- MITRE ATT&CK coverage heatmap
- Platform navigation for all content

**To run locally:**
```bash
cd /path/to/threat-intelligence-blueteam
python3 -m http.server 8080
# Open http://localhost:8080
```

**To deploy on GitHub Pages:**
1. Push this repo to GitHub
2. Go to Settings > Pages
3. Source: Deploy from branch `main`, folder `/ (root)`
4. Your site will be live at `https://yourusername.github.io/threat-intelligence-blueteam/`

---

## Platform Coverage

### SIEM Platforms (14) - Rules + Training
| Platform | Rules | Training | Query Language |
|----------|-------|----------|----------------|
| Splunk | 9 SPL files + correlations + dashboards | Zero-to-Hero | SPL |
| Microsoft Sentinel | 6 KQL analytics + hunting queries | Zero-to-Hero | KQL |
| IBM QRadar | 5 AQL + XML correlations + reference sets | Zero-to-Hero | AQL |
| Elastic SIEM | 8 TOML + 4 EQL + dashboards | Zero-to-Hero | KQL / EQL |
| Google Chronicle | 5 YARA-L rules | Zero-to-Hero | YARA-L 2.0 |
| ArcSight ESM | XML correlation rules + FlexConnectors | Zero-to-Hero | CEF |
| FortiSIEM | XML detection rules | Zero-to-Hero | FortiSIEM QL |
| **Wazuh** | **10 XML rule files (90+ rules)** + decoders + active response | Zero-to-Hero | XML Rules |
| **Exabeam Fusion** | **7 YAML rule files** (UEBA insider threat) | Zero-to-Hero | Correlation YAML |
| **LogRhythm** | **7 YAML (AI Engine: statistical, behavioral, threshold, unique, trend)** | Zero-to-Hero | AI Engine |
| **Securonix** | **6 Spotter queries + 2 threat models** | Zero-to-Hero | Spotter |
| **McAfee ESM / Trellix** | **XML correlation rules** | Zero-to-Hero | ESM Rules |
| **LogPoint** | **6 LPQL query files** | Zero-to-Hero | LPQL |
| **Rapid7 InsightIDR** | **6 LEQL query files** | Zero-to-Hero | LEQL |

### EDR Platforms (4)
| Platform | Content | Training |
|----------|---------|----------|
| CrowdStrike Falcon | Custom IOA rules (YAML) + FQL queries | Zero-to-Hero |
| Microsoft Defender for Endpoint | Custom detections (JSON) + KQL queries | Zero-to-Hero |
| SentinelOne | STAR rules (JSON) + Deep Visibility queries | Zero-to-Hero |
| Carbon Black | Watchlists + threat feeds | Zero-to-Hero |

### XDR Platforms (3)
| Platform | Content | Training |
|----------|---------|----------|
| Palo Alto Cortex XDR | 20+ XQL hunting queries | Zero-to-Hero |
| Microsoft 365 Defender | 20+ cross-workload KQL queries | Zero-to-Hero |
| Trend Micro Vision One | 10 detection models (YAML) | Zero-to-Hero |

### SOAR Platforms (7)
| Platform | Content | Training |
|----------|---------|----------|
| Splunk SOAR | Python phishing playbook | Zero-to-Hero |
| Sentinel SOAR | Logic Apps guidance | Zero-to-Hero |
| Palo Alto XSOAR | Playbook YAML + integration template | Zero-to-Hero |
| QRadar SOAR | Playbook guidance | Zero-to-Hero |
| Shuffle (open-source) | Wazuh integration workflows | Zero-to-Hero |
| TheHive + Cortex | Analyzer/responder templates | Zero-to-Hero |
| FortiSOAR | Playbook guidance | Zero-to-Hero |

### AV / EPP
| Platform | Content |
|----------|---------|
| Windows Defender AV | ASR rules reference + training |
| EDR/XDR/AV | Comparison matrix |

---

## Tools

### Threat Intel Auto-Fetcher
```bash
pip install -r tools/requirements.txt

# Fetch IOCs from all OSINT feeds
python tools/threat-intel-fetcher.py --all --format json

# Generate SIEM rules from IOCs
python tools/siem-rule-generator.py --input output/threat_intel.json --platforms all
```

**Supported feeds:** abuse.ch (URLhaus, MalwareBazaar, ThreatFox, FeodoTracker), AlienVault OTX, MITRE ATT&CK, NIST NVD, CISA KEV

**Generates rules for:** All 14 SIEM platforms

---

## Blue Team Resources

| Resource | Description |
|----------|-------------|
| **Rule Creation Guide** | Detection-as-code, Sigma format, testing, lifecycle, metrics |
| **IR Playbooks** | 8 playbooks: Phishing, Ransomware, Data Breach, Insider Threat, DDoS, Supply Chain, Cloud, BEC |
| **Alert Triage Guide** | 5-minute triage framework, severity matrix, investigation checklists |
| **SOC Runbooks** | Daily operations, shift handover, hunting cadence, escalation matrix |
| **Threat Hunting** | 12 hypothesis-driven playbooks with SPL + KQL queries |
| **SOAR Comparison** | Side-by-side matrix of all 7 SOAR platforms |

---

## Directory Structure
```
blueshell/
├── index.html                    # Web app (GitHub Pages root)
├── css/hacker.css               # Hacker terminal theme
├── js/app.js                    # Web app logic
├── tools/                       # Automation tools
│   ├── threat-intel-fetcher.py  # OSINT IOC fetcher
│   ├── siem-rule-generator.py   # Multi-SIEM rule generator
│   └── feed-config.yaml         # Feed configuration
├── siem-rules/                  # 14 SIEM platforms
│   ├── splunk/                  # SPL rules + training
│   ├── microsoft-sentinel/      # KQL rules + training
│   ├── ibm-qradar/             # AQL rules + training
│   ├── elastic-siem/           # TOML/EQL rules + training
│   ├── chronicle/              # YARA-L rules + training
│   ├── arcsight/               # XML rules + training
│   ├── fortisiem/              # XML rules + training
│   ├── wazuh/                  # XML rules + decoders + training
│   ├── exabeam-fusion/         # YAML rules + training
│   ├── logrhythm/              # AI Engine rules + training
│   ├── securonix/              # Spotter queries + training
│   ├── mcafee-esm/             # XML correlation + training
│   ├── logpoint/               # LPQL queries + training
│   └── insightidr/             # LEQL queries + training
├── edr-rules/                   # 4 EDR platforms
│   ├── crowdstrike-falcon/     # IOA rules + training
│   ├── microsoft-defender-endpoint/ # KQL + training
│   ├── sentinelone/            # STAR rules + training
│   ├── carbon-black/           # Watchlists + training
│   └── antivirus-epp/          # AV comparison + Windows Defender
├── xdr-rules/                   # 3 XDR platforms
│   ├── palo-alto-cortex-xdr/   # XQL queries + training
│   ├── microsoft-365-defender/  # KQL queries + training
│   └── trend-micro-vision-one/ # Detection models + training
├── soar/                        # 7 SOAR platforms
│   ├── splunk-soar/            # Python playbooks + training
│   ├── sentinel-soar/          # Logic Apps + training
│   ├── palo-alto-xsoar/        # YAML playbooks + training
│   ├── qradar-soar/            # Training
│   ├── shuffle-soar/           # Wazuh workflows + training
│   ├── thehive-cortex/         # Analyzers + training
│   ├── fortisoar/              # Training
│   └── general/                # SOAR comparison + fundamentals
├── blue-team-resources/         # SOC operations
│   ├── detection-engineering/   # Rule creation guide
│   ├── incident-response/       # 8 IR playbooks
│   ├── alert-triage/           # Triage methodology
│   └── soc-runbooks/           # Daily SOC operations
└── threat-intelligence/         # TI resources
    ├── ioc-management/          # IOC lifecycle guide
    ├── mitre-attack-mapping/    # Coverage matrix
    └── threat-hunting/          # 12 hunting playbooks
```

---

## Contributing

1. Fork this repository
2. Create your feature branch (`git checkout -b feature/new-siem-rules`)
3. Add your detection rules, training content, or tools
4. Ensure MITRE ATT&CK mapping is included
5. Submit a Pull Request

### Contribution Ideas
- Additional detection rules for any platform
- New SIEM/EDR/XDR platform support
- Translated content (non-English)
- Bug fixes in detection rules
- New threat hunting playbooks
- SOAR playbook implementations

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

All content is provided as-is for educational and operational reference. Detection rules require testing, validation, and tuning before production deployment. The authors are not responsible for any issues arising from the use of this content.

---

**Built for the Blue Team community** | MITRE ATT&CK v15 | 186+ files | 14 SIEMs | 4 EDRs | 3 XDRs | 7 SOARs
