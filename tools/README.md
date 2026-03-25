# Threat Intelligence Auto-Fetcher & SIEM Rule Generator

Automated tools for fetching threat intelligence from OSINT feeds and generating detection rules for 14+ SIEM platforms.

## Components

### 1. `threat-intel-fetcher.py` - IOC Fetcher
Fetches indicators of compromise from multiple sources:

| Feed | Type | API Key Required |
|------|------|-----------------|
| URLhaus (abuse.ch) | Malicious URLs, domains, IPs | No |
| MalwareBazaar (abuse.ch) | Malware hashes | No |
| ThreatFox (abuse.ch) | Mixed IOCs | No |
| Feodo Tracker (abuse.ch) | Botnet C2 IPs | No |
| AlienVault OTX | All IOC types | Yes (free) |
| MITRE ATT&CK | Techniques & TTPs | No |
| NIST NVD | CVEs | Optional |
| CISA KEV | Exploited vulns | No |
| Emerging Threats | IPs, Suricata rules | No |

### 2. `siem-rule-generator.py` - Rule Generator
Converts fetched IOCs into platform-specific detection rules:

- **Splunk** (SPL)
- **Microsoft Sentinel** (KQL)
- **IBM QRadar** (AQL)
- **Elastic SIEM** (KQL/EQL/TOML)
- **Google Chronicle** (YARA-L)
- **ArcSight** (XML correlation rules)
- **FortiSIEM** (XML rules)
- **Exabeam Fusion** (YAML correlation rules)
- **LogRhythm** (AI Engine YAML)
- **Securonix** (Spotter queries)
- **McAfee ESM / Trellix** (XML correlation rules)
- **LogPoint** (LPQL queries)
- **Rapid7 InsightIDR** (LEQL queries)
- **Wazuh** (XML rules)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Fetch all feeds, output as JSON
python threat-intel-fetcher.py --all --format json --output-dir ./output

# Fetch specific feeds
python threat-intel-fetcher.py --feed urlhaus --feed threatfox --format csv

# Fetch and generate SIEM rules
python threat-intel-fetcher.py --all --generate-rules

# Generate rules from existing IOC file
python siem-rule-generator.py --input ./output/threat_intel.json --platforms all

# Generate rules for specific platforms
python siem-rule-generator.py --input ./output/threat_intel.json --platforms splunk sentinel wazuh

# Schedule automatic fetching every 60 minutes
python threat-intel-fetcher.py --all --schedule 60

# Output as STIX 2.1
python threat-intel-fetcher.py --all --format stix2
```

## Configuration

Edit `feed-config.yaml` to:
- Enable/disable specific feeds
- Set API keys (via environment variables)
- Configure refresh intervals
- Set proxy settings
- Choose output formats
- Select target SIEM platforms for rule generation

### Environment Variables
```bash
export OTX_API_KEY="your-alienvault-otx-api-key"
export NVD_API_KEY="your-nist-nvd-api-key"  # Optional, increases rate limit
```

## Output Formats

- **JSON** - Structured IOC data with metadata
- **CSV** - Flat file for spreadsheet/SIEM import
- **STIX 2.1** - Standard threat intelligence format

## Architecture

```
threat-intel-fetcher.py  -->  OSINT Feeds (abuse.ch, OTX, MITRE, NIST, CISA)
        |
        v
    IOC Database (JSON/CSV/STIX2)
        |
        v
siem-rule-generator.py  -->  Platform-specific detection rules
        |
        v
    Generated Rules (SPL, KQL, AQL, YARA-L, XML, YAML, LEQL, LPQL)
```
