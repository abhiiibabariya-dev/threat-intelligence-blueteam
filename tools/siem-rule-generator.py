#!/usr/bin/env python3
"""
SIEM Rule Generator
Converts fetched IOCs into platform-specific detection rules for 14+ SIEM platforms.

Usage:
    python siem-rule-generator.py --input ./output/threat_intel.json --platforms all
    python siem-rule-generator.py --input ./output/threat_intel.json --platforms splunk sentinel wazuh
"""

import argparse
import json
import os
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("siem-rule-generator")


class SIEMRuleGenerator:
    """Generate detection rules for multiple SIEM platforms from IOCs."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.generators = {
            "splunk": self.generate_splunk,
            "sentinel": self.generate_sentinel,
            "qradar": self.generate_qradar,
            "elastic": self.generate_elastic,
            "chronicle": self.generate_chronicle,
            "arcsight": self.generate_arcsight,
            "fortisiem": self.generate_fortisiem,
            "exabeam": self.generate_exabeam,
            "logrhythm": self.generate_logrhythm,
            "securonix": self.generate_securonix,
            "mcafee_esm": self.generate_mcafee_esm,
            "logpoint": self.generate_logpoint,
            "insightidr": self.generate_insightidr,
            "wazuh": self.generate_wazuh,
        }

    def generate_all(self, iocs: list, output_dir: str, platforms: Optional[list[str]] = None) -> None:
        """Generate rules for all or specified platforms."""
        os.makedirs(output_dir, exist_ok=True)
        target_platforms = platforms or list(self.generators.keys())
        ip_iocs = [i for i in iocs if hasattr(i, "ioc_type") and i.ioc_type in ("ip", "ipv4", "ipv6")]
        domain_iocs = [i for i in iocs if hasattr(i, "ioc_type") and i.ioc_type == "domain"]
        hash_iocs = [i for i in iocs if hasattr(i, "ioc_type") and i.ioc_type.startswith("hash")]
        url_iocs = [i for i in iocs if hasattr(i, "ioc_type") and i.ioc_type == "url"]

        ioc_groups = {"ip": ip_iocs, "domain": domain_iocs, "hash": hash_iocs, "url": url_iocs}

        for platform in target_platforms:
            gen_func = self.generators.get(platform)
            if gen_func:
                try:
                    platform_dir = os.path.join(output_dir, "generated-rules", platform)
                    os.makedirs(platform_dir, exist_ok=True)
                    gen_func(ioc_groups, platform_dir)
                    logger.info(f"Generated rules for {platform}")
                except Exception as e:
                    logger.error(f"Error generating {platform} rules: {e}")

    # -----------------------------------------------------------------------
    # Splunk SPL
    # -----------------------------------------------------------------------
    def generate_splunk(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if ioc_groups.get("ip"):
            ips = " OR ".join(f'dest_ip="{i.value}"' for i in ioc_groups["ip"][:100])
            rules.append(f"""| `---- Threat Intel - Malicious IP Detection ----`
| `---- Generated: {timestamp} ----`
| `---- Source: Threat Intel Auto-Fetcher ----`
index=* sourcetype=*firewall* OR sourcetype=*proxy* OR sourcetype=*dns*
  ({ips})
| eval severity="critical"
| eval mitre_technique="T1071"
| table _time src_ip dest_ip dest_port action severity mitre_technique
| sort -_time""")

        if ioc_groups.get("domain"):
            domains = " OR ".join(f'query="{i.value}"' for i in ioc_groups["domain"][:100])
            rules.append(f"""| `---- Threat Intel - Malicious Domain Detection ----`
index=* sourcetype=*dns* OR sourcetype=*proxy*
  ({domains})
| eval severity="high"
| eval mitre_technique="T1071.001"
| table _time src_ip query answer action severity
| sort -_time""")

        if ioc_groups.get("hash"):
            hashes = " OR ".join(f'file_hash="{i.value}"' for i in ioc_groups["hash"][:100])
            rules.append(f"""| `---- Threat Intel - Malicious Hash Detection ----`
index=* sourcetype=*endpoint* OR sourcetype=*sysmon*
  ({hashes})
| eval severity="critical"
| eval mitre_technique="T1204"
| table _time host file_name file_hash file_path process_name severity
| sort -_time""")

        with open(os.path.join(output_dir, "ti-detection-rules.spl"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # Microsoft Sentinel KQL
    # -----------------------------------------------------------------------
    def generate_sentinel(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if ioc_groups.get("ip"):
            ip_list = ", ".join(f'"{i.value}"' for i in ioc_groups["ip"][:100])
            rules.append(f"""// Threat Intel - Malicious IP Detection
// Generated: {timestamp}
// Source: Threat Intel Auto-Fetcher
let MaliciousIPs = dynamic([{ip_list}]);
union
  CommonSecurityLog,
  SigninLogs,
  AzureActivity,
  OfficeActivity
| where TimeGenerated > ago(1h)
| where DestinationIP in (MaliciousIPs)
    or SourceIP in (MaliciousIPs)
    or CallerIpAddress in (MaliciousIPs)
| extend AlertSeverity = "High"
| extend MITRETechnique = "T1071"
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction, Activity, AlertSeverity""")

        if ioc_groups.get("domain"):
            domain_list = ", ".join(f'"{i.value}"' for i in ioc_groups["domain"][:100])
            rules.append(f"""// Threat Intel - Malicious Domain Detection
let MaliciousDomains = dynamic([{domain_list}]);
DnsEvents
| where TimeGenerated > ago(1h)
| where Name has_any (MaliciousDomains)
| extend AlertSeverity = "High"
| project TimeGenerated, ClientIP, Name, QueryType, IPAddresses, AlertSeverity""")

        if ioc_groups.get("hash"):
            hash_list = ", ".join(f'"{i.value}"' for i in ioc_groups["hash"][:100])
            rules.append(f"""// Threat Intel - Malicious File Hash Detection
let MaliciousHashes = dynamic([{hash_list}]);
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where SHA256 in (MaliciousHashes) or MD5 in (MaliciousHashes)
| extend AlertSeverity = "Critical"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, MD5, ActionType""")

        with open(os.path.join(output_dir, "ti-detection-rules.kql"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # IBM QRadar AQL
    # -----------------------------------------------------------------------
    def generate_qradar(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []

        if ioc_groups.get("ip"):
            ip_list = ", ".join(f"'{i.value}'" for i in ioc_groups["ip"][:100])
            rules.append(f"""-- Threat Intel - Malicious IP Detection
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time",
       sourceip AS "Source IP",
       destinationip AS "Destination IP",
       destinationport AS "Dest Port",
       CATEGORYNAME(category) AS "Category",
       PROTOCOLNAME(protocolid) AS "Protocol"
FROM events
WHERE destinationip IN ({ip_list})
   OR sourceip IN ({ip_list})
LAST 1 HOURS""")

        if ioc_groups.get("domain"):
            domain_conditions = " OR ".join(f"DOMAINNAME(dnsdomain) = '{i.value}'" for i in ioc_groups["domain"][:50])
            rules.append(f"""-- Threat Intel - Malicious Domain Detection
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS "Time",
       sourceip AS "Source IP",
       DOMAINNAME(dnsdomain) AS "Domain",
       CATEGORYNAME(category) AS "Category"
FROM events
WHERE ({domain_conditions})
LAST 1 HOURS""")

        with open(os.path.join(output_dir, "ti-detection-rules.aql"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # Elastic KQL/EQL
    # -----------------------------------------------------------------------
    def generate_elastic(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []

        if ioc_groups.get("ip"):
            ip_list = " or ".join(f'destination.ip: "{i.value}"' for i in ioc_groups["ip"][:50])
            rules.append(f"""// Threat Intel - Malicious IP Detection
// KQL Query
{ip_list}""")

        # Also generate as TOML detection rule
        if ioc_groups.get("ip"):
            ip_values = ", ".join(f'"{i.value}"' for i in ioc_groups["ip"][:50])
            toml_rule = f"""[metadata]
creation_date = "{datetime.now(timezone.utc).strftime("%Y/%m/%d")}"
integration = ["endpoint"]
maturity = "production"

[rule]
author = ["Threat Intel Auto-Fetcher"]
description = "Detects connections to known malicious IP addresses from threat intelligence feeds."
name = "Threat Intel - Malicious IP Communication"
risk_score = 73
severity = "high"
type = "query"
query = 'destination.ip : ({ip_values})'

[rule.threat]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1071"
name = "Application Layer Protocol"

[rule.threat.tactic]
id = "TA0011"
name = "Command and Control"
"""
            with open(os.path.join(output_dir, "ti-malicious-ip.toml"), "w") as f:
                f.write(toml_rule)

        with open(os.path.join(output_dir, "ti-detection-rules.kql"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # Google Chronicle YARA-L
    # -----------------------------------------------------------------------
    def generate_chronicle(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []

        if ioc_groups.get("ip"):
            ip_list = ", ".join(f'"{i.value}"' for i in ioc_groups["ip"][:50])
            rules.append(f"""rule threat_intel_malicious_ip {{
  meta:
    author = "Threat Intel Auto-Fetcher"
    description = "Detects communication with known malicious IPs"
    severity = "HIGH"
    mitre_attack = "T1071"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.target.ip in [{ip_list}]

  condition:
    $e
}}""")

        if ioc_groups.get("domain"):
            domain_list = ", ".join(f'"{i.value}"' for i in ioc_groups["domain"][:50])
            rules.append(f"""rule threat_intel_malicious_domain {{
  meta:
    author = "Threat Intel Auto-Fetcher"
    description = "Detects DNS queries to known malicious domains"
    severity = "HIGH"
    mitre_attack = "T1071.001"

  events:
    $e.metadata.event_type = "NETWORK_DNS"
    $e.network.dns.questions.name in [{domain_list}]

  condition:
    $e
}}""")

        with open(os.path.join(output_dir, "ti-detection-rules.yaral"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # ArcSight ESM XML
    # -----------------------------------------------------------------------
    def generate_arcsight(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            conditions = "\n".join(
                f'        <Condition field="destinationAddress" operator="Equals" value="{i.value}"/>'
                for i in ioc_groups["ip"][:50]
            )
            rules.append(f"""<?xml version="1.0" encoding="UTF-8"?>
<Rule name="Threat Intel - Malicious IP Detection" enabled="true">
  <Description>Detects communication with threat intel malicious IPs</Description>
  <Severity>8</Severity>
  <ConditionGroup operator="OR">
{conditions}
  </ConditionGroup>
  <Actions>
    <Action type="generateCorrelationEvent"/>
    <Action type="sendNotification" template="ThreatIntel-Alert"/>
  </Actions>
</Rule>""")

        with open(os.path.join(output_dir, "ti-detection-rules.xml"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # FortiSIEM
    # -----------------------------------------------------------------------
    def generate_fortisiem(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            ip_csv = ",".join(i.value for i in ioc_groups["ip"][:50])
            rules.append(f"""<?xml version="1.0" encoding="UTF-8"?>
<Rule naturalId="TI-MaliciousIP-001" name="Threat Intel - Malicious IP Detection">
  <Description>Communication with threat intelligence malicious IPs</Description>
  <Severity>9</Severity>
  <IncidentCategory>Security</IncidentCategory>
  <SubPattern>
    <SingleEvtConstr>destIpAddr IN [{ip_csv}]</SingleEvtConstr>
    <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
  </SubPattern>
  <Action>CREATE_INCIDENT</Action>
</Rule>""")

        with open(os.path.join(output_dir, "ti-detection-rules.xml"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # Exabeam
    # -----------------------------------------------------------------------
    def generate_exabeam(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            ip_list = ", ".join(f'"{i.value}"' for i in ioc_groups["ip"][:50])
            rules.append(f"""# Exabeam Correlation Rule - Threat Intel Malicious IP
---
rule_name: "TI - Communication with Malicious IP"
description: "Detects network communication with known malicious IP addresses"
severity: "critical"
risk_score: 95
mitre_attack:
  - T1071
trigger:
  type: correlation
  conditions:
    - field: dest_ip
      operator: in
      values: [{ip_list}]
  time_window: 1h
entity: src_user
response:
  - create_notable_event
  - add_to_watchlist
  - trigger_playbook: "threat-intel-investigation"
""")

        with open(os.path.join(output_dir, "ti-detection-rules.yaml"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # LogRhythm
    # -----------------------------------------------------------------------
    def generate_logrhythm(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            ip_list = "|".join(i.value for i in ioc_groups["ip"][:50])
            rules.append(f"""# LogRhythm AI Engine Rule - Threat Intel
---
rule_name: "TI - Malicious IP Communication"
rule_type: "threshold"
description: "Detects communication with known malicious IPs from threat feeds"
severity: "critical"
risk_rating: 10
common_event: "Threat Intel Match"
filter:
  log_source_type: "Firewall,Proxy,DNS"
  direction: "outbound"
  destination_host_regex: "{ip_list}"
threshold:
  count: 1
  time_window_seconds: 3600
  group_by: "origin_host"
actions:
  - create_alarm
  - add_to_list: "Compromised Hosts"
  - smartresponse: "Block IP at Firewall"
""")

        with open(os.path.join(output_dir, "ti-detection-rules.yaml"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # Securonix Spotter
    # -----------------------------------------------------------------------
    def generate_securonix(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            ip_filter = " OR ".join(f'destinationaddress = "{i.value}"' for i in ioc_groups["ip"][:50])
            rules.append(f"""# Securonix Spotter Query - Threat Intel Malicious IP
# Usage: Run in Spotter search interface
index = activity AND ({ip_filter}) AND timeline = "Last 1 Hour"
| select rawevent, sourceaddress, destinationaddress, destinationport, datetime
| sort -datetime""")

        if ioc_groups.get("domain"):
            domain_filter = " OR ".join(f'requesturl CONTAINS "{i.value}"' for i in ioc_groups["domain"][:50])
            rules.append(f"""# Securonix Spotter Query - Threat Intel Malicious Domain
index = activity AND ({domain_filter}) AND timeline = "Last 1 Hour"
| select rawevent, sourceaddress, requesturl, datetime
| sort -datetime""")

        with open(os.path.join(output_dir, "ti-detection-rules.spotter"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # McAfee ESM (Trellix)
    # -----------------------------------------------------------------------
    def generate_mcafee_esm(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            conditions = "\n".join(
                f'      <FilterCondition field="DST_IP" operator="EQUALS" value="{i.value}"/>'
                for i in ioc_groups["ip"][:50]
            )
            rules.append(f"""<?xml version="1.0" encoding="UTF-8"?>
<CorrelationRule name="TI - Malicious IP Detection" severity="90" normalization="true">
  <Description>Threat intelligence feed - malicious IP communication</Description>
  <Filter operator="OR">
{conditions}
  </Filter>
  <Correlation>
    <TimeWindow value="3600"/>
    <GroupBy field="SRC_IP"/>
    <Threshold count="1"/>
  </Correlation>
  <Actions>
    <Action type="createAlarm" assignee="SOC-L1"/>
    <Action type="addToWatchlist" name="TI-Malicious-IPs"/>
  </Actions>
</CorrelationRule>""")

        with open(os.path.join(output_dir, "ti-detection-rules.xml"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # LogPoint LPQL
    # -----------------------------------------------------------------------
    def generate_logpoint(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            ip_list = " OR ".join(f'destination_address="{i.value}"' for i in ioc_groups["ip"][:50])
            rules.append(f"""# LogPoint LPQL - Threat Intel Malicious IP Detection
# Timerange: Last 1 hour
({ip_list})
| chart count() by source_address, destination_address, destination_port
| search count > 0
| rename source_address as "Source IP", destination_address as "Malicious IP"
""")

        if ioc_groups.get("domain"):
            domain_list = " OR ".join(f'query="{i.value}"' for i in ioc_groups["domain"][:50])
            rules.append(f"""# LogPoint LPQL - Threat Intel Malicious Domain Detection
({domain_list})
| chart count() by source_address, query, answer
| search count > 0
""")

        with open(os.path.join(output_dir, "ti-detection-rules.lp"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # Rapid7 InsightIDR LEQL
    # -----------------------------------------------------------------------
    def generate_insightidr(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            ip_filter = " OR ".join(f'destination_address = "{i.value}"' for i in ioc_groups["ip"][:50])
            rules.append(f"""// InsightIDR LEQL - Threat Intel Malicious IP Detection
// Log Set: Firewall Activity
where({ip_filter})
groupby(source_address, destination_address)
sort(desc)""")

        if ioc_groups.get("domain"):
            domain_filter = " OR ".join(f'query = "{i.value}"' for i in ioc_groups["domain"][:50])
            rules.append(f"""// InsightIDR LEQL - Threat Intel Malicious Domain Detection
// Log Set: DNS Query
where({domain_filter})
groupby(source_address, query)
sort(desc)""")

        with open(os.path.join(output_dir, "ti-detection-rules.leql"), "w") as f:
            f.write("\n\n".join(rules))

    # -----------------------------------------------------------------------
    # Wazuh XML Rules
    # -----------------------------------------------------------------------
    def generate_wazuh(self, ioc_groups: dict, output_dir: str) -> None:
        rules = []
        if ioc_groups.get("ip"):
            ip_regex = "|".join(i.value.replace(".", "\\.") for i in ioc_groups["ip"][:50])
            rules.append(f"""<!-- Wazuh Rules - Threat Intel Malicious IP Detection -->
<group name="threat_intel,">
  <rule id="100200" level="14">
    <if_sid>5700,5710</if_sid>
    <srcip negate="no">{ip_regex}</srcip>
    <description>Threat Intel: Connection from known malicious IP $(srcip)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>threat_intel,malicious_ip,</group>
    <options>alert_by_email</options>
  </rule>

  <rule id="100201" level="14">
    <if_sid>5700,5710</if_sid>
    <dstip negate="no">{ip_regex}</dstip>
    <description>Threat Intel: Connection to known malicious IP $(dstip)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>threat_intel,malicious_ip,</group>
    <options>alert_by_email</options>
  </rule>
</group>""")

        if ioc_groups.get("domain"):
            domain_regex = "|".join(i.value.replace(".", "\\.") for i in ioc_groups["domain"][:50])
            rules.append(f"""<group name="threat_intel,dns,">
  <rule id="100210" level="12">
    <if_sid>5300,5301</if_sid>
    <regex>{domain_regex}</regex>
    <description>Threat Intel: DNS query to malicious domain</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
    <group>threat_intel,malicious_domain,</group>
  </rule>
</group>""")

        with open(os.path.join(output_dir, "ti-detection-rules.xml"), "w") as f:
            f.write("\n\n".join(rules))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SIEM detection rules from threat intelligence IOCs")
    parser.add_argument("--input", required=True, help="Path to IOC JSON file from threat-intel-fetcher")
    parser.add_argument("--output-dir", default="./generated-rules", help="Output directory for rules")
    parser.add_argument("--platforms", nargs="+", default=["all"],
                        help="Target SIEM platforms (splunk, sentinel, qradar, elastic, chronicle, arcsight, "
                             "fortisiem, exabeam, logrhythm, securonix, mcafee_esm, logpoint, insightidr, wazuh, all)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    with open(input_path) as f:
        data = json.load(f)

    # Reconstruct IOC objects from JSON
    from threat_intel_fetcher import IOC
    iocs = []
    for item in data.get("iocs", []):
        iocs.append(IOC(
            ioc_type=item["ioc_type"],
            value=item["value"],
            source=item["source"],
            confidence=item.get("confidence", 50),
            tlp=item.get("tlp", "GREEN"),
            tags=item.get("tags", []),
            description=item.get("description", ""),
            first_seen=item.get("first_seen"),
            last_seen=item.get("last_seen"),
            mitre_techniques=item.get("mitre_techniques", []),
            severity=item.get("severity", "medium"),
        ))

    logger.info(f"Loaded {len(iocs)} IOCs from {input_path}")

    generator = SIEMRuleGenerator()
    platforms = None if "all" in args.platforms else args.platforms
    generator.generate_all(iocs, args.output_dir, platforms)
    logger.info("Rule generation complete!")


if __name__ == "__main__":
    main()
