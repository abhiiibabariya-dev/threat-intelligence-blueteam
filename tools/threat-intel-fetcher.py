#!/usr/bin/env python3
"""
Threat Intelligence Auto-Fetcher
Fetches IOCs from multiple OSINT feeds, MITRE ATT&CK, CVE databases.
Outputs in STIX2, CSV, JSON formats. Generates SIEM-specific detection rules.

Usage:
    python threat-intel-fetcher.py --config feed-config.yaml --output-dir ./output
    python threat-intel-fetcher.py --feed urlhaus --format csv
    python threat-intel-fetcher.py --all --schedule 60
"""

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logger = logging.getLogger("threat-intel-fetcher")


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=getattr(logging, level.upper()), format=LOG_FORMAT, handlers=handlers)


# ---------------------------------------------------------------------------
# HTTP Session with retries
# ---------------------------------------------------------------------------
def create_session(config: dict) -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=config.get("max_retries", 3),
        backoff_factor=config.get("retry_delay", 5),
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.timeout = config.get("request_timeout", 30)
    proxy_cfg = config.get("proxy", {})
    if proxy_cfg.get("enabled"):
        session.proxies = {"http": proxy_cfg["http"], "https": proxy_cfg["https"]}
    return session


# ---------------------------------------------------------------------------
# IOC Data Model
# ---------------------------------------------------------------------------
class IOC:
    """Normalized Indicator of Compromise."""

    def __init__(
        self,
        ioc_type: str,
        value: str,
        source: str,
        confidence: int = 50,
        tlp: str = "GREEN",
        tags: Optional[list[str]] = None,
        description: str = "",
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        mitre_techniques: Optional[list[str]] = None,
        severity: str = "medium",
        raw_data: Optional[dict] = None,
    ):
        self.ioc_type = ioc_type
        self.value = value
        self.source = source
        self.confidence = confidence
        self.tlp = tlp
        self.tags = tags or []
        self.description = description
        self.first_seen = first_seen or datetime.now(timezone.utc).isoformat()
        self.last_seen = last_seen or datetime.now(timezone.utc).isoformat()
        self.mitre_techniques = mitre_techniques or []
        self.severity = severity
        self.raw_data = raw_data or {}
        self.id = hashlib.sha256(f"{ioc_type}:{value}:{source}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "tlp": self.tlp,
            "tags": self.tags,
            "description": self.description,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "mitre_techniques": self.mitre_techniques,
            "severity": self.severity,
        }

    def to_stix2(self) -> dict:
        stix_type_map = {
            "ip": "ipv4-addr:value",
            "ipv4": "ipv4-addr:value",
            "ipv6": "ipv6-addr:value",
            "domain": "domain-name:value",
            "url": "url:value",
            "hash_md5": "file:hashes.MD5",
            "hash_sha1": "file:hashes.'SHA-1'",
            "hash_sha256": "file:hashes.'SHA-256'",
            "email": "email-addr:value",
        }
        pattern_key = stix_type_map.get(self.ioc_type, f"{self.ioc_type}:value")
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{self.id}-{hashlib.md5(self.value.encode()).hexdigest()[:20]}",
            "created": self.first_seen,
            "modified": self.last_seen,
            "name": f"{self.ioc_type}: {self.value}",
            "description": self.description,
            "pattern": f"[{pattern_key} = '{self.value}']",
            "pattern_type": "stix",
            "valid_from": self.first_seen,
            "confidence": self.confidence,
            "labels": self.tags,
            "external_references": [
                {"source_name": self.source, "description": f"Feed: {self.source}"}
            ],
        }


# ---------------------------------------------------------------------------
# Feed Fetchers
# ---------------------------------------------------------------------------
class BaseFetcher:
    """Base class for all feed fetchers."""

    def __init__(self, session: requests.Session, feed_config: dict):
        self.session = session
        self.config = feed_config
        self.name = feed_config.get("name", "Unknown")

    def fetch(self) -> list[IOC]:
        raise NotImplementedError

    def _get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> requests.Response:
        headers = headers or {}
        api_key = self.config.get("api_key", "")
        if api_key and api_key.startswith("${"):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, "")
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        resp = self.session.get(url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp

    def _post(self, url: str, data: Optional[dict] = None, headers: Optional[dict] = None) -> requests.Response:
        headers = headers or {"Content-Type": "application/x-www-form-urlencoded"}
        resp = self.session.post(url, data=data, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp


class URLhausFetcher(BaseFetcher):
    """Fetch malicious URLs from abuse.ch URLhaus."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        iocs: list[IOC] = []
        try:
            url = self.config["url"] + "urls/recent/"
            resp = self._post(url, data={"limit": "100"})
            data = resp.json()
            for entry in data.get("urls", [])[:200]:
                iocs.append(IOC(
                    ioc_type="url",
                    value=entry.get("url", ""),
                    source="URLhaus",
                    confidence=self.config.get("confidence", 80),
                    tlp=self.config.get("tlp", "GREEN"),
                    tags=entry.get("tags", []) or [],
                    description=f"Threat: {entry.get('threat', 'unknown')} | Status: {entry.get('url_status', 'unknown')}",
                    first_seen=entry.get("dateadded", ""),
                    last_seen=entry.get("last_online", ""),
                    severity="high" if entry.get("threat") == "malware_download" else "medium",
                ))
                host = entry.get("host", "")
                if host:
                    iocs.append(IOC(
                        ioc_type="domain" if not host.replace(".", "").isdigit() else "ip",
                        value=host,
                        source="URLhaus",
                        confidence=self.config.get("confidence", 80),
                        tlp=self.config.get("tlp", "GREEN"),
                        tags=entry.get("tags", []) or [],
                        description=f"Host serving malicious URL",
                    ))
            logger.info(f"  -> {len(iocs)} IOCs from URLhaus")
        except Exception as e:
            logger.error(f"Error fetching URLhaus: {e}")
        return iocs


class MalwareBazaarFetcher(BaseFetcher):
    """Fetch malware sample hashes from MalwareBazaar."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        iocs: list[IOC] = []
        try:
            resp = self._post(self.config["url"], data={"query": "get_recent", "selector": "100"})
            data = resp.json()
            for entry in data.get("data", [])[:200]:
                for hash_type in ["sha256_hash", "md5_hash", "sha1_hash"]:
                    h = entry.get(hash_type)
                    if h:
                        ioc_type_map = {"sha256_hash": "hash_sha256", "md5_hash": "hash_md5", "sha1_hash": "hash_sha1"}
                        iocs.append(IOC(
                            ioc_type=ioc_type_map[hash_type],
                            value=h,
                            source="MalwareBazaar",
                            confidence=self.config.get("confidence", 90),
                            tlp=self.config.get("tlp", "GREEN"),
                            tags=entry.get("tags", []) or [],
                            description=f"Malware: {entry.get('signature', 'unknown')} | Type: {entry.get('file_type', 'unknown')}",
                            first_seen=entry.get("first_seen", ""),
                            severity="critical" if entry.get("signature") else "high",
                        ))
            logger.info(f"  -> {len(iocs)} IOCs from MalwareBazaar")
        except Exception as e:
            logger.error(f"Error fetching MalwareBazaar: {e}")
        return iocs


class ThreatFoxFetcher(BaseFetcher):
    """Fetch IOCs from ThreatFox."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        iocs: list[IOC] = []
        try:
            resp = self._post(self.config["url"], data=json.dumps({"query": "get_iocs", "days": 7}),
                              headers={"Content-Type": "application/json"})
            data = resp.json()
            for entry in data.get("data", [])[:200]:
                ioc_value = entry.get("ioc", "")
                ioc_type = entry.get("ioc_type", "unknown")
                type_map = {"ip:port": "ip", "domain": "domain", "url": "url",
                            "md5_hash": "hash_md5", "sha256_hash": "hash_sha256"}
                iocs.append(IOC(
                    ioc_type=type_map.get(ioc_type, ioc_type),
                    value=ioc_value.split(":")[0] if "ip:port" in ioc_type else ioc_value,
                    source="ThreatFox",
                    confidence=self.config.get("confidence", 85),
                    tlp=self.config.get("tlp", "GREEN"),
                    tags=entry.get("tags", []) or [],
                    description=f"Malware: {entry.get('malware', 'unknown')} | Confidence: {entry.get('confidence_level', 0)}",
                    first_seen=entry.get("first_seen_utc", ""),
                    last_seen=entry.get("last_seen_utc", ""),
                    mitre_techniques=[entry["mitre_attack"]] if entry.get("mitre_attack") else [],
                    severity="high",
                ))
            logger.info(f"  -> {len(iocs)} IOCs from ThreatFox")
        except Exception as e:
            logger.error(f"Error fetching ThreatFox: {e}")
        return iocs


class FeodoTrackerFetcher(BaseFetcher):
    """Fetch botnet C2 IPs from Feodo Tracker."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        iocs: list[IOC] = []
        try:
            url = self.config["url"] + "/downloads/ipblocklist.json"
            resp = self._get(url)
            data = resp.json()
            for entry in data[:200]:
                iocs.append(IOC(
                    ioc_type="ip",
                    value=entry.get("ip_address", ""),
                    source="FeodoTracker",
                    confidence=self.config.get("confidence", 95),
                    tlp=self.config.get("tlp", "GREEN"),
                    tags=[entry.get("malware", "botnet")],
                    description=f"Botnet C2: {entry.get('malware', 'unknown')} | Port: {entry.get('port', 'N/A')} | Status: {entry.get('status', 'unknown')}",
                    first_seen=entry.get("first_seen", ""),
                    last_seen=entry.get("last_seen", ""),
                    severity="critical",
                ))
            logger.info(f"  -> {len(iocs)} IOCs from FeodoTracker")
        except Exception as e:
            logger.error(f"Error fetching FeodoTracker: {e}")
        return iocs


class AlienVaultOTXFetcher(BaseFetcher):
    """Fetch pulse IOCs from AlienVault OTX."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        iocs: list[IOC] = []
        api_key = self.config.get("api_key", "")
        if api_key.startswith("${"):
            api_key = os.environ.get(api_key[2:-1], "")
        if not api_key:
            logger.warning("OTX API key not set. Skipping AlienVault OTX.")
            return iocs
        try:
            headers = {"X-OTX-API-KEY": api_key}
            days = self.config.get("pulse_days", 30)
            modified_since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            url = f"{self.config['url']}/pulses/subscribed?modified_since={modified_since}&limit=50"
            resp = self._get(url, headers=headers)
            data = resp.json()
            for pulse in data.get("results", [])[:50]:
                pulse_tags = pulse.get("tags", [])
                attack_ids = [a.get("id", "") for a in pulse.get("attack_ids", [])]
                for indicator in pulse.get("indicators", [])[:100]:
                    type_map = {"IPv4": "ip", "IPv6": "ipv6", "domain": "domain", "hostname": "domain",
                                "URL": "url", "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1",
                                "FileHash-SHA256": "hash_sha256", "email": "email", "CVE": "cve"}
                    ioc_type = type_map.get(indicator.get("type", ""), indicator.get("type", "unknown"))
                    iocs.append(IOC(
                        ioc_type=ioc_type,
                        value=indicator.get("indicator", ""),
                        source="AlienVault-OTX",
                        confidence=self.config.get("confidence", 70),
                        tlp=self.config.get("tlp", "GREEN"),
                        tags=pulse_tags,
                        description=f"Pulse: {pulse.get('name', 'unknown')}",
                        first_seen=indicator.get("created", ""),
                        mitre_techniques=attack_ids,
                        severity="high" if ioc_type in ("ip", "hash_sha256") else "medium",
                    ))
            logger.info(f"  -> {len(iocs)} IOCs from AlienVault OTX")
        except Exception as e:
            logger.error(f"Error fetching AlienVault OTX: {e}")
        return iocs


class MITREAttackFetcher(BaseFetcher):
    """Fetch MITRE ATT&CK technique data."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        techniques: list[dict] = []
        try:
            url = self.config["url"] + "/enterprise-attack/enterprise-attack.json"
            resp = self._get(url)
            data = resp.json()
            for obj in data.get("objects", []):
                if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                    ext_refs = obj.get("external_references", [])
                    technique_id = ""
                    for ref in ext_refs:
                        if ref.get("source_name") == "mitre-attack":
                            technique_id = ref.get("external_id", "")
                            break
                    phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
                    platforms = obj.get("x_mitre_platforms", [])
                    techniques.append({
                        "technique_id": technique_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", "")[:200],
                        "tactics": phases,
                        "platforms": platforms,
                        "detection": obj.get("x_mitre_detection", "")[:200] if obj.get("x_mitre_detection") else "",
                        "data_sources": obj.get("x_mitre_data_sources", []),
                    })
            logger.info(f"  -> {len(techniques)} MITRE ATT&CK techniques fetched")
        except Exception as e:
            logger.error(f"Error fetching MITRE ATT&CK: {e}")
        return techniques  # type: ignore


class NISTNVDFetcher(BaseFetcher):
    """Fetch recent CVEs from NIST NVD."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        iocs: list[IOC] = []
        try:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=7)
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                "resultsPerPage": 100,
            }
            api_key = self.config.get("api_key", "")
            if api_key.startswith("${"):
                api_key = os.environ.get(api_key[2:-1], "")
            headers = {}
            if api_key:
                headers["apiKey"] = api_key
            resp = self._get(self.config["url"], params=params, headers=headers)
            data = resp.json()
            for vuln in data.get("vulnerabilities", [])[:100]:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve_data.get("metrics", {})
                cvss_score = 0.0
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        cvss_score = metrics[version][0].get("cvssData", {}).get("baseScore", 0.0)
                        break
                severity = "critical" if cvss_score >= 9.0 else "high" if cvss_score >= 7.0 else "medium" if cvss_score >= 4.0 else "low"
                iocs.append(IOC(
                    ioc_type="cve",
                    value=cve_id,
                    source="NIST-NVD",
                    confidence=100,
                    tlp="CLEAR",
                    tags=[severity, f"cvss:{cvss_score}"],
                    description=desc[:300],
                    first_seen=cve_data.get("published", ""),
                    last_seen=cve_data.get("lastModified", ""),
                    severity=severity,
                ))
            logger.info(f"  -> {len(iocs)} CVEs from NIST NVD")
        except Exception as e:
            logger.error(f"Error fetching NIST NVD: {e}")
        return iocs


class CISAKEVFetcher(BaseFetcher):
    """Fetch CISA Known Exploited Vulnerabilities."""

    def fetch(self) -> list[IOC]:
        logger.info(f"Fetching from {self.name}...")
        iocs: list[IOC] = []
        try:
            resp = self._get(self.config["url"])
            data = resp.json()
            for vuln in data.get("vulnerabilities", [])[:200]:
                iocs.append(IOC(
                    ioc_type="cve",
                    value=vuln.get("cveID", ""),
                    source="CISA-KEV",
                    confidence=100,
                    tlp="CLEAR",
                    tags=["known-exploited", vuln.get("vendorProject", "")],
                    description=f"{vuln.get('vulnerabilityName', '')} | Product: {vuln.get('product', '')} | Action: {vuln.get('requiredAction', '')}",
                    first_seen=vuln.get("dateAdded", ""),
                    severity="critical",
                ))
            logger.info(f"  -> {len(iocs)} KEVs from CISA")
        except Exception as e:
            logger.error(f"Error fetching CISA KEV: {e}")
        return iocs


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------
def export_json(iocs: list[IOC], output_path: str) -> None:
    data = {"metadata": {"generated": datetime.now(timezone.utc).isoformat(), "total_iocs": len(iocs),
                         "tool": "threat-intel-fetcher"}, "iocs": [i.to_dict() for i in iocs]}
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    logger.info(f"Exported {len(iocs)} IOCs to JSON: {output_path}")


def export_csv(iocs: list[IOC], output_path: str) -> None:
    fields = ["id", "ioc_type", "value", "source", "confidence", "tlp", "tags",
              "description", "first_seen", "last_seen", "mitre_techniques", "severity"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for ioc in iocs:
            row = ioc.to_dict()
            row["tags"] = "|".join(row["tags"])
            row["mitre_techniques"] = "|".join(row["mitre_techniques"])
            writer.writerow(row)
    logger.info(f"Exported {len(iocs)} IOCs to CSV: {output_path}")


def export_stix2(iocs: list[IOC], output_path: str) -> None:
    bundle = {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(datetime.now(timezone.utc).isoformat().encode()).hexdigest()}",
        "spec_version": "2.1",
        "objects": [i.to_stix2() for i in iocs],
    }
    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=2)
    logger.info(f"Exported {len(iocs)} IOCs to STIX2: {output_path}")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
FETCHER_MAP: dict[str, type[BaseFetcher]] = {
    "urlhaus": URLhausFetcher,
    "malwarebazaar": MalwareBazaarFetcher,
    "threatfox": ThreatFoxFetcher,
    "feodotracker": FeodoTrackerFetcher,
    "alienvault_otx": AlienVaultOTXFetcher,
    "mitre_attack": MITREAttackFetcher,
    "nist_nvd": NISTNVDFetcher,
    "cisa_kev": CISAKEVFetcher,
}


def run_fetch(config: dict, feeds_to_run: Optional[list[str]] = None, output_format: str = "json",
              output_dir: str = "./output") -> list[IOC]:
    """Run the fetcher for specified feeds or all enabled feeds."""
    session = create_session(config.get("global", {}))
    all_iocs: list[IOC] = []
    feeds_config = config.get("feeds", {})

    for feed_name, feed_cfg in feeds_config.items():
        if feeds_to_run and feed_name not in feeds_to_run:
            continue
        if not feed_cfg.get("enabled", False):
            logger.info(f"Skipping disabled feed: {feed_name}")
            continue
        fetcher_cls = FETCHER_MAP.get(feed_name)
        if not fetcher_cls:
            logger.warning(f"No fetcher implemented for: {feed_name}")
            continue
        try:
            fetcher = fetcher_cls(session, feed_cfg)
            results = fetcher.fetch()
            if isinstance(results, list) and results and isinstance(results[0], IOC):
                all_iocs.extend(results)
        except Exception as e:
            logger.error(f"Failed to fetch {feed_name}: {e}")

    # Deduplicate
    seen: set[str] = set()
    unique_iocs: list[IOC] = []
    for ioc in all_iocs:
        key = f"{ioc.ioc_type}:{ioc.value}"
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    logger.info(f"Total unique IOCs: {len(unique_iocs)} (from {len(all_iocs)} raw)")

    # Export
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    exporters = {"json": export_json, "csv": export_csv, "stix2": export_stix2}
    ext_map = {"json": "json", "csv": "csv", "stix2": "json"}
    exporter = exporters.get(output_format, export_json)
    output_path = os.path.join(output_dir, f"threat_intel_{timestamp}.{ext_map.get(output_format, 'json')}")
    exporter(unique_iocs, output_path)

    return unique_iocs


def run_scheduled(config: dict, interval_minutes: int, output_format: str, output_dir: str) -> None:
    """Run fetcher on a schedule."""
    logger.info(f"Starting scheduled fetch every {interval_minutes} minutes...")
    while True:
        try:
            run_fetch(config, output_format=output_format, output_dir=output_dir)
        except Exception as e:
            logger.error(f"Scheduled run failed: {e}")
        logger.info(f"Next fetch in {interval_minutes} minutes...")
        time.sleep(interval_minutes * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Auto-Fetcher - Fetch IOCs from OSINT feeds",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all --format json                      Fetch all feeds, output JSON
  %(prog)s --feed urlhaus --feed threatfox           Fetch specific feeds
  %(prog)s --all --format csv --output-dir ./data    Fetch all, CSV output
  %(prog)s --all --schedule 60                       Fetch every 60 minutes
  %(prog)s --generate-rules --format json            Fetch and generate SIEM rules
        """,
    )
    parser.add_argument("--config", default="feed-config.yaml", help="Path to feed configuration YAML")
    parser.add_argument("--all", action="store_true", help="Fetch from all enabled feeds")
    parser.add_argument("--feed", action="append", dest="feeds", help="Specific feed to fetch (can repeat)")
    parser.add_argument("--format", choices=["json", "csv", "stix2"], default="json", help="Output format")
    parser.add_argument("--output-dir", default="./output", help="Output directory")
    parser.add_argument("--schedule", type=int, metavar="MINUTES", help="Run on schedule (minutes between runs)")
    parser.add_argument("--generate-rules", action="store_true", help="Generate SIEM detection rules from IOCs")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    with open(config_path) as f:
        config = yaml.safe_load(f)

    setup_logging(args.log_level, config.get("global", {}).get("log_file"))

    if not args.all and not args.feeds:
        parser.print_help()
        sys.exit(1)

    feeds_to_run = None if args.all else args.feeds

    if args.schedule:
        run_scheduled(config, args.schedule, args.format, args.output_dir)
    else:
        iocs = run_fetch(config, feeds_to_run, args.format, args.output_dir)
        if args.generate_rules and iocs:
            logger.info("Generating SIEM rules... Use siem-rule-generator.py for full generation.")
            from siem_rule_generator import SIEMRuleGenerator
            generator = SIEMRuleGenerator(config)
            generator.generate_all(iocs, args.output_dir)


if __name__ == "__main__":
    main()
