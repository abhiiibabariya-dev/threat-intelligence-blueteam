#!/usr/bin/env python3
"""
IP Reputation Checker - Blue Team Toolkit
Check IP addresses against multiple threat intelligence sources and provide risk assessment.
"""

import argparse
import json
import sys
import re
import socket
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    print("Error: requests library required. pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    console = None


# Public threat intelligence APIs (no key required)
ABUSE_IPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
IPINFO_URL = "https://ipinfo.io/{ip}/json"
BLOCKLIST_DE_URL = "https://api.blocklist.de/api.fcgi?ip={ip}"


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    pattern = r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    return bool(re.match(pattern, ip))


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range."""
    parts = [int(p) for p in ip.split('.')]
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


def reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "N/A"


def check_ipinfo(ip: str) -> dict:
    """Get IP geolocation and ASN info from ipinfo.io."""
    try:
        resp = requests.get(IPINFO_URL.format(ip=ip), timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "country": data.get("country", "Unknown"),
                "region": data.get("region", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
                "timezone": data.get("timezone", ""),
                "loc": data.get("loc", "")
            }
    except requests.RequestException:
        pass
    return {"country": "Unknown", "org": "Unknown"}


def check_abuseipdb(ip: str, api_key: str = None) -> dict:
    """Check IP against AbuseIPDB."""
    if not api_key:
        return {"available": False, "reason": "No API key configured"}

    try:
        resp = requests.get(
            ABUSE_IPDB_CHECK,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "available": True,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", "Never"),
                "isp": data.get("isp", ""),
                "usage_type": data.get("usageType", ""),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "country": data.get("countryCode", "")
            }
    except requests.RequestException:
        pass
    return {"available": False, "reason": "API error"}


def check_virustotal(ip: str, api_key: str = None) -> dict:
    """Check IP against VirusTotal."""
    if not api_key:
        return {"available": False, "reason": "No API key configured"}

    try:
        resp = requests.get(
            VT_IP_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "available": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "as_owner": data.get("as_owner", ""),
                "country": data.get("country", ""),
                "reputation": data.get("reputation", 0)
            }
    except requests.RequestException:
        pass
    return {"available": False, "reason": "API error"}


def check_local_iocs(ip: str, ioc_dir: str = "ioc") -> dict:
    """Check IP against local IOC database."""
    db_path = Path(ioc_dir) / "ioc_database.json"
    result = {"found": False, "matches": []}

    if not db_path.exists():
        return result

    try:
        data = json.loads(db_path.read_text())
        indicators = data if isinstance(data, list) else data.get("indicators", [])

        for ioc in indicators:
            if ioc.get("value") == ip or ioc.get("indicator") == ip:
                result["found"] = True
                result["matches"].append({
                    "source": ioc.get("source", "unknown"),
                    "type": ioc.get("type", "ip"),
                    "timestamp": ioc.get("timestamp") or ioc.get("collected_at", "")
                })
    except Exception:
        pass

    return result


def check_blocklist_de(ip: str) -> dict:
    """Check IP against blocklist.de."""
    try:
        resp = requests.get(BLOCKLIST_DE_URL.format(ip=ip), timeout=10)
        if resp.status_code == 200:
            text = resp.text.strip()
            attacks = int(text) if text.isdigit() else 0
            return {"available": True, "attacks": attacks, "listed": attacks > 0}
    except requests.RequestException:
        pass
    return {"available": False}


def calculate_risk(results: dict) -> dict:
    """Calculate overall risk score from all sources."""
    score = 0
    factors = []

    # Local IOC match
    if results.get("local_iocs", {}).get("found"):
        score += 40
        factors.append("Found in local IOC database")

    # AbuseIPDB
    abuse = results.get("abuseipdb", {})
    if abuse.get("available"):
        abuse_score = abuse.get("abuse_score", 0)
        score += min(abuse_score * 0.3, 30)
        if abuse_score > 50:
            factors.append(f"AbuseIPDB confidence: {abuse_score}%")
        if abuse.get("is_tor"):
            score += 10
            factors.append("Tor exit node")

    # VirusTotal
    vt = results.get("virustotal", {})
    if vt.get("available"):
        malicious = vt.get("malicious", 0)
        if malicious > 0:
            score += min(malicious * 3, 30)
            factors.append(f"VirusTotal: {malicious} malicious detections")

    # blocklist.de
    bl = results.get("blocklist_de", {})
    if bl.get("available") and bl.get("listed"):
        score += 15
        factors.append(f"blocklist.de: {bl.get('attacks', 0)} reported attacks")

    score = min(score, 100)

    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    elif score >= 15:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    return {"score": score, "verdict": verdict, "factors": factors}


def check_ip(ip: str, abuseipdb_key: str = None, vt_key: str = None,
             ioc_dir: str = "ioc") -> dict:
    """Run all checks on an IP address."""
    result = {
        "ip": ip,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "is_private": is_private_ip(ip),
        "reverse_dns": reverse_dns(ip),
        "geo": check_ipinfo(ip),
        "local_iocs": check_local_iocs(ip, ioc_dir),
        "abuseipdb": check_abuseipdb(ip, abuseipdb_key),
        "virustotal": check_virustotal(ip, vt_key),
        "blocklist_de": check_blocklist_de(ip)
    }

    result["risk"] = calculate_risk(result)
    return result


def print_rich_result(result: dict):
    """Print formatted result."""
    if not console:
        print(json.dumps(result, indent=2))
        return

    risk = result["risk"]
    color = {"MALICIOUS": "red", "SUSPICIOUS": "yellow", "LOW RISK": "bright_yellow",
             "CLEAN": "green"}.get(risk["verdict"], "white")

    console.print(Panel(
        f"[bold {color}]{risk['verdict']}[/] (Score: {risk['score']}/100)\n" +
        ("\n".join(f"  - {f}" for f in risk["factors"]) if risk["factors"] else "  No risk factors found"),
        title=f"[bold]IP Reputation: {result['ip']}[/]",
        box=box.DOUBLE
    ))

    # Basic info
    info_table = Table(box=box.ROUNDED)
    info_table.add_column("Field", style="cyan")
    info_table.add_column("Value", style="white")
    info_table.add_row("Reverse DNS", result["reverse_dns"])
    info_table.add_row("Private IP", str(result["is_private"]))
    geo = result.get("geo", {})
    info_table.add_row("Country", geo.get("country", "Unknown"))
    info_table.add_row("City", f"{geo.get('city', '')}, {geo.get('region', '')}")
    info_table.add_row("Organization", geo.get("org", "Unknown"))
    info_table.add_row("Coordinates", geo.get("loc", "N/A"))
    console.print(info_table)

    # Source results
    sources_table = Table(title="Intelligence Sources", box=box.ROUNDED)
    sources_table.add_column("Source", style="cyan")
    sources_table.add_column("Status", style="white")
    sources_table.add_column("Details", style="dim")

    local = result.get("local_iocs", {})
    if local.get("found"):
        sources = ", ".join(m["source"] for m in local.get("matches", []))
        sources_table.add_row("Local IOCs", "[red]FOUND[/]", f"Sources: {sources}")
    else:
        sources_table.add_row("Local IOCs", "[green]Clean[/]", "Not in database")

    abuse = result.get("abuseipdb", {})
    if abuse.get("available"):
        score = abuse.get("abuse_score", 0)
        sc = "red" if score > 50 else "yellow" if score > 20 else "green"
        sources_table.add_row("AbuseIPDB", f"[{sc}]{score}% confidence[/]",
                              f"{abuse.get('total_reports', 0)} reports")
    else:
        sources_table.add_row("AbuseIPDB", "[dim]N/A[/]", abuse.get("reason", ""))

    vt = result.get("virustotal", {})
    if vt.get("available"):
        mal = vt.get("malicious", 0)
        vc = "red" if mal > 3 else "yellow" if mal > 0 else "green"
        sources_table.add_row("VirusTotal", f"[{vc}]{mal} malicious[/]",
                              f"{vt.get('suspicious', 0)} suspicious, {vt.get('harmless', 0)} clean")
    else:
        sources_table.add_row("VirusTotal", "[dim]N/A[/]", vt.get("reason", ""))

    bl = result.get("blocklist_de", {})
    if bl.get("available"):
        if bl.get("listed"):
            sources_table.add_row("blocklist.de", "[red]LISTED[/]", f"{bl.get('attacks', 0)} attacks")
        else:
            sources_table.add_row("blocklist.de", "[green]Clean[/]", "Not listed")

    console.print(sources_table)


def main():
    parser = argparse.ArgumentParser(description="IP Reputation Checker")
    parser.add_argument("ips", nargs="+", help="IP addresses to check")
    parser.add_argument("--abuseipdb-key", help="AbuseIPDB API key")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--ioc-dir", default="ioc", help="IOC database directory")
    args = parser.parse_args()

    results = []
    for ip in args.ips:
        ip = ip.strip()
        if not is_valid_ip(ip):
            print(f"[!] Invalid IP: {ip}")
            continue

        result = check_ip(ip, args.abuseipdb_key, args.vt_key, args.ioc_dir)
        results.append(result)

        if not args.json:
            print_rich_result(result)

    if args.json:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
