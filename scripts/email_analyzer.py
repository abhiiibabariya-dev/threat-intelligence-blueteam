#!/usr/bin/env python3
"""
Email Header Analyzer - Blue Team Toolkit
Parses and analyzes email headers to detect phishing, spoofing, and suspicious routing.
"""

import argparse
import re
import sys
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    console = None


def parse_headers(raw_headers: str) -> dict:
    """Parse raw email headers into structured data."""
    headers = {}
    current_key = None
    current_value = []

    for line in raw_headers.split('\n'):
        if re.match(r'^[A-Za-z0-9\-]+:', line):
            if current_key:
                headers.setdefault(current_key.lower(), []).append(' '.join(current_value).strip())
            parts = line.split(':', 1)
            current_key = parts[0].strip()
            current_value = [parts[1].strip() if len(parts) > 1 else '']
        elif line.startswith((' ', '\t')) and current_key:
            current_value.append(line.strip())
        elif line.strip() == '' and current_key:
            headers.setdefault(current_key.lower(), []).append(' '.join(current_value).strip())
            current_key = None
            current_value = []

    if current_key:
        headers.setdefault(current_key.lower(), []).append(' '.join(current_value).strip())

    return headers


def extract_ips(headers: dict) -> list:
    """Extract all IP addresses from Received headers."""
    ips = []
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for received in headers.get('received', []):
        found = ip_pattern.findall(received)
        for ip in found:
            if not ip.startswith(('10.', '192.168.', '127.')) and ip not in ips:
                ips.append(ip)
    return ips


def check_spf(headers: dict) -> dict:
    """Analyze SPF authentication results."""
    result = {"status": "not_found", "details": "No SPF record found in headers"}
    for auth in headers.get('authentication-results', []) + headers.get('received-spf', []):
        auth_lower = auth.lower()
        if 'spf=pass' in auth_lower:
            result = {"status": "pass", "details": auth.strip()}
        elif 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower:
            result = {"status": "fail", "details": auth.strip()}
        elif 'spf=neutral' in auth_lower:
            result = {"status": "neutral", "details": auth.strip()}
    return result


def check_dkim(headers: dict) -> dict:
    """Analyze DKIM authentication results."""
    result = {"status": "not_found", "details": "No DKIM signature found"}
    for auth in headers.get('authentication-results', []):
        auth_lower = auth.lower()
        if 'dkim=pass' in auth_lower:
            result = {"status": "pass", "details": auth.strip()}
        elif 'dkim=fail' in auth_lower:
            result = {"status": "fail", "details": auth.strip()}
    if headers.get('dkim-signature'):
        if result["status"] == "not_found":
            result = {"status": "present", "details": "DKIM signature present but no verification result"}
    return result


def check_dmarc(headers: dict) -> dict:
    """Analyze DMARC authentication results."""
    result = {"status": "not_found", "details": "No DMARC result found"}
    for auth in headers.get('authentication-results', []):
        auth_lower = auth.lower()
        if 'dmarc=pass' in auth_lower:
            result = {"status": "pass", "details": auth.strip()}
        elif 'dmarc=fail' in auth_lower or 'dmarc=reject' in auth_lower:
            result = {"status": "fail", "details": auth.strip()}
    return result


def detect_spoofing_indicators(headers: dict) -> list:
    """Detect potential email spoofing indicators."""
    indicators = []

    # Check Reply-To mismatch
    from_addr = headers.get('from', [''])[0]
    reply_to = headers.get('reply-to', [''])[0]
    if reply_to and from_addr:
        from_domain = re.search(r'@([\w\.\-]+)', from_addr)
        reply_domain = re.search(r'@([\w\.\-]+)', reply_to)
        if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
            indicators.append({
                "type": "reply_to_mismatch",
                "severity": "high",
                "description": f"Reply-To domain ({reply_domain.group(1)}) differs from From domain ({from_domain.group(1)})"
            })

    # Check Return-Path mismatch
    return_path = headers.get('return-path', [''])[0]
    if return_path and from_addr:
        from_domain = re.search(r'@([\w\.\-]+)', from_addr)
        return_domain = re.search(r'@([\w\.\-]+)', return_path)
        if from_domain and return_domain and from_domain.group(1) != return_domain.group(1):
            indicators.append({
                "type": "return_path_mismatch",
                "severity": "medium",
                "description": f"Return-Path domain ({return_domain.group(1)}) differs from From domain ({from_domain.group(1)})"
            })

    # Check for suspicious X-Mailer
    x_mailer = headers.get('x-mailer', [''])[0]
    suspicious_mailers = ['PHPMailer', 'SwiftMailer', 'Python', 'curl']
    for mailer in suspicious_mailers:
        if mailer.lower() in x_mailer.lower():
            indicators.append({
                "type": "suspicious_mailer",
                "severity": "medium",
                "description": f"Suspicious X-Mailer detected: {x_mailer}"
            })

    # Check for multiple Received headers suggesting relay chain
    received_count = len(headers.get('received', []))
    if received_count > 8:
        indicators.append({
            "type": "excessive_hops",
            "severity": "low",
            "description": f"Email passed through {received_count} mail servers (unusual relay chain)"
        })

    # Check for display name deception
    if from_addr:
        display_match = re.match(r'"?([^"<]+)"?\s*<', from_addr)
        if display_match:
            display_name = display_match.group(1).strip()
            if '@' in display_name:
                indicators.append({
                    "type": "display_name_spoofing",
                    "severity": "high",
                    "description": f"Display name contains email address (social engineering): {display_name}"
                })

    return indicators


def detect_phishing_indicators(headers: dict) -> list:
    """Detect potential phishing indicators in headers."""
    indicators = []
    subject = headers.get('subject', [''])[0].lower()

    urgency_keywords = ['urgent', 'immediate', 'action required', 'verify your',
                        'suspended', 'confirm your', 'security alert', 'unusual activity',
                        'unauthorized', 'expire', 'locked', 'limited time']
    for keyword in urgency_keywords:
        if keyword in subject:
            indicators.append({
                "type": "urgency_language",
                "severity": "medium",
                "description": f"Subject contains urgency keyword: '{keyword}'"
            })
            break

    content_type = headers.get('content-type', [''])[0]
    if 'multipart/mixed' in content_type.lower():
        indicators.append({
            "type": "has_attachments",
            "severity": "info",
            "description": "Email contains attachments (review for malicious content)"
        })

    return indicators


def analyze_routing(headers: dict) -> list:
    """Analyze email routing path from Received headers."""
    hops = []
    for i, received in enumerate(reversed(headers.get('received', []))):
        hop = {"hop": i + 1, "raw": received}

        from_match = re.search(r'from\s+([\w\.\-]+)', received)
        by_match = re.search(r'by\s+([\w\.\-]+)', received)
        time_match = re.search(r';\s*(.+)$', received)

        if from_match:
            hop["from"] = from_match.group(1)
        if by_match:
            hop["by"] = by_match.group(1)
        if time_match:
            hop["timestamp"] = time_match.group(1).strip()

        hops.append(hop)
    return hops


def calculate_risk_score(spf: dict, dkim: dict, dmarc: dict,
                         spoofing: list, phishing: list) -> dict:
    """Calculate overall risk score."""
    score = 0

    if spf["status"] == "fail":
        score += 30
    elif spf["status"] == "not_found":
        score += 15

    if dkim["status"] == "fail":
        score += 25
    elif dkim["status"] == "not_found":
        score += 10

    if dmarc["status"] == "fail":
        score += 30
    elif dmarc["status"] == "not_found":
        score += 10

    for indicator in spoofing:
        if indicator["severity"] == "high":
            score += 20
        elif indicator["severity"] == "medium":
            score += 10
        else:
            score += 5

    for indicator in phishing:
        if indicator["severity"] == "high":
            score += 15
        elif indicator["severity"] == "medium":
            score += 10

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "SAFE"

    return {"score": score, "level": level}


def analyze_email(raw_headers: str) -> dict:
    """Main analysis function."""
    headers = parse_headers(raw_headers)

    spf = check_spf(headers)
    dkim = check_dkim(headers)
    dmarc = check_dmarc(headers)
    spoofing = detect_spoofing_indicators(headers)
    phishing = detect_phishing_indicators(headers)
    routing = analyze_routing(headers)
    ips = extract_ips(headers)
    risk = calculate_risk_score(spf, dkim, dmarc, spoofing, phishing)

    return {
        "from": headers.get('from', ['Unknown'])[0],
        "to": headers.get('to', ['Unknown'])[0],
        "subject": headers.get('subject', ['No Subject'])[0],
        "date": headers.get('date', ['Unknown'])[0],
        "message_id": headers.get('message-id', ['Unknown'])[0],
        "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "spoofing_indicators": spoofing,
        "phishing_indicators": phishing,
        "routing": routing,
        "external_ips": ips,
        "risk": risk
    }


def print_rich_report(result: dict):
    """Print formatted report using Rich."""
    if not console:
        print(json.dumps(result, indent=2))
        return

    risk = result["risk"]
    risk_color = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                  "LOW": "green", "SAFE": "bright_green"}.get(risk["level"], "white")

    console.print(Panel(
        f"[bold {risk_color}]Risk Level: {risk['level']} ({risk['score']}/100)[/]",
        title="[bold]Email Header Analysis Report[/]", box=box.DOUBLE
    ))

    # Basic info
    info_table = Table(title="Email Information", box=box.ROUNDED)
    info_table.add_column("Field", style="cyan")
    info_table.add_column("Value", style="white")
    info_table.add_row("From", result["from"])
    info_table.add_row("To", result["to"])
    info_table.add_row("Subject", result["subject"])
    info_table.add_row("Date", result["date"])
    info_table.add_row("Message-ID", result["message_id"])
    console.print(info_table)

    # Authentication
    auth_table = Table(title="Authentication Results", box=box.ROUNDED)
    auth_table.add_column("Check", style="cyan")
    auth_table.add_column("Status", style="white")
    auth_table.add_column("Details", style="dim")
    for check_name in ["spf", "dkim", "dmarc"]:
        check = result["authentication"][check_name]
        status_color = {"pass": "green", "fail": "red", "not_found": "yellow"}.get(check["status"], "white")
        auth_table.add_row(check_name.upper(), f"[{status_color}]{check['status'].upper()}[/]",
                           check["details"][:80])
    console.print(auth_table)

    # Spoofing indicators
    if result["spoofing_indicators"]:
        spoof_table = Table(title="Spoofing Indicators", box=box.ROUNDED)
        spoof_table.add_column("Type", style="cyan")
        spoof_table.add_column("Severity", style="white")
        spoof_table.add_column("Description", style="white")
        for ind in result["spoofing_indicators"]:
            sev_color = {"high": "red", "medium": "yellow", "low": "green"}.get(ind["severity"], "white")
            spoof_table.add_row(ind["type"], f"[{sev_color}]{ind['severity'].upper()}[/]", ind["description"])
        console.print(spoof_table)

    # Phishing indicators
    if result["phishing_indicators"]:
        phish_table = Table(title="Phishing Indicators", box=box.ROUNDED)
        phish_table.add_column("Type", style="cyan")
        phish_table.add_column("Severity", style="white")
        phish_table.add_column("Description", style="white")
        for ind in result["phishing_indicators"]:
            sev_color = {"high": "red", "medium": "yellow", "low": "green"}.get(ind["severity"], "white")
            phish_table.add_row(ind["type"], f"[{sev_color}]{ind['severity'].upper()}[/]", ind["description"])
        console.print(phish_table)

    # Routing
    if result["routing"]:
        route_table = Table(title="Email Routing Path", box=box.ROUNDED)
        route_table.add_column("Hop", style="cyan")
        route_table.add_column("From", style="white")
        route_table.add_column("By", style="white")
        route_table.add_column("Timestamp", style="dim")
        for hop in result["routing"]:
            route_table.add_row(str(hop["hop"]), hop.get("from", "?"),
                                hop.get("by", "?"), hop.get("timestamp", "?")[:40])
        console.print(route_table)

    # External IPs
    if result["external_ips"]:
        console.print(f"\n[bold cyan]External IPs found:[/] {', '.join(result['external_ips'])}")


def main():
    parser = argparse.ArgumentParser(description="Analyze email headers for security threats")
    parser.add_argument('--file', '-f', help="File containing raw email headers")
    parser.add_argument('--stdin', action='store_true', help="Read headers from stdin")
    parser.add_argument('--json', action='store_true', help="Output as JSON")
    args = parser.parse_args()

    if args.file:
        raw = Path(args.file).read_text()
    elif args.stdin or not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        parser.print_help()
        sys.exit(1)

    result = analyze_email(raw)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_rich_report(result)


if __name__ == '__main__':
    main()
