#!/usr/bin/env python3
"""
Log Analyzer - Parse and detect suspicious patterns in system logs.
Supports syslog, auth.log, and common web server log formats.
"""

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()

# Detection patterns mapped to MITRE ATT&CK
PATTERNS = {
    "brute_force": {
        "regex": r"Failed password for (?:invalid user )?(\S+) from (\S+)",
        "mitre": "T1110",
        "severity": "high",
        "description": "Failed SSH login attempt",
    },
    "successful_login": {
        "regex": r"Accepted (?:password|publickey) for (\S+) from (\S+)",
        "mitre": "T1078",
        "severity": "info",
        "description": "Successful login",
    },
    "sudo_abuse": {
        "regex": r"sudo:\s+(\S+)\s.*COMMAND=(.*)",
        "mitre": "T1548.003",
        "severity": "medium",
        "description": "Sudo command execution",
    },
    "user_created": {
        "regex": r"new user: name=(\S+)",
        "mitre": "T1136.001",
        "severity": "high",
        "description": "New user account created",
    },
    "cron_modified": {
        "regex": r"crontab.*REPLACE.*\((\S+)\)",
        "mitre": "T1053.003",
        "severity": "medium",
        "description": "Crontab modified",
    },
    "ssh_tunnel": {
        "regex": r"sshd.*port forwarding",
        "mitre": "T1572",
        "severity": "high",
        "description": "SSH port forwarding detected",
    },
    "web_shell_access": {
        "regex": r'(?:GET|POST)\s+\S*(?:cmd|shell|backdoor|c99|r57|webshell)\S*',
        "mitre": "T1505.003",
        "severity": "critical",
        "description": "Possible webshell access",
    },
    "sql_injection": {
        "regex": r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|--\s*$|;\s*DELETE)",
        "mitre": "T1190",
        "severity": "critical",
        "description": "Possible SQL injection attempt",
    },
    "directory_traversal": {
        "regex": r"\.\./\.\./|%2e%2e%2f|%252e%252e%252f",
        "mitre": "T1083",
        "severity": "high",
        "description": "Directory traversal attempt",
    },
}


def analyze_file(filepath, output_format="table"):
    """Analyze a log file for suspicious patterns."""
    path = Path(filepath)
    if not path.exists():
        console.print(f"[red]File not found: {filepath}[/]")
        return

    console.print(f"[bold]Analyzing: {filepath}[/]\n")

    alerts = []
    failed_logins = defaultdict(lambda: defaultdict(int))  # ip -> user -> count
    line_count = 0

    with open(path, errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line_count += 1
            for name, pattern in PATTERNS.items():
                match = re.search(pattern["regex"], line, re.IGNORECASE)
                if match:
                    alert = {
                        "line": line_num,
                        "rule": name,
                        "severity": pattern["severity"],
                        "mitre": pattern["mitre"],
                        "description": pattern["description"],
                        "match": match.group(0)[:120],
                        "groups": match.groups(),
                    }
                    alerts.append(alert)

                    if name == "brute_force" and len(match.groups()) >= 2:
                        user, ip = match.group(1), match.group(2)
                        failed_logins[ip][user] += 1

    # Generate brute force summary
    brute_force_sources = {
        ip: dict(users)
        for ip, users in failed_logins.items()
        if sum(users.values()) >= 5
    }

    _display_results(alerts, brute_force_sources, line_count, output_format, filepath)
    return alerts


def _display_results(alerts, brute_force_sources, line_count, fmt, filepath):
    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "info": "blue",
    }

    # Summary
    counts = Counter(a["severity"] for a in alerts)
    console.print(f"Scanned [cyan]{line_count}[/] lines, found [bold]{len(alerts)}[/] alerts:")
    for sev in ["critical", "high", "medium", "info"]:
        if counts.get(sev):
            console.print(f"  [{severity_colors[sev]}]{sev.upper()}: {counts[sev]}[/]")

    # Alerts table
    if alerts:
        table = Table(title="\nDetection Alerts", show_lines=True)
        table.add_column("Line", style="dim", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Rule", style="cyan", width=20)
        table.add_column("MITRE", width=12)
        table.add_column("Match", max_width=60)

        for a in alerts[:100]:
            sev_style = severity_colors.get(a["severity"], "white")
            table.add_row(
                str(a["line"]),
                f"[{sev_style}]{a['severity'].upper()}[/]",
                a["rule"],
                a["mitre"],
                a["match"][:60],
            )
        console.print(table)
        if len(alerts) > 100:
            console.print(f"  ... and {len(alerts) - 100} more alerts")

    # Brute force summary
    if brute_force_sources:
        console.print("\n[bold red]Brute Force Sources (5+ failed attempts):[/]")
        bf_table = Table()
        bf_table.add_column("Source IP", style="red")
        bf_table.add_column("Total Attempts")
        bf_table.add_column("Target Users")
        for ip, users in sorted(brute_force_sources.items(), key=lambda x: -sum(x[1].values())):
            total = sum(users.values())
            targets = ", ".join(f"{u}({c})" for u, c in sorted(users.items(), key=lambda x: -x[1])[:5])
            bf_table.add_row(ip, str(total), targets)
        console.print(bf_table)

    # JSON export
    if fmt == "json":
        out = Path(filepath).with_suffix(".alerts.json")
        with open(out, "w") as f:
            json.dump({"alerts": alerts, "brute_force": brute_force_sources}, f, indent=2)
        console.print(f"\n[green]Results saved to {out}[/]")


def main():
    parser = argparse.ArgumentParser(description="Log Analyzer - Blue Team Toolkit")
    parser.add_argument("--input", "-i", required=True, help="Log file to analyze")
    parser.add_argument("--format", "-f", choices=["table", "json"], default="table")
    args = parser.parse_args()
    analyze_file(args.input, args.format)


if __name__ == "__main__":
    main()
