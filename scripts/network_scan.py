#!/usr/bin/env python3
"""
Network Scanner - Baseline network connections and detect anomalies.
Compares current connections against a known-good baseline.
"""

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()
BASE_DIR = Path(__file__).resolve().parent.parent
BASELINE_FILE = BASE_DIR / "output" / "network_baseline.json"
IOC_DB = BASE_DIR / "output" / "ioc_database.json"


def get_connections():
    """Get current network connections using ss or netstat."""
    connections = []
    try:
        result = subprocess.run(
            ["ss", "-tunap"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().splitlines()[1:]  # skip header
    except (FileNotFoundError, subprocess.TimeoutExpired):
        try:
            result = subprocess.run(
                ["netstat", "-tunap"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().splitlines()[2:]  # skip headers
        except (FileNotFoundError, subprocess.TimeoutExpired):
            console.print("[red]Neither ss nor netstat available[/]")
            return []

    using_ss = "ss" in result.args[0] if result.args else False

    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        if using_ss:
            state = parts[1] if proto.startswith("tcp") else ""
            local = parts[4] if len(parts) > 4 else ""
            remote = parts[5] if len(parts) > 5 else ""
        else:
            local = parts[3]
            remote = parts[4] if len(parts) > 4 else ""
            state = parts[5] if len(parts) > 5 else ""
        process = parts[-1] if parts[-1] != "-" else "unknown"

        # Extract IP and port
        remote_ip = remote.rsplit(":", 1)[0] if ":" in remote else remote
        remote_port = remote.rsplit(":", 1)[1] if ":" in remote else ""

        if remote_ip and remote_ip not in ("0.0.0.0", "*", "127.0.0.1", "::1", "::"):
            connections.append({
                "proto": proto,
                "local": local,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "process": process,
            })
    return connections


def load_known_ioc_ips():
    """Load IP-type IOCs from the local database."""
    if not IOC_DB.exists():
        return set()
    with open(IOC_DB) as f:
        db = json.load(f)
    return {
        ioc["value"] for ioc in db.get("iocs", [])
        if ioc.get("type") == "ip"
    }


def baseline(args):
    """Save current connections as baseline."""
    connections = get_connections()
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)

    baseline_data = {
        "created": datetime.now(timezone.utc).isoformat(),
        "remote_ips": list({c["remote_ip"] for c in connections}),
        "remote_endpoints": list({f"{c['remote_ip']}:{c['remote_port']}" for c in connections}),
        "connection_count": len(connections),
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline_data, f, indent=2)

    console.print(f"[green]Baseline saved:[/] {len(baseline_data['remote_ips'])} unique IPs, "
                  f"{len(connections)} connections")


def scan(args):
    """Scan current connections and compare to baseline."""
    connections = get_connections()
    malicious_ips = load_known_ioc_ips()

    # Load baseline if it exists
    baseline_ips = set()
    if BASELINE_FILE.exists():
        with open(BASELINE_FILE) as f:
            bl = json.load(f)
        baseline_ips = set(bl.get("remote_ips", []))

    current_ips = {c["remote_ip"] for c in connections}
    new_ips = current_ips - baseline_ips
    ioc_hits = current_ips & malicious_ips

    # Display results
    console.print(f"[bold]Network Scan Results[/] - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    console.print(f"Active connections: [cyan]{len(connections)}[/]")
    console.print(f"Unique remote IPs:  [cyan]{len(current_ips)}[/]")

    if baseline_ips:
        console.print(f"New IPs (not in baseline): [yellow]{len(new_ips)}[/]")
    else:
        console.print("[dim]No baseline set — run with 'baseline' to create one[/]")

    console.print(f"IOC matches: [{'red' if ioc_hits else 'green'}]{len(ioc_hits)}[/]")

    # IOC hits table
    if ioc_hits:
        console.print("\n[bold red]ALERT: Connections to known malicious IPs![/]")
        alert_table = Table(title="IOC Hits", style="red")
        alert_table.add_column("IP", style="bold red")
        alert_table.add_column("Port")
        alert_table.add_column("Process")
        for c in connections:
            if c["remote_ip"] in ioc_hits:
                alert_table.add_row(c["remote_ip"], c["remote_port"], c["process"])
        console.print(alert_table)

    # New connections table
    if new_ips and baseline_ips:
        console.print("\n[bold yellow]New connections not in baseline:[/]")
        new_table = Table()
        new_table.add_column("IP", style="yellow")
        new_table.add_column("Port")
        new_table.add_column("Process")
        for c in connections:
            if c["remote_ip"] in new_ips:
                new_table.add_row(c["remote_ip"], c["remote_port"], c["process"])
        console.print(new_table)

    # All connections
    if args.verbose:
        console.print("\n[bold]All Active Connections:[/]")
        all_table = Table()
        all_table.add_column("Proto")
        all_table.add_column("Remote IP")
        all_table.add_column("Port")
        all_table.add_column("State")
        all_table.add_column("Process")
        for c in connections:
            ip_style = "red" if c["remote_ip"] in ioc_hits else ("yellow" if c["remote_ip"] in new_ips else "")
            all_table.add_row(c["proto"], f"[{ip_style}]{c['remote_ip']}[/]",
                              c["remote_port"], c["state"], c["process"])
        console.print(all_table)


def main():
    parser = argparse.ArgumentParser(description="Network Scanner - Blue Team Toolkit")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("baseline", help="Save current connections as baseline")

    sp_scan = sub.add_parser("scan", help="Scan and compare to baseline")
    sp_scan.add_argument("-v", "--verbose", action="store_true", help="Show all connections")

    args = parser.parse_args()
    commands = {"baseline": baseline, "scan": scan}

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
