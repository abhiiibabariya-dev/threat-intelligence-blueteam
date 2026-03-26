#!/usr/bin/env python3
"""
Forensic Timeline Generator - Blue Team Toolkit
Generates chronological event timelines from multiple log sources for incident investigation.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    console = None

try:
    from dateutil import parser as date_parser
except ImportError:
    date_parser = None


# Log format patterns
LOG_PATTERNS = {
    "syslog": {
        "pattern": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.+)$',
        "fields": ["timestamp", "hostname", "process", "pid", "message"]
    },
    "auth": {
        "pattern": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.+)$',
        "fields": ["timestamp", "hostname", "process", "pid", "message"]
    },
    "apache_access": {
        "pattern": r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)',
        "fields": ["source_ip", "user", "timestamp", "method", "uri", "status", "bytes"]
    },
    "apache_error": {
        "pattern": r'^\[([^\]]+)\]\s+\[(\S+)\]\s+(?:\[pid\s+(\d+)\])?\s*(.+)$',
        "fields": ["timestamp", "level", "pid", "message"]
    },
    "windows_evtx_exported": {
        "pattern": r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+(\d+)\s+(\S+)\s+(.+)$',
        "fields": ["timestamp", "event_id", "source", "message"]
    },
    "json_log": {
        "pattern": r'^\{.*\}$',
        "fields": ["json"]
    },
    "iso_timestamp": {
        "pattern": r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.+)$',
        "fields": ["timestamp", "message"]
    }
}

# Event classification
EVENT_CATEGORIES = {
    "authentication": [
        r'(?i)(login|logon|logoff|logout|authentication|session opened|session closed)',
        r'(?i)(Failed password|Accepted password|publickey|keyboard-interactive)',
        r'(?i)(su:|sudo:|pam_unix)',
    ],
    "account_modification": [
        r'(?i)(useradd|userdel|usermod|groupadd|passwd|chpasswd)',
        r'(?i)(account created|account deleted|password changed)',
        r'(?i)(new user|delete user|change user)',
    ],
    "network": [
        r'(?i)(connection|connect|disconnect|listening|bind|socket)',
        r'(?i)(firewall|iptables|nftables|ufw|ACCEPT|DROP|REJECT)',
        r'(?i)(dns|dhcp|arp|icmp)',
    ],
    "process": [
        r'(?i)(started|stopped|killed|segfault|core dump)',
        r'(?i)(exec|spawn|fork|cron|at\s)',
        r'(?i)(service|systemd|init)',
    ],
    "file_access": [
        r'(?i)(open|read|write|delete|rename|chmod|chown)',
        r'(?i)(created|modified|removed|accessed)',
    ],
    "security_alert": [
        r'(?i)(attack|exploit|vulnerability|malware|virus|trojan)',
        r'(?i)(brute.force|scan|probe|injection|overflow)',
        r'(?i)(alert|warning|critical|emergency|intrusion)',
        r'(?i)(denied|blocked|violation|unauthorized)',
    ],
    "system": [
        r'(?i)(boot|shutdown|reboot|kernel|module)',
        r'(?i)(mount|umount|disk|filesystem)',
        r'(?i)(memory|cpu|swap|oom)',
    ]
}


def parse_timestamp(ts_str: str, year: int = None) -> datetime:
    """Parse various timestamp formats."""
    if not year:
        year = datetime.now().year

    if date_parser:
        try:
            dt = date_parser.parse(ts_str, fuzzy=True)
            if dt.year == 1900:
                dt = dt.replace(year=year)
            return dt
        except (ValueError, OverflowError):
            pass

    # Manual parsing for syslog format
    syslog_match = re.match(r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', ts_str)
    if syslog_match:
        month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                     'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
        month = month_map.get(syslog_match.group(1), 1)
        return datetime(year, month, int(syslog_match.group(2)),
                        int(syslog_match.group(3)), int(syslog_match.group(4)),
                        int(syslog_match.group(5)))

    return datetime.min


def classify_event(message: str) -> list:
    """Classify an event into categories."""
    categories = []
    for category, patterns in EVENT_CATEGORIES.items():
        for pattern in patterns:
            if re.search(pattern, message):
                categories.append(category)
                break
    return categories if categories else ["other"]


def detect_log_format(line: str) -> str:
    """Auto-detect log format from a sample line."""
    if line.strip().startswith('{'):
        try:
            json.loads(line)
            return "json_log"
        except json.JSONDecodeError:
            pass

    for fmt_name, fmt_info in LOG_PATTERNS.items():
        if fmt_name == "json_log":
            continue
        if re.match(fmt_info["pattern"], line):
            return fmt_name

    return "iso_timestamp"


def parse_log_line(line: str, fmt: str, source_file: str) -> dict:
    """Parse a single log line into a structured event."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    if fmt == "json_log":
        try:
            data = json.loads(line)
            ts = data.get("timestamp") or data.get("@timestamp") or data.get("time") or data.get("date", "")
            return {
                "timestamp": parse_timestamp(str(ts)),
                "timestamp_raw": str(ts),
                "source_file": source_file,
                "message": data.get("message") or data.get("msg") or json.dumps(data),
                "hostname": data.get("hostname") or data.get("host", ""),
                "process": data.get("process") or data.get("program") or data.get("source", ""),
                "categories": classify_event(str(data)),
                "raw": line
            }
        except json.JSONDecodeError:
            return None

    fmt_info = LOG_PATTERNS.get(fmt)
    if not fmt_info:
        return None

    match = re.match(fmt_info["pattern"], line)
    if not match:
        return None

    groups = match.groups()
    fields = dict(zip(fmt_info["fields"], groups))

    ts_raw = fields.get("timestamp", "")
    message = fields.get("message") or fields.get("uri") or ""

    return {
        "timestamp": parse_timestamp(ts_raw),
        "timestamp_raw": ts_raw,
        "source_file": source_file,
        "message": message,
        "hostname": fields.get("hostname", ""),
        "process": fields.get("process") or fields.get("source", ""),
        "pid": fields.get("pid", ""),
        "source_ip": fields.get("source_ip", ""),
        "categories": classify_event(message + " " + line),
        "raw": line
    }


def generate_timeline(log_files: list, year: int = None) -> list:
    """Generate a unified timeline from multiple log files."""
    events = []

    for log_file in log_files:
        path = Path(log_file)
        if not path.exists():
            print(f"[!] File not found: {log_file}")
            continue

        try:
            lines = path.read_text(errors='replace').splitlines()
        except Exception as e:
            print(f"[!] Error reading {log_file}: {e}")
            continue

        if not lines:
            continue

        # Auto-detect format from first non-empty line
        sample = next((l for l in lines if l.strip() and not l.startswith('#')), "")
        fmt = detect_log_format(sample)

        for line in lines:
            event = parse_log_line(line, fmt, str(path.name))
            if event and event["timestamp"] != datetime.min:
                events.append(event)

    events.sort(key=lambda e: e["timestamp"])
    return events


def filter_events(events: list, category: str = None, keyword: str = None,
                  start: str = None, end: str = None) -> list:
    """Filter events by criteria."""
    filtered = events

    if category:
        filtered = [e for e in filtered if category in e.get("categories", [])]

    if keyword:
        keyword_lower = keyword.lower()
        filtered = [e for e in filtered if keyword_lower in e.get("message", "").lower()
                    or keyword_lower in e.get("raw", "").lower()]

    if start and date_parser:
        start_dt = date_parser.parse(start)
        filtered = [e for e in filtered if e["timestamp"] >= start_dt]

    if end and date_parser:
        end_dt = date_parser.parse(end)
        filtered = [e for e in filtered if e["timestamp"] <= end_dt]

    return filtered


def generate_summary(events: list) -> dict:
    """Generate a statistical summary of the timeline."""
    summary = {
        "total_events": len(events),
        "sources": defaultdict(int),
        "categories": defaultdict(int),
        "hosts": defaultdict(int),
        "processes": defaultdict(int),
        "time_range": {"start": None, "end": None}
    }

    for event in events:
        summary["sources"][event.get("source_file", "unknown")] += 1
        for cat in event.get("categories", ["other"]):
            summary["categories"][cat] += 1
        if event.get("hostname"):
            summary["hosts"][event["hostname"]] += 1
        if event.get("process"):
            summary["processes"][event["process"]] += 1

    if events:
        summary["time_range"]["start"] = events[0]["timestamp"].isoformat()
        summary["time_range"]["end"] = events[-1]["timestamp"].isoformat()

    # Convert defaultdicts
    summary["sources"] = dict(summary["sources"])
    summary["categories"] = dict(summary["categories"])
    summary["hosts"] = dict(sorted(summary["hosts"].items(), key=lambda x: x[1], reverse=True)[:20])
    summary["processes"] = dict(sorted(summary["processes"].items(), key=lambda x: x[1], reverse=True)[:20])

    return summary


def print_timeline(events: list, summary: dict, limit: int = 100):
    """Print timeline with Rich formatting."""
    if not console:
        for e in events[:limit]:
            ts = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            cats = ",".join(e.get("categories", []))
            print(f"[{ts}] [{e.get('source_file', '')}] [{cats}] {e.get('message', '')}")
        return

    # Summary panel
    console.print(Panel(
        f"Total Events: [bold]{summary['total_events']}[/]\n"
        f"Time Range: {summary['time_range']['start']} to {summary['time_range']['end']}\n"
        f"Sources: {', '.join(summary['sources'].keys())}\n"
        f"Categories: {', '.join(f'{k}({v})' for k, v in sorted(summary['categories'].items(), key=lambda x: -x[1]))}",
        title="[bold]Forensic Timeline Summary[/]",
        box=box.DOUBLE
    ))

    # Category colors
    cat_colors = {
        "security_alert": "red", "authentication": "yellow", "account_modification": "bright_red",
        "network": "cyan", "process": "blue", "file_access": "magenta",
        "system": "green", "other": "dim"
    }

    table = Table(title=f"Timeline Events (showing {min(limit, len(events))} of {len(events)})", box=box.SIMPLE)
    table.add_column("Timestamp", style="dim", width=19)
    table.add_column("Source", style="cyan", width=15)
    table.add_column("Category", width=15)
    table.add_column("Process", style="blue", width=15)
    table.add_column("Message", style="white", max_width=80)

    for event in events[:limit]:
        ts = event["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        cats = event.get("categories", ["other"])
        cat_str = cats[0] if cats else "other"
        color = cat_colors.get(cat_str, "white")
        msg = event.get("message", "")[:80]

        table.add_row(ts, event.get("source_file", ""),
                      f"[{color}]{cat_str}[/]",
                      event.get("process", ""),
                      msg)

    console.print(table)


def export_timeline(events: list, output_path: str, fmt: str = "json"):
    """Export timeline to file."""
    serializable = []
    for e in events:
        entry = dict(e)
        entry["timestamp"] = entry["timestamp"].isoformat()
        serializable.append(entry)

    if fmt == "json":
        Path(output_path).write_text(json.dumps(serializable, indent=2))
    elif fmt == "csv":
        import csv
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "source_file", "hostname", "process",
                             "categories", "message"])
            for e in serializable:
                writer.writerow([e["timestamp"], e.get("source_file", ""),
                                 e.get("hostname", ""), e.get("process", ""),
                                 "|".join(e.get("categories", [])),
                                 e.get("message", "")])

    print(f"[+] Timeline exported to {output_path} ({len(events)} events)")


def main():
    parser = argparse.ArgumentParser(description="Forensic Timeline Generator")
    parser.add_argument("logs", nargs="+", help="Log files to process")
    parser.add_argument("--category", choices=list(EVENT_CATEGORIES.keys()),
                        help="Filter by event category")
    parser.add_argument("--keyword", help="Filter by keyword")
    parser.add_argument("--start", help="Start time filter (ISO format)")
    parser.add_argument("--end", help="End time filter (ISO format)")
    parser.add_argument("--year", type=int, help="Year for syslog timestamps")
    parser.add_argument("--limit", type=int, default=100, help="Max events to display")
    parser.add_argument("--output", help="Export timeline to file")
    parser.add_argument("--format", choices=["json", "csv"], default="json",
                        help="Export format")
    parser.add_argument("--json", action="store_true", help="Output as JSON to stdout")
    args = parser.parse_args()

    events = generate_timeline(args.logs, year=args.year)
    events = filter_events(events, category=args.category, keyword=args.keyword,
                           start=args.start, end=args.end)
    summary = generate_summary(events)

    if args.output:
        export_timeline(events, args.output, args.format)

    if args.json:
        serializable = []
        for e in events:
            entry = dict(e)
            entry["timestamp"] = entry["timestamp"].isoformat()
            serializable.append(entry)
        print(json.dumps({"summary": summary, "events": serializable}, indent=2))
    else:
        print_timeline(events, summary, args.limit)


if __name__ == "__main__":
    main()
