#!/usr/bin/env python3
"""
IOC Manager - Collect, store, and query Indicators of Compromise
from multiple threat intelligence feeds.
"""

import argparse
import csv
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml
from rich.console import Console
from rich.table import Table

console = Console()

BASE_DIR = Path(__file__).resolve().parent.parent
FEEDS_FILE = BASE_DIR / "ioc" / "feeds.yaml"
CONFIG_FILE = BASE_DIR / "config" / "settings.yaml"
IOC_DB_FILE = BASE_DIR / "output" / "ioc_database.json"


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f)
    return {}


def load_feeds():
    with open(FEEDS_FILE) as f:
        data = yaml.safe_load(f)
    return [f for f in data["feeds"] if f.get("enabled", True)]


def load_ioc_db():
    if IOC_DB_FILE.exists():
        with open(IOC_DB_FILE) as f:
            return json.load(f)
    return {"iocs": [], "last_updated": None, "feed_status": {}}


def save_ioc_db(db):
    IOC_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(IOC_DB_FILE, "w") as f:
        json.dump(db, f, indent=2, default=str)


def fetch_feed(feed):
    """Download and parse a single threat intel feed."""
    console.print(f"  [cyan]Fetching[/] {feed['name']}...", end=" ")
    try:
        resp = requests.get(feed["url"], timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        console.print(f"[red]FAILED[/] ({e})")
        return []

    indicators = []
    lines = resp.text.strip().splitlines()

    if feed["format"] == "csv":
        # Skip comment lines
        clean = [l for l in lines if not l.startswith("#") and l.strip()]
        if not clean:
            console.print("[yellow]EMPTY[/]")
            return []
        reader = csv.reader(io.StringIO("\n".join(clean)))
        for row in reader:
            if not row:
                continue
            value = row[0].strip()
            if value and not value.startswith('"'):
                indicators.append({
                    "value": value,
                    "type": feed["type"],
                    "source": feed["name"],
                    "collected": datetime.now(timezone.utc).isoformat(),
                })

    elif feed["format"] == "plaintext":
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                indicators.append({
                    "value": line,
                    "type": feed["type"],
                    "source": feed["name"],
                    "collected": datetime.now(timezone.utc).isoformat(),
                })

    console.print(f"[green]OK[/] ({len(indicators)} indicators)")
    return indicators


def collect(args):
    """Collect IOCs from all enabled feeds."""
    console.print("[bold]Collecting IOCs from threat feeds...[/]\n")
    feeds = load_feeds()
    db = load_ioc_db()

    all_new = []
    existing_values = {i["value"] for i in db["iocs"]}

    for feed in feeds:
        indicators = fetch_feed(feed)
        new = [i for i in indicators if i["value"] not in existing_values]
        all_new.extend(new)
        existing_values.update(i["value"] for i in new)
        db["feed_status"][feed["name"]] = {
            "last_fetch": datetime.now(timezone.utc).isoformat(),
            "count": len(indicators),
            "new": len(new),
        }

    db["iocs"].extend(all_new)
    db["last_updated"] = datetime.now(timezone.utc).isoformat()
    save_ioc_db(db)

    console.print(f"\n[bold green]Done.[/] {len(all_new)} new IOCs added "
                  f"(total: {len(db['iocs'])})")


def search(args):
    """Search the IOC database for a specific indicator."""
    db = load_ioc_db()
    query = args.query.lower()
    matches = [i for i in db["iocs"] if query in i["value"].lower()]

    if not matches:
        console.print(f"[yellow]No matches found for '{args.query}'[/]")
        return

    table = Table(title=f"IOC Search: {args.query}")
    table.add_column("Value", style="red")
    table.add_column("Type")
    table.add_column("Source", style="cyan")
    table.add_column("Collected")

    for m in matches[:50]:
        table.add_row(m["value"], m["type"], m["source"], m["collected"][:10])

    console.print(table)
    if len(matches) > 50:
        console.print(f"  ... and {len(matches) - 50} more results")


def stats(args):
    """Show IOC database statistics."""
    db = load_ioc_db()

    table = Table(title="IOC Database Statistics")
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="cyan")

    table.add_row("Total IOCs", str(len(db["iocs"])))
    table.add_row("Last Updated", db.get("last_updated", "Never") or "Never")

    # Count by type
    types = {}
    sources = {}
    for i in db["iocs"]:
        types[i["type"]] = types.get(i["type"], 0) + 1
        sources[i["source"]] = sources.get(i["source"], 0) + 1

    for t, count in sorted(types.items()):
        table.add_row(f"  Type: {t}", str(count))
    for s, count in sorted(sources.items(), key=lambda x: -x[1])[:10]:
        table.add_row(f"  Source: {s}", str(count))

    console.print(table)


def export(args):
    """Export IOCs to CSV."""
    db = load_ioc_db()
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["value", "type", "source", "collected"])
        writer.writeheader()
        writer.writerows(db["iocs"])

    console.print(f"[green]Exported {len(db['iocs'])} IOCs to {out_path}[/]")


def main():
    parser = argparse.ArgumentParser(description="IOC Manager - Threat Intelligence")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("collect", help="Collect IOCs from all enabled feeds")

    sp_search = sub.add_parser("search", help="Search IOC database")
    sp_search.add_argument("query", help="IP, domain, hash, or URL to search")

    sub.add_parser("stats", help="Show database statistics")

    sp_export = sub.add_parser("export", help="Export IOCs to CSV")
    sp_export.add_argument("-o", "--output", default="output/iocs_export.csv")

    args = parser.parse_args()
    commands = {"collect": collect, "search": search, "stats": stats, "export": export}

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
