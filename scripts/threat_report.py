#!/usr/bin/env python3
"""
Threat Report Generator - Blue Team Toolkit
Generates comprehensive threat intelligence reports combining IOC data,
detection coverage, and incident metrics.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    yaml = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich import box
    console = Console()
except ImportError:
    console = None


def load_ioc_database(ioc_dir: str = "ioc") -> dict:
    """Load IOC database and compute statistics."""
    db_path = Path(ioc_dir) / "ioc_database.json"
    stats = {
        "total": 0,
        "by_type": defaultdict(int),
        "by_source": defaultdict(int),
        "recent_24h": 0,
        "recent_7d": 0
    }

    if not db_path.exists():
        return stats

    try:
        data = json.loads(db_path.read_text())
        now = datetime.utcnow()

        for ioc in data if isinstance(data, list) else data.get("indicators", []):
            stats["total"] += 1
            stats["by_type"][ioc.get("type", "unknown")] += 1
            stats["by_source"][ioc.get("source", "unknown")] += 1

            ts = ioc.get("timestamp") or ioc.get("collected_at", "")
            if ts:
                try:
                    from dateutil import parser as dp
                    ioc_time = dp.parse(ts)
                    if hasattr(ioc_time, 'tzinfo') and ioc_time.tzinfo:
                        ioc_time = ioc_time.replace(tzinfo=None)
                    delta = (now - ioc_time).total_seconds()
                    if delta <= 86400:
                        stats["recent_24h"] += 1
                    if delta <= 604800:
                        stats["recent_7d"] += 1
                except Exception:
                    pass
    except Exception:
        pass

    stats["by_type"] = dict(stats["by_type"])
    stats["by_source"] = dict(stats["by_source"])
    return stats


def count_detection_rules(rules_dir: str = "rules") -> dict:
    """Count detection rules by type."""
    stats = {
        "sigma": {"count": 0, "files": 0, "by_level": defaultdict(int)},
        "yara": {"count": 0, "files": 0}
    }

    sigma_path = Path(rules_dir) / "sigma"
    if sigma_path.exists():
        for f in sigma_path.rglob("*.yml"):
            stats["sigma"]["files"] += 1
            try:
                content = f.read_text()
                docs = list(yaml.safe_load_all(content)) if yaml else []
                for doc in docs:
                    if isinstance(doc, dict) and doc.get("title"):
                        stats["sigma"]["count"] += 1
                        level = doc.get("level", "medium")
                        stats["sigma"]["by_level"][level] += 1
            except Exception:
                pass

    yara_path = Path(rules_dir) / "yara"
    if yara_path.exists():
        import re
        for f in yara_path.rglob("*.yar"):
            stats["yara"]["files"] += 1
            try:
                content = f.read_text()
                stats["yara"]["count"] += len(re.findall(r'^rule\s+\w+', content, re.MULTILINE))
            except Exception:
                pass

    stats["sigma"]["by_level"] = dict(stats["sigma"]["by_level"])
    return stats


def count_playbooks(playbooks_dir: str = "playbooks") -> dict:
    """Count and summarize IR playbooks."""
    stats = {"count": 0, "by_severity": defaultdict(int), "playbooks": []}
    pb_path = Path(playbooks_dir)

    if not pb_path.exists() or not yaml:
        return stats

    for f in pb_path.rglob("*.yaml"):
        try:
            data = yaml.safe_load(f.read_text())
            if not isinstance(data, dict):
                continue
            for pb in data.get("playbooks", []):
                stats["count"] += 1
                stats["by_severity"][pb.get("severity", "medium")] += 1
                stats["playbooks"].append({
                    "id": pb.get("id", ""),
                    "name": pb.get("name", ""),
                    "severity": pb.get("severity", "")
                })
        except Exception:
            pass

    stats["by_severity"] = dict(stats["by_severity"])
    return stats


def count_feeds(ioc_dir: str = "ioc") -> dict:
    """Count configured threat feeds."""
    stats = {"total": 0, "enabled": 0, "feeds": []}
    feeds_path = Path(ioc_dir) / "feeds.yaml"

    if not feeds_path.exists() or not yaml:
        return stats

    try:
        data = yaml.safe_load(feeds_path.read_text())
        for feed in data.get("feeds", []):
            stats["total"] += 1
            if feed.get("enabled", True):
                stats["enabled"] += 1
            stats["feeds"].append({
                "name": feed.get("name", ""),
                "type": feed.get("type", ""),
                "enabled": feed.get("enabled", True)
            })
    except Exception:
        pass

    return stats


def generate_report(output_format: str = "rich") -> dict:
    """Generate comprehensive threat report."""
    report = {
        "title": "Blue Team Threat Intelligence Report",
        "generated": datetime.utcnow().isoformat() + "Z",
        "ioc_stats": load_ioc_database(),
        "detection_rules": count_detection_rules(),
        "playbooks": count_playbooks(),
        "feeds": count_feeds(),
        "recommendations": []
    }

    # Generate recommendations
    if report["ioc_stats"]["total"] == 0:
        report["recommendations"].append("Run IOC collection: python ioc/ioc_manager.py collect")

    sigma = report["detection_rules"]["sigma"]
    if sigma["count"] < 10:
        report["recommendations"].append(
            f"Only {sigma['count']} Sigma rules deployed. Consider adding more detection rules.")

    if report["feeds"]["enabled"] < report["feeds"]["total"]:
        disabled = report["feeds"]["total"] - report["feeds"]["enabled"]
        report["recommendations"].append(f"{disabled} threat feeds are disabled. Review and enable if appropriate.")

    if report["playbooks"]["count"] < 5:
        report["recommendations"].append("Consider adding playbooks for: DDoS, insider threat, supply chain attack.")

    return report


def print_rich_report(report: dict):
    """Print formatted report."""
    if not console:
        print(json.dumps(report, indent=2))
        return

    console.print(Panel(
        f"[bold]Generated:[/] {report['generated']}\n"
        f"[bold]Toolkit Status:[/] Operational",
        title="[bold cyan]Blue Team Threat Intelligence Report[/]",
        box=box.DOUBLE
    ))

    # IOC Statistics
    ioc = report["ioc_stats"]
    ioc_table = Table(title="IOC Database", box=box.ROUNDED)
    ioc_table.add_column("Metric", style="cyan")
    ioc_table.add_column("Value", style="bold white")
    ioc_table.add_row("Total IOCs", str(ioc["total"]))
    ioc_table.add_row("Added (24h)", str(ioc["recent_24h"]))
    ioc_table.add_row("Added (7d)", str(ioc["recent_7d"]))
    for ioc_type, count in ioc.get("by_type", {}).items():
        ioc_table.add_row(f"  Type: {ioc_type}", str(count))
    console.print(ioc_table)

    # Detection Rules
    rules = report["detection_rules"]
    rules_table = Table(title="Detection Rules", box=box.ROUNDED)
    rules_table.add_column("Type", style="cyan")
    rules_table.add_column("Rules", style="bold green")
    rules_table.add_column("Files", style="dim")
    rules_table.add_row("Sigma (SIEM)", str(rules["sigma"]["count"]), str(rules["sigma"]["files"]))
    rules_table.add_row("YARA (Malware)", str(rules["yara"]["count"]), str(rules["yara"]["files"]))
    for level, count in rules["sigma"].get("by_level", {}).items():
        rules_table.add_row(f"  Sigma Level: {level}", str(count), "")
    console.print(rules_table)

    # Feeds
    feeds = report["feeds"]
    feeds_table = Table(title="Threat Intelligence Feeds", box=box.ROUNDED)
    feeds_table.add_column("Feed", style="cyan")
    feeds_table.add_column("Type", style="white")
    feeds_table.add_column("Status", style="white")
    for feed in feeds.get("feeds", []):
        status = "[green]Enabled[/]" if feed["enabled"] else "[red]Disabled[/]"
        feeds_table.add_row(feed["name"], feed["type"], status)
    console.print(feeds_table)

    # Playbooks
    pbs = report["playbooks"]
    if pbs["playbooks"]:
        pb_table = Table(title="Incident Response Playbooks", box=box.ROUNDED)
        pb_table.add_column("ID", style="cyan")
        pb_table.add_column("Name", style="white")
        pb_table.add_column("Severity", style="white")
        for pb in pbs["playbooks"]:
            sev_color = {"critical": "red", "high": "yellow", "medium": "green"}.get(pb["severity"], "white")
            pb_table.add_row(pb["id"], pb["name"], f"[{sev_color}]{pb['severity'].upper()}[/]")
        console.print(pb_table)

    # Recommendations
    if report["recommendations"]:
        console.print(Panel(
            "\n".join(f"[yellow]>[/] {r}" for r in report["recommendations"]),
            title="[bold yellow]Recommendations[/]",
            box=box.ROUNDED
        ))


def export_markdown(report: dict, output_path: str):
    """Export report as Markdown."""
    lines = [
        f"# {report['title']}",
        f"\n**Generated:** {report['generated']}\n",
        "## IOC Database\n",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total IOCs | {report['ioc_stats']['total']} |",
        f"| Added (24h) | {report['ioc_stats']['recent_24h']} |",
        f"| Added (7d) | {report['ioc_stats']['recent_7d']} |",
        "\n## Detection Rules\n",
        f"| Type | Count |",
        f"|------|-------|",
        f"| Sigma Rules | {report['detection_rules']['sigma']['count']} |",
        f"| YARA Rules | {report['detection_rules']['yara']['count']} |",
        "\n## Threat Feeds\n",
        f"| Feed | Type | Status |",
        f"|------|------|--------|",
    ]
    for feed in report["feeds"].get("feeds", []):
        status = "Enabled" if feed["enabled"] else "Disabled"
        lines.append(f"| {feed['name']} | {feed['type']} | {status} |")

    lines.append("\n## Incident Response Playbooks\n")
    for pb in report["playbooks"].get("playbooks", []):
        lines.append(f"- **{pb['id']}** - {pb['name']} (Severity: {pb['severity']})")

    if report["recommendations"]:
        lines.append("\n## Recommendations\n")
        for r in report["recommendations"]:
            lines.append(f"- {r}")

    Path(output_path).write_text("\n".join(lines))
    print(f"[+] Report exported to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Report Generator")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--markdown", help="Export as Markdown to specified path")
    parser.add_argument("--output", help="Export JSON report to file")
    args = parser.parse_args()

    report = generate_report()

    if args.json:
        print(json.dumps(report, indent=2))
    elif args.markdown:
        export_markdown(report, args.markdown)
    elif args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
        print(f"[+] Report saved to {args.output}")
    else:
        print_rich_report(report)


if __name__ == "__main__":
    main()
