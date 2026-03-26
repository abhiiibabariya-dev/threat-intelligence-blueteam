#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Mapper - Blue Team Toolkit
Maps detection rules and playbooks to MITRE ATT&CK techniques to identify coverage gaps.
"""

import argparse
import json
import sys
import re
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("Error: pyyaml required. pip install pyyaml")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    console = None


# MITRE ATT&CK Enterprise Tactics and common Techniques
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance"
}

MITRE_TECHNIQUES = {
    "T1566": {"name": "Phishing", "tactic": "TA0001", "subtechniques": ["T1566.001", "T1566.002", "T1566.003"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1133": {"name": "External Remote Services", "tactic": "TA0001"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002",
              "subtechniques": ["T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007"]},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0002", "subtechniques": ["T1053.003", "T1053.005"]},
    "T1204": {"name": "User Execution", "tactic": "TA0002"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "TA0003"},
    "T1136": {"name": "Create Account", "tactic": "TA0003", "subtechniques": ["T1136.001", "T1136.002"]},
    "T1505": {"name": "Server Software Component", "tactic": "TA0003", "subtechniques": ["T1505.003"]},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004",
              "subtechniques": ["T1548.001", "T1548.003"]},
    "T1055": {"name": "Process Injection", "tactic": "TA0005"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006",
              "subtechniques": ["T1110.001", "T1110.002", "T1110.003"]},
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006"},
    "T1087": {"name": "Account Discovery", "tactic": "TA0007"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "TA0007"},
    "T1021": {"name": "Remote Services", "tactic": "TA0008"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "TA0008"},
    "T1560": {"name": "Archive Collected Data", "tactic": "TA0009"},
    "T1005": {"name": "Data from Local System", "tactic": "TA0009"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "TA0011"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040"},
}


def scan_sigma_rules(rules_dir: str) -> list:
    """Scan Sigma rules for ATT&CK technique references."""
    coverage = []
    rules_path = Path(rules_dir)

    for rule_file in rules_path.rglob("*.yml"):
        try:
            content = rule_file.read_text()
            docs = list(yaml.safe_load_all(content))
        except Exception:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            title = doc.get("title", rule_file.stem)
            tags = doc.get("tags", [])
            techniques = []

            for tag in tags:
                tag_str = str(tag)
                match = re.search(r'attack\.t(\d{4}(?:\.\d{3})?)', tag_str.lower())
                if match:
                    techniques.append(f"T{match.group(1).upper()}")
                # Also match tactic names
                tactic_match = re.search(r'attack\.(initial.access|execution|persistence|'
                                         r'privilege.escalation|defense.evasion|credential.access|'
                                         r'discovery|lateral.movement|collection|exfiltration|'
                                         r'command.and.control|impact)', tag_str.lower())
                if tactic_match:
                    pass  # Tactics extracted from technique mapping

            # Also search the description and detection logic for technique IDs
            full_text = json.dumps(doc)
            for tid in re.findall(r'T\d{4}(?:\.\d{3})?', full_text):
                if tid not in techniques:
                    techniques.append(tid)

            if techniques:
                coverage.append({
                    "source": "sigma",
                    "file": str(rule_file.relative_to(rules_path.parent.parent)),
                    "title": title,
                    "techniques": techniques,
                    "level": doc.get("level", "medium"),
                    "status": doc.get("status", "experimental")
                })

    return coverage


def scan_yara_rules(rules_dir: str) -> list:
    """Scan YARA rules for ATT&CK references in metadata."""
    coverage = []
    rules_path = Path(rules_dir)

    for rule_file in rules_path.rglob("*.yar"):
        try:
            content = rule_file.read_text()
        except Exception:
            continue

        # Parse YARA rule names and metadata
        for match in re.finditer(r'rule\s+(\w+)\s*\{(.*?)\}', content, re.DOTALL):
            rule_name = match.group(1)
            rule_body = match.group(2)

            techniques = re.findall(r'T\d{4}(?:\.\d{3})?', rule_body)

            # Infer techniques from rule patterns
            inferred = []
            body_lower = rule_body.lower()
            if 'powershell' in body_lower or 'encodedcommand' in body_lower:
                inferred.append("T1059.001")
            if 'webshell' in rule_name.lower() or 'web_shell' in body_lower:
                inferred.append("T1505.003")
            if 'mimikatz' in body_lower:
                inferred.append("T1003")
            if 'ransomware' in body_lower or 'ransom' in body_lower:
                inferred.append("T1486")
            if 'macro' in body_lower or 'vba' in body_lower:
                inferred.append("T1204")
            if 'cobalt' in body_lower or 'beacon' in body_lower:
                inferred.append("T1071")

            all_techniques = list(set(techniques + inferred))
            if all_techniques:
                coverage.append({
                    "source": "yara",
                    "file": str(rule_file.relative_to(rules_path.parent.parent)),
                    "title": rule_name,
                    "techniques": all_techniques,
                    "level": "detection",
                    "status": "active"
                })

    return coverage


def scan_playbooks(playbooks_dir: str) -> list:
    """Scan IR playbooks for ATT&CK tactic references."""
    coverage = []
    pb_path = Path(playbooks_dir)

    for pb_file in pb_path.rglob("*.yaml"):
        try:
            data = yaml.safe_load(pb_file.read_text())
        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        for playbook in data.get("playbooks", []):
            tactics = playbook.get("mitre_tactics", [])
            name = playbook.get("name", pb_file.stem)
            pb_id = playbook.get("id", "")

            # Map tactic names to technique IDs where possible
            technique_ids = []
            for technique_id, technique_info in MITRE_TECHNIQUES.items():
                tactic_id = technique_info.get("tactic", "")
                tactic_name = MITRE_TACTICS.get(tactic_id, "")
                if tactic_name in tactics:
                    technique_ids.append(technique_id)

            coverage.append({
                "source": "playbook",
                "file": str(pb_file.relative_to(pb_path.parent)),
                "title": f"{pb_id} - {name}",
                "tactics": tactics,
                "techniques": technique_ids,
                "level": playbook.get("severity", "high"),
                "status": "active"
            })

    return coverage


def scan_log_analyzer(scripts_dir: str) -> list:
    """Extract ATT&CK mappings from log analyzer patterns."""
    coverage = []
    analyzer_path = Path(scripts_dir) / "log_analyzer.py"

    if not analyzer_path.exists():
        return coverage

    content = analyzer_path.read_text()
    for match in re.finditer(r'"name":\s*"([^"]+)".*?"mitre":\s*"(T\d{4}(?:\.\d{3})?)"', content, re.DOTALL):
        coverage.append({
            "source": "log_analyzer",
            "file": "scripts/log_analyzer.py",
            "title": match.group(1),
            "techniques": [match.group(2)],
            "level": "detection",
            "status": "active"
        })

    return coverage


def build_coverage_map(all_coverage: list) -> dict:
    """Build a technique-to-coverage mapping."""
    coverage_map = defaultdict(list)

    for item in all_coverage:
        for technique in item.get("techniques", []):
            base_technique = technique.split(".")[0]
            coverage_map[technique].append(item)
            if technique != base_technique:
                coverage_map[base_technique].append(item)

    return dict(coverage_map)


def identify_gaps(coverage_map: dict) -> list:
    """Identify ATT&CK techniques with no coverage."""
    gaps = []
    for tid, tinfo in MITRE_TECHNIQUES.items():
        if tid not in coverage_map:
            tactic = MITRE_TACTICS.get(tinfo.get("tactic", ""), "Unknown")
            gaps.append({
                "technique_id": tid,
                "technique_name": tinfo["name"],
                "tactic": tactic
            })
    return gaps


def print_coverage_report(all_coverage: list, coverage_map: dict, gaps: list):
    """Print formatted coverage report."""
    if not console:
        print(json.dumps({"coverage": all_coverage, "gaps": gaps}, indent=2))
        return

    # Summary
    total_techniques = len(MITRE_TECHNIQUES)
    covered = len([t for t in MITRE_TECHNIQUES if t in coverage_map])
    pct = (covered / total_techniques * 100) if total_techniques else 0

    console.print(Panel(
        f"[bold]Total ATT&CK Techniques Tracked:[/] {total_techniques}\n"
        f"[bold green]Covered:[/] {covered} ({pct:.0f}%)\n"
        f"[bold red]Gaps:[/] {len(gaps)}\n"
        f"[bold]Detection Sources:[/] {len(all_coverage)} rules/playbooks",
        title="[bold]MITRE ATT&CK Coverage Report[/]",
        box=box.DOUBLE
    ))

    # Coverage by tactic
    tactic_coverage = defaultdict(lambda: {"covered": 0, "total": 0})
    for tid, tinfo in MITRE_TECHNIQUES.items():
        tactic = MITRE_TACTICS.get(tinfo.get("tactic", ""), "Unknown")
        tactic_coverage[tactic]["total"] += 1
        if tid in coverage_map:
            tactic_coverage[tactic]["covered"] += 1

    tactic_table = Table(title="Coverage by Tactic", box=box.ROUNDED)
    tactic_table.add_column("Tactic", style="cyan")
    tactic_table.add_column("Covered", style="green")
    tactic_table.add_column("Total", style="white")
    tactic_table.add_column("Coverage", style="bold")
    tactic_table.add_column("Bar", style="white")

    for tactic, data in sorted(tactic_coverage.items()):
        pct = (data["covered"] / data["total"] * 100) if data["total"] else 0
        bar_filled = int(pct / 5)
        bar = f"[green]{'█' * bar_filled}[/][dim]{'░' * (20 - bar_filled)}[/]"
        pct_color = "green" if pct >= 75 else "yellow" if pct >= 50 else "red"
        tactic_table.add_row(tactic, str(data["covered"]), str(data["total"]),
                             f"[{pct_color}]{pct:.0f}%[/]", bar)

    console.print(tactic_table)

    # Covered techniques
    covered_table = Table(title="Detected Techniques", box=box.ROUNDED)
    covered_table.add_column("Technique", style="bold")
    covered_table.add_column("Name", style="white")
    covered_table.add_column("Sources", style="cyan")
    covered_table.add_column("Count", style="green")

    for tid in sorted(coverage_map.keys()):
        if tid in MITRE_TECHNIQUES:
            sources = set(c["source"] for c in coverage_map[tid])
            covered_table.add_row(tid, MITRE_TECHNIQUES[tid]["name"],
                                  ", ".join(sources), str(len(coverage_map[tid])))

    console.print(covered_table)

    # Gaps
    if gaps:
        gap_table = Table(title="[bold red]Coverage Gaps[/]", box=box.ROUNDED)
        gap_table.add_column("Technique", style="red")
        gap_table.add_column("Name", style="white")
        gap_table.add_column("Tactic", style="yellow")

        for gap in gaps:
            gap_table.add_row(gap["technique_id"], gap["technique_name"], gap["tactic"])

        console.print(gap_table)


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Coverage Mapper")
    parser.add_argument("--rules-dir", default="rules",
                        help="Directory containing detection rules")
    parser.add_argument("--playbooks-dir", default="playbooks",
                        help="Directory containing IR playbooks")
    parser.add_argument("--scripts-dir", default="scripts",
                        help="Directory containing analysis scripts")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--gaps-only", action="store_true", help="Only show coverage gaps")
    args = parser.parse_args()

    all_coverage = []

    # Scan all sources
    sigma_dir = Path(args.rules_dir) / "sigma"
    if sigma_dir.exists():
        all_coverage.extend(scan_sigma_rules(str(sigma_dir)))

    yara_dir = Path(args.rules_dir) / "yara"
    if yara_dir.exists():
        all_coverage.extend(scan_yara_rules(str(yara_dir)))

    pb_dir = Path(args.playbooks_dir)
    if pb_dir.exists():
        all_coverage.extend(scan_playbooks(str(pb_dir)))

    scripts_dir = Path(args.scripts_dir)
    if scripts_dir.exists():
        all_coverage.extend(scan_log_analyzer(str(scripts_dir)))

    coverage_map = build_coverage_map(all_coverage)
    gaps = identify_gaps(coverage_map)

    if args.json:
        output = {
            "total_techniques": len(MITRE_TECHNIQUES),
            "covered": len([t for t in MITRE_TECHNIQUES if t in coverage_map]),
            "gaps": gaps,
            "coverage": [{k: v for k, v in c.items()} for c in all_coverage]
        }
        print(json.dumps(output, indent=2))
    elif args.gaps_only:
        for gap in gaps:
            print(f"{gap['technique_id']}: {gap['technique_name']} ({gap['tactic']})")
    else:
        print_coverage_report(all_coverage, coverage_map, gaps)


if __name__ == "__main__":
    main()
