#!/usr/bin/env python3
"""
Hash Checker - Check file hashes against threat intelligence sources.
Supports SHA256, SHA1, and MD5.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import requests
import yaml
from rich.console import Console
from rich.table import Table

console = Console()
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config" / "settings.yaml"
IOC_DB = BASE_DIR / "output" / "ioc_database.json"


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f)
    return {}


def hash_file(filepath):
    """Compute MD5, SHA1, and SHA256 for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def check_local_iocs(hash_value):
    """Check hash against local IOC database."""
    if not IOC_DB.exists():
        return []
    with open(IOC_DB) as f:
        db = json.load(f)
    return [
        ioc for ioc in db.get("iocs", [])
        if ioc.get("type") == "hash" and hash_value.lower() in ioc["value"].lower()
    ]


def check_virustotal(hash_value, api_key):
    """Check hash against VirusTotal API."""
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": data.get("malicious", 0),
                "suspicious": data.get("suspicious", 0),
                "undetected": data.get("undetected", 0),
                "harmless": data.get("harmless", 0),
            }
        elif resp.status_code == 404:
            return {"status": "not_found"}
    except requests.RequestException:
        return {"status": "error"}
    return None


def check_malware_bazaar(hash_value):
    """Check hash against MalwareBazaar."""
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        resp = requests.post(url, data={"query": "get_info", "hash": hash_value}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                sample = data["data"][0]
                return {
                    "file_type": sample.get("file_type", "unknown"),
                    "signature": sample.get("signature"),
                    "tags": sample.get("tags", []),
                    "first_seen": sample.get("first_seen"),
                }
    except requests.RequestException:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Hash Checker - Blue Team Toolkit")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hash", "-H", help="Hash value to check (MD5, SHA1, or SHA256)")
    group.add_argument("--file", "-f", help="File path to hash and check")
    args = parser.parse_args()

    config = load_config()
    vt_key = config.get("api_keys", {}).get("virustotal", "")

    if args.file:
        path = Path(args.file)
        if not path.exists():
            console.print(f"[red]File not found: {args.file}[/]")
            sys.exit(1)
        hashes = hash_file(path)
        console.print(f"[bold]File: {args.file}[/]")
        console.print(f"  MD5:    [cyan]{hashes['md5']}[/]")
        console.print(f"  SHA1:   [cyan]{hashes['sha1']}[/]")
        console.print(f"  SHA256: [cyan]{hashes['sha256']}[/]\n")
        check_value = hashes["sha256"]
    else:
        check_value = args.hash
        console.print(f"[bold]Checking hash:[/] [cyan]{check_value}[/]\n")

    table = Table(title="Reputation Results")
    table.add_column("Source", style="bold")
    table.add_column("Result")
    table.add_column("Details")

    # Local IOC check
    local = check_local_iocs(check_value)
    if local:
        table.add_row("Local IOC DB", "[red]MATCH[/]",
                       f"Found in {local[0]['source']} ({local[0]['collected'][:10]})")
    else:
        table.add_row("Local IOC DB", "[green]Clean[/]", "No match")

    # VirusTotal
    if vt_key:
        vt = check_virustotal(check_value, vt_key)
        if vt and "malicious" in vt:
            total_engines = sum(vt.values())
            detections = vt["malicious"] + vt["suspicious"]
            style = "[red]MALICIOUS[/]" if detections > 0 else "[green]Clean[/]"
            table.add_row("VirusTotal", style,
                          f"{detections}/{total_engines} detections")
        elif vt and vt.get("status") == "not_found":
            table.add_row("VirusTotal", "[yellow]Unknown[/]", "Not found in VT")
        else:
            table.add_row("VirusTotal", "[yellow]Error[/]", "API request failed")
    else:
        table.add_row("VirusTotal", "[dim]Skipped[/]", "No API key configured")

    # MalwareBazaar
    mb = check_malware_bazaar(check_value)
    if mb:
        tags = ", ".join(mb.get("tags", [])[:5]) if mb.get("tags") else "none"
        table.add_row("MalwareBazaar", "[red]KNOWN MALWARE[/]",
                       f"{mb.get('signature', 'unknown')} | {mb.get('file_type')} | tags: {tags}")
    else:
        table.add_row("MalwareBazaar", "[green]Clean[/]", "Not found")

    console.print(table)


if __name__ == "__main__":
    main()
