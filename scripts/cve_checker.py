#!/usr/bin/env python3
"""
CVE Vulnerability Checker - Blue Team Toolkit
Query CVE databases for known vulnerabilities by product, keyword, or CVE ID.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta

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

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def search_nvd(keyword: str = None, cve_id: str = None, api_key: str = None,
               days: int = None, severity: str = None) -> list:
    """Search NVD for CVEs."""
    params = {"resultsPerPage": 20}
    headers = {}

    if api_key:
        headers["apiKey"] = api_key

    if cve_id:
        params["cveId"] = cve_id
    elif keyword:
        params["keywordSearch"] = keyword

    if days:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT23:59:59.999")

    if severity:
        params["cvssV3Severity"] = severity.upper()

    try:
        resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"[!] NVD API error: {e}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_info = {
            "id": cve.get("id", "Unknown"),
            "published": cve.get("published", "")[:10],
            "modified": cve.get("lastModified", "")[:10],
            "description": "",
            "cvss_score": None,
            "cvss_severity": None,
            "cvss_vector": None,
            "references": [],
            "weaknesses": []
        }

        # Description
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                cve_info["description"] = desc.get("value", "")
                break

        # CVSS v3.1
        metrics = cve.get("metrics", {})
        for cvss_data in metrics.get("cvssMetricV31", []):
            score_data = cvss_data.get("cvssData", {})
            cve_info["cvss_score"] = score_data.get("baseScore")
            cve_info["cvss_severity"] = score_data.get("baseSeverity")
            cve_info["cvss_vector"] = score_data.get("vectorString")
            break

        # CVSS v3.0 fallback
        if not cve_info["cvss_score"]:
            for cvss_data in metrics.get("cvssMetricV30", []):
                score_data = cvss_data.get("cvssData", {})
                cve_info["cvss_score"] = score_data.get("baseScore")
                cve_info["cvss_severity"] = score_data.get("baseSeverity")
                break

        # References
        for ref in cve.get("references", [])[:5]:
            cve_info["references"].append(ref.get("url", ""))

        # Weaknesses (CWE)
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cve_info["weaknesses"].append(desc.get("value", ""))

        results.append(cve_info)

    return results


def get_cisa_kev() -> list:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"[!] CISA KEV fetch error: {e}")
        return []


def check_kev(cve_id: str, kev_list: list) -> dict:
    """Check if a CVE is in the CISA KEV list."""
    for entry in kev_list:
        if entry.get("cveID") == cve_id:
            return {
                "in_kev": True,
                "vendor": entry.get("vendorProject"),
                "product": entry.get("product"),
                "date_added": entry.get("dateAdded"),
                "due_date": entry.get("dueDate"),
                "action": entry.get("requiredAction"),
                "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown")
            }
    return {"in_kev": False}


def print_rich_results(results: list, kev_list: list = None):
    """Display results with Rich formatting."""
    if not console:
        print(json.dumps(results, indent=2))
        return

    if not results:
        console.print("[yellow]No CVEs found matching your query.[/]")
        return

    for cve in results:
        score = cve.get("cvss_score")
        severity = cve.get("cvss_severity", "N/A")
        score_color = "bright_green"
        if score and score >= 9.0:
            score_color = "red"
        elif score and score >= 7.0:
            score_color = "bright_red"
        elif score and score >= 4.0:
            score_color = "yellow"

        score_str = f"{score}" if score else "N/A"
        title = f"[bold]{cve['id']}[/] | CVSS: [{score_color}]{score_str} ({severity})[/]"

        # Check KEV
        kev_info = ""
        if kev_list:
            kev = check_kev(cve["id"], kev_list)
            if kev["in_kev"]:
                kev_info = f"\n[bold red]CISA KEV: ACTIVELY EXPLOITED[/] | Due: {kev['due_date']} | Ransomware: {kev['ransomware_use']}"
                kev_info += f"\n[bold]Required Action:[/] {kev['action']}"

        desc = cve["description"][:300] + ("..." if len(cve["description"]) > 300 else "")
        body = f"[dim]Published: {cve['published']} | Modified: {cve['modified']}[/]\n"
        body += f"CWE: {', '.join(cve['weaknesses']) if cve['weaknesses'] else 'N/A'}\n"
        if cve.get("cvss_vector"):
            body += f"Vector: {cve['cvss_vector']}\n"
        body += f"\n{desc}"
        if kev_info:
            body += kev_info
        if cve["references"]:
            body += "\n\n[bold]References:[/]\n" + "\n".join(f"  - {r}" for r in cve["references"][:3])

        console.print(Panel(body, title=title, box=box.ROUNDED))
        console.print()


def main():
    parser = argparse.ArgumentParser(description="CVE Vulnerability Checker")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search NVD for CVEs")
    search_parser.add_argument("query", help="Keyword or product name to search")
    search_parser.add_argument("--days", type=int, help="Only show CVEs from last N days")
    search_parser.add_argument("--severity", choices=["low", "medium", "high", "critical"],
                               help="Filter by CVSS severity")
    search_parser.add_argument("--api-key", help="NVD API key for higher rate limits")
    search_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Lookup command
    lookup_parser = subparsers.add_parser("lookup", help="Look up a specific CVE")
    lookup_parser.add_argument("cve_id", help="CVE ID (e.g., CVE-2024-1234)")
    lookup_parser.add_argument("--api-key", help="NVD API key")
    lookup_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # KEV command
    kev_parser = subparsers.add_parser("kev", help="List CISA Known Exploited Vulnerabilities")
    kev_parser.add_argument("--search", help="Search KEV by keyword")
    kev_parser.add_argument("--recent", type=int, default=10, help="Show N most recent entries")
    kev_parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "search":
        kev_list = get_cisa_kev()
        results = search_nvd(keyword=args.query, days=args.days,
                             severity=args.severity, api_key=args.api_key)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print_rich_results(results, kev_list)

    elif args.command == "lookup":
        kev_list = get_cisa_kev()
        results = search_nvd(cve_id=args.cve_id, api_key=args.api_key)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print_rich_results(results, kev_list)

    elif args.command == "kev":
        kev_list = get_cisa_kev()
        if args.search:
            keyword = args.search.lower()
            kev_list = [k for k in kev_list if keyword in json.dumps(k).lower()]
        kev_list = sorted(kev_list, key=lambda x: x.get("dateAdded", ""), reverse=True)
        kev_list = kev_list[:args.recent]

        if args.json:
            print(json.dumps(kev_list, indent=2))
        elif console:
            table = Table(title="CISA Known Exploited Vulnerabilities", box=box.ROUNDED)
            table.add_column("CVE ID", style="bold red")
            table.add_column("Vendor", style="cyan")
            table.add_column("Product", style="white")
            table.add_column("Added", style="dim")
            table.add_column("Due Date", style="yellow")
            table.add_column("Ransomware", style="red")
            for k in kev_list:
                table.add_row(k.get("cveID", ""), k.get("vendorProject", ""),
                              k.get("product", ""), k.get("dateAdded", ""),
                              k.get("dueDate", ""),
                              k.get("knownRansomwareCampaignUse", "Unknown"))
            console.print(table)
        else:
            print(json.dumps(kev_list, indent=2))


if __name__ == "__main__":
    main()
