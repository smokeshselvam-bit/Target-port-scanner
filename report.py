"""
report.py — Report Generation Module
Simple Vulnerability Scanner | Educational Use Only
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def _base_filename(target: str) -> str:
    """Generate a timestamped filename safe for the filesystem."""
    safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_{safe_target}_{timestamp}"


# ---------------------------------------------------------------------------
# TXT Report
# ---------------------------------------------------------------------------

def save_txt(scan_data: dict, findings: list[dict], filename: str | None = None) -> Path:
    """Save a human-readable TXT report."""
    base = filename or _base_filename(scan_data.get("target", "unknown"))
    path = RESULTS_DIR / f"{base}.txt"

    with open(path, "w") as f:
        _write_txt(f, scan_data, findings)

    return path


def _write_txt(f, scan_data: dict, findings: list[dict]):
    sep = "=" * 60
    thin = "-" * 60

    f.write(f"{sep}\n")
    f.write("   SIMPLE VULNERABILITY SCANNER — SCAN REPORT\n")
    f.write(f"{sep}\n\n")
    f.write(f"  Target     : {scan_data.get('target')}\n")
    f.write(f"  IP Address : {scan_data.get('ip')}\n")
    f.write(f"  Scan Time  : {scan_data.get('scan_time')}\n")
    f.write(f"  Duration   : {scan_data.get('duration_seconds')}s\n")
    f.write(f"  Open Ports : {scan_data.get('total_open', 0)}\n")
    f.write(f"  Findings   : {len(findings)}\n\n")

    f.write(f"{sep}\n")
    f.write(" OPEN PORTS\n")
    f.write(f"{sep}\n")
    for p in scan_data.get("open_ports", []):
        banner_str = f"  ← {p['banner']}" if p.get("banner") else ""
        f.write(f"  [+] Port {p['port']:5}  {p['service']:15}{banner_str}\n")

    f.write(f"\n{sep}\n")
    f.write(" VULNERABILITY FINDINGS\n")
    f.write(f"{sep}\n")
    if not findings:
        f.write("  No known vulnerabilities matched in the local database.\n")
    else:
        for v in findings:
            f.write(f"\n  {thin}\n")
            f.write(f"  CVE        : {v['cve']}\n")
            f.write(f"  Port       : {v['port']}  ({v['service']})\n")
            f.write(f"  Service    : {v['vuln_service']}\n")
            f.write(f"  Severity   : {v['severity']}   CVSS: {v['cvss']}\n")
            f.write(f"  Description: {v['description']}\n")
            f.write(f"  Fix        : {v['fix']}\n")

    f.write(f"\n{sep}\n")
    f.write("  ⚠ FOR EDUCATIONAL AND AUTHORIZED TESTING USE ONLY\n")
    f.write(f"{sep}\n")


# ---------------------------------------------------------------------------
# CSV Report
# ---------------------------------------------------------------------------

def save_csv(scan_data: dict, findings: list[dict], filename: str | None = None) -> Path:
    """Save findings to a CSV file."""
    base = filename or _base_filename(scan_data.get("target", "unknown"))
    path = RESULTS_DIR / f"{base}.csv"

    fieldnames = [
        "target", "ip", "port", "service", "banner",
        "cve", "vuln_service", "severity", "cvss", "description", "fix",
    ]

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        if findings:
            for v in findings:
                row = {
                    "target":       scan_data.get("target"),
                    "ip":           scan_data.get("ip"),
                    "port":         v["port"],
                    "service":      v["service"],
                    "banner":       v.get("banner", ""),
                    "cve":          v["cve"],
                    "vuln_service": v["vuln_service"],
                    "severity":     v["severity"],
                    "cvss":         v["cvss"],
                    "description":  v["description"],
                    "fix":          v["fix"],
                }
                writer.writerow(row)
        else:
            # Write a single "clean" row
            writer.writerow({
                "target": scan_data.get("target"),
                "ip":     scan_data.get("ip"),
                "port":   "N/A",
                "service": "N/A",
                "banner": "",
                "cve": "No findings",
                "vuln_service": "",
                "severity": "",
                "cvss": "",
                "description": "No known vulnerabilities matched.",
                "fix": "",
            })

    return path


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def save_json(scan_data: dict, findings: list[dict], filename: str | None = None) -> Path:
    """Save full scan + findings as a JSON file."""
    base = filename or _base_filename(scan_data.get("target", "unknown"))
    path = RESULTS_DIR / f"{base}.json"

    report = {
        "scanner":  "Simple Vulnerability Scanner",
        "version":  "1.0.0",
        "scan_info": scan_data,
        "vulnerabilities": findings,
        "summary": {
            "total_open_ports": scan_data.get("total_open", 0),
            "total_vulnerabilities": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":      sum(1 for f in findings if f["severity"] == "LOW"),
        },
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    return path


# ---------------------------------------------------------------------------
# Save All Formats
# ---------------------------------------------------------------------------

def save_all(scan_data: dict, findings: list[dict]) -> dict[str, Path]:
    """Save TXT, CSV, and JSON reports. Returns a dict of format → path."""
    base = _base_filename(scan_data.get("target", "unknown"))
    return {
        "txt":  save_txt(scan_data, findings, base),
        "csv":  save_csv(scan_data, findings, base),
        "json": save_json(scan_data, findings, base),
    }
