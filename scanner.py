#!/usr/bin/env python3
"""
scanner.py — Main Entry Point
Simple Vulnerability Scanner | Educational Use Only

Usage:
    python scanner.py                        # Interactive mode (menu)
    python scanner.py -t 192.168.1.1         # Scan common ports
    python scanner.py -t 192.168.1.1 -p 1-1024   # Scan port range
    python scanner.py -t 192.168.1.1 --ports 22,80,443   # Specific ports
    python scanner.py -t example.com --no-report         # Skip saving report
"""

import argparse
import sys
import time

import ports as port_scanner
import vulnerabilities as vuln_checker
import report as report_gen

# ─── ANSI colour helpers ────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   BLUE,
    "LOW":      GREEN,
    "INFO":     CYAN,
}


# ─── Banner ─────────────────────────────────────────────────────────────────

BANNER = rf"""
{CYAN}{BOLD}
  ╔══════════════════════════════════════════════════════╗
  ║        Simple Vulnerability Scanner v1.0.0           ║
  ║        Educational & Ethical Hacking Practice        ║
  ╚══════════════════════════════════════════════════════╝
{RESET}{DIM}  ⚠  Only scan systems you own or have written permission to test.{RESET}
"""


def print_banner():
    print(BANNER)


# ─── Display helpers ────────────────────────────────────────────────────────

def print_section(title: str):
    bar = "─" * 54
    print(f"\n{CYAN}{BOLD}  {title}{RESET}")
    print(f"  {bar}")


def print_open_port(port_info: dict):
    port    = port_info["port"]
    service = port_info.get("service", "Unknown")
    banner  = port_info.get("banner", "")
    banner_str = f"  {DIM}{banner[:80]}{RESET}" if banner else ""
    print(f"  {GREEN}[+]{RESET} Port {BOLD}{port:5}{RESET}  {CYAN}{service:15}{RESET}{banner_str}")


def print_finding(finding: dict):
    sev   = finding["severity"]
    color = SEVERITY_COLOR.get(sev, RESET)
    print(f"\n  {color}{BOLD}[{sev}]{RESET} {finding['cve']}")
    print(f"       Port     : {finding['port']}  ({finding['service']})")
    print(f"       Service  : {finding['vuln_service']}")
    print(f"       CVSS     : {finding['cvss']}")
    print(f"       Info     : {finding['description']}")
    print(f"       Fix      : {GREEN}{finding['fix']}{RESET}")


def live_callback(port: int, result):
    """Called after each port is scanned in verbose mode."""
    if result:
        service = result.get("service", "?")
        print(f"    {GREEN}[open]{RESET}  {port}/{service}")


# ─── Core scan workflow ─────────────────────────────────────────────────────

def run_scan(
    target: str,
    port_list: list[int] | None,
    port_range: tuple[int, int] | None,
    verbose: bool,
    save_report: bool,
    timeout: float,
    threads: int,
):
    print_section(f"Target: {target}")

    # Resolve hostname
    try:
        ip = port_scanner.resolve_target(target)
    except ValueError as e:
        print(f"\n  {RED}[ERROR]{RESET} {e}\n")
        sys.exit(1)

    if ip != target:
        print(f"  Resolved  → {ip}")

    print(f"  Scanning  …", end="", flush=True)
    start = time.monotonic()

    callback = live_callback if verbose else None

    if verbose:
        print()  # newline before per-port output

    # Determine port list
    if port_list:
        scan_result_ports = port_scanner.scan_ports(
            ip, ports=port_list, timeout=timeout, max_workers=threads, callback=callback
        )
    elif port_range:
        scan_result_ports = port_scanner.scan_ports(
            ip, port_range=port_range, timeout=timeout, max_workers=threads, callback=callback
        )
    else:
        scan_result_ports = port_scanner.scan_ports(
            ip, ports=list(port_scanner.COMMON_PORTS.keys()),
            timeout=timeout, max_workers=threads, callback=callback
        )

    duration = round(time.monotonic() - start, 2)

    if not verbose:
        print(f"  {GREEN}done{RESET}  ({duration}s)")

    # Build scan_data dict for reporting
    from datetime import datetime
    scan_data = {
        "target":            target,
        "ip":                ip,
        "scan_time":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds":  duration,
        "open_ports":        scan_result_ports,
        "total_open":        len(scan_result_ports),
    }

    # Print open ports
    print_section("Open Ports")
    if not scan_result_ports:
        print(f"  {DIM}No open ports found.{RESET}")
    else:
        for p in scan_result_ports:
            print_open_port(p)

    # Vulnerability check
    print_section("Vulnerability Analysis")
    findings = vuln_checker.check_vulnerabilities(scan_result_ports)

    if not findings:
        print(f"  {GREEN}No matches found in the local CVE database.{RESET}")
        print(f"  {DIM}(This does NOT mean the host is fully secure.){RESET}")
    else:
        for f in findings:
            print_finding(f)

    # Summary
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    print_section("Summary")
    print(f"  Open ports   : {scan_data['total_open']}")
    print(f"  Findings     : {len(findings)}")
    if findings:
        print(f"  Critical     : {RED}{critical}{RESET}")
        print(f"  High         : {YELLOW}{high}{RESET}")

    # Save reports
    if save_report:
        paths = report_gen.save_all(scan_data, findings)
        print_section("Reports Saved")
        for fmt, path in paths.items():
            print(f"  [{fmt.upper():4}]  {path}")

    print()
    return scan_data, findings


# ─── Interactive menu ────────────────────────────────────────────────────────

def interactive_mode():
    print_banner()
    print(f"  {BOLD}Interactive Mode{RESET}\n")

    target = input("  Enter target IP or hostname: ").strip()
    if not target:
        print("  No target entered. Exiting.")
        sys.exit(0)

    print("\n  Port scan mode:")
    print("  1) Common ports (default — fast)")
    print("  2) Port range")
    print("  3) Specific ports")
    choice = input("  Choice [1]: ").strip() or "1"

    port_list  = None
    port_range = None

    if choice == "2":
        r = input("  Enter range (e.g. 1-1024): ").strip()
        try:
            start, end = map(int, r.split("-"))
            port_range = (start, end)
        except ValueError:
            print("  Invalid range. Using common ports.")
    elif choice == "3":
        raw = input("  Enter ports (e.g. 22,80,443): ").strip()
        try:
            port_list = [int(p.strip()) for p in raw.split(",")]
        except ValueError:
            print("  Invalid port list. Using common ports.")

    save = input("\n  Save reports? (Y/n): ").strip().lower() != "n"

    run_scan(
        target=target,
        port_list=port_list,
        port_range=port_range,
        verbose=False,
        save_report=save,
        timeout=1.0,
        threads=100,
    )


# ─── CLI argument mode ───────────────────────────────────────────────────────

def cli_mode():
    parser = argparse.ArgumentParser(
        description="Simple Vulnerability Scanner — Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -t 192.168.1.1
  python scanner.py -t 192.168.1.1 -p 1-1024
  python scanner.py -t 192.168.1.1 --ports 22,80,443,3306
  python scanner.py -t scanme.nmap.org --verbose --no-report
        """,
    )
    parser.add_argument("-t", "--target",    required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--range",     help="Port range, e.g. 1-1024")
    parser.add_argument("--ports",           help="Comma-separated specific ports, e.g. 22,80,443")
    parser.add_argument("--timeout",         type=float, default=1.0, help="Seconds per port (default 1.0)")
    parser.add_argument("--threads",         type=int,   default=100, help="Worker threads (default 100)")
    parser.add_argument("--verbose", "-v",   action="store_true", help="Print each open port as found")
    parser.add_argument("--no-report",       action="store_true",  help="Skip saving reports to disk")
    args = parser.parse_args()

    port_list  = None
    port_range = None

    if args.ports:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(f"{RED}[ERROR]{RESET} Invalid --ports value.")
            sys.exit(1)
    elif args.range:
        try:
            start, end = map(int, args.range.split("-"))
            port_range = (start, end)
        except ValueError:
            print(f"{RED}[ERROR]{RESET} Invalid --range value (use start-end, e.g. 1-1024).")
            sys.exit(1)

    print_banner()
    run_scan(
        target=args.target,
        port_list=port_list,
        port_range=port_range,
        verbose=args.verbose,
        save_report=not args.no_report,
        timeout=args.timeout,
        threads=args.threads,
    )


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No CLI args → launch interactive menu
        interactive_mode()
    else:
        cli_mode()
