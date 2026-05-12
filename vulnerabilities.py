"""
vulnerabilities.py — Vulnerability Detection Module
Simple Vulnerability Scanner | Educational Use Only

Contains a local CVE reference database and banner-matching logic.
In a real-world tool this would query the NVD API or a live CVE feed.
"""

import re

# ---------------------------------------------------------------------------
# Local CVE Reference Database
# Format: { "keyword_pattern": [CVE_entries] }
# ---------------------------------------------------------------------------

CVE_DATABASE = {
    # Apache HTTP Server
    "apache": [
        {
            "cve": "CVE-2021-41773",
            "service": "Apache HTTP Server",
            "affected_versions": ["2.4.49"],
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Path traversal and remote code execution via mod_cgi.",
            "fix": "Upgrade to Apache 2.4.50 or later.",
        },
        {
            "cve": "CVE-2021-42013",
            "service": "Apache HTTP Server",
            "affected_versions": ["2.4.49", "2.4.50"],
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Incomplete fix for CVE-2021-41773 allows further path traversal.",
            "fix": "Upgrade to Apache 2.4.51 or later.",
        },
        {
            "cve": "CVE-2022-22720",
            "service": "Apache HTTP Server",
            "affected_versions": ["2.4.52"],
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "HTTP request smuggling via incomplete request handling.",
            "fix": "Upgrade to Apache 2.4.53 or later.",
        },
    ],
    # OpenSSH
    "openssh": [
        {
            "cve": "CVE-2023-38408",
            "service": "OpenSSH",
            "affected_versions": ["< 9.3p2"],
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Remote code execution via ssh-agent forwarding (PKCS#11 providers).",
            "fix": "Upgrade to OpenSSH 9.3p2 or later.",
        },
        {
            "cve": "CVE-2024-6387",
            "service": "OpenSSH",
            "affected_versions": ["8.5p1 - 9.7p1"],
            "severity": "CRITICAL",
            "cvss": 8.1,
            "description": "regreSSHion: race condition in signal handler allows unauthenticated RCE.",
            "fix": "Upgrade to OpenSSH 9.8p1 or later.",
        },
        {
            "cve": "CVE-2016-6515",
            "service": "OpenSSH",
            "affected_versions": ["< 7.4"],
            "severity": "HIGH",
            "cvss": 7.8,
            "description": "DoS via long passwords in auth_password function.",
            "fix": "Upgrade to OpenSSH 7.4 or later.",
        },
    ],
    # FTP
    "vsftpd": [
        {
            "cve": "CVE-2011-2523",
            "service": "vsftpd",
            "affected_versions": ["2.3.4"],
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "Backdoor in vsftpd 2.3.4 allows remote command execution.",
            "fix": "Replace with vsftpd 2.3.5 or later immediately.",
        },
    ],
    # ProFTPD
    "proftpd": [
        {
            "cve": "CVE-2019-12815",
            "service": "ProFTPD",
            "affected_versions": ["< 1.3.6"],
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Arbitrary file copy via mod_copy without authentication.",
            "fix": "Upgrade to ProFTPD 1.3.6 or apply patch.",
        },
    ],
    # MySQL
    "mysql": [
        {
            "cve": "CVE-2021-2154",
            "service": "MySQL Server",
            "affected_versions": ["5.7.x <= 5.7.33", "8.0.x <= 8.0.23"],
            "severity": "HIGH",
            "cvss": 7.2,
            "description": "Server DoS vulnerability in the DML component.",
            "fix": "Upgrade to MySQL 5.7.34+ or 8.0.24+.",
        },
    ],
    # Redis
    "redis": [
        {
            "cve": "CVE-2022-0543",
            "service": "Redis",
            "affected_versions": ["< 6.2.7", "< 7.0"],
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "Lua sandbox escape allows arbitrary code execution (Debian/Ubuntu packages).",
            "fix": "Upgrade to Redis 6.2.7+ or 7.0+.",
        },
    ],
    # Telnet (no auth)
    "telnet": [
        {
            "cve": "GENERAL-001",
            "service": "Telnet",
            "affected_versions": ["any"],
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Telnet transmits credentials and data in plaintext. No encryption.",
            "fix": "Disable Telnet and use SSH instead.",
        },
    ],
    # SMB / Samba
    "smb": [
        {
            "cve": "CVE-2017-0144",
            "service": "SMBv1 (EternalBlue)",
            "affected_versions": ["Windows SMBv1"],
            "severity": "CRITICAL",
            "cvss": 9.3,
            "description": "Remote code execution via SMBv1 — used by WannaCry and NotPetya.",
            "fix": "Disable SMBv1; apply MS17-010 patch.",
        },
    ],
    # MongoDB (open/no-auth)
    "mongodb": [
        {
            "cve": "GENERAL-002",
            "service": "MongoDB",
            "affected_versions": ["any unauthenticated"],
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "MongoDB exposed without authentication allows full database access.",
            "fix": "Enable authentication; bind to localhost or firewall the port.",
        },
    ],
    # RDP
    "rdp": [
        {
            "cve": "CVE-2019-0708",
            "service": "RDP (BlueKeep)",
            "affected_versions": ["Windows 7, Windows Server 2008 R2 and earlier"],
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Unauthenticated RCE in Remote Desktop Services — wormable.",
            "fix": "Apply Microsoft Security Advisory KB4499175; disable RDP if not needed.",
        },
    ],
}

# Map open ports → database keys to check
PORT_TO_VULN_KEYS = {
    21:    ["vsftpd", "proftpd"],
    22:    ["openssh"],
    23:    ["telnet"],
    80:    ["apache"],
    443:   ["apache"],
    445:   ["smb"],
    3306:  ["mysql"],
    3389:  ["rdp"],
    6379:  ["redis"],
    8080:  ["apache"],
    8443:  ["apache"],
    27017: ["mongodb"],
}


def _version_in_banner(banner: str, version_str: str) -> bool:
    """Check whether a version string appears in a banner (case-insensitive)."""
    return version_str.lower() in banner.lower()


def _check_entry(banner: str, entry: dict) -> bool:
    """Return True if any affected version string matches the banner."""
    for v in entry.get("affected_versions", []):
        if _version_in_banner(banner, v):
            return True
    return False


def check_vulnerabilities(open_ports: list[dict]) -> list[dict]:
    """
    For each open port, check banners and port numbers against the CVE database.

    Args:
        open_ports : List of dicts from ports.scan_ports()

    Returns:
        List of vulnerability finding dicts.
    """
    findings = []

    for port_info in open_ports:
        port = port_info["port"]
        banner = port_info.get("banner", "")
        service = port_info.get("service", "")

        keys_to_check = PORT_TO_VULN_KEYS.get(port, [])

        # Also check if the banner itself hints at a product
        lower_banner = banner.lower()
        for key in CVE_DATABASE:
            if key not in keys_to_check and key in lower_banner:
                keys_to_check.append(key)

        for key in keys_to_check:
            entries = CVE_DATABASE.get(key, [])
            for entry in entries:
                # Match if version found in banner OR port is inherently insecure
                if _check_entry(banner, entry) or entry["affected_versions"] == ["any"]:
                    findings.append(
                        {
                            "port": port,
                            "service": service,
                            "banner": banner,
                            "cve": entry["cve"],
                            "vuln_service": entry["service"],
                            "severity": entry["severity"],
                            "cvss": entry["cvss"],
                            "description": entry["description"],
                            "fix": entry["fix"],
                        }
                    )

    # De-duplicate by (port, cve)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["port"], f["cve"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


def severity_color(severity: str) -> str:
    """Return an ANSI color code for a severity level."""
    return {
        "CRITICAL": "\033[91m",   # bright red
        "HIGH":     "\033[93m",   # yellow
        "MEDIUM":   "\033[94m",   # blue
        "LOW":      "\033[92m",   # green
        "INFO":     "\033[96m",   # cyan
    }.get(severity.upper(), "\033[0m")


RESET = "\033[0m"
BOLD  = "\033[1m"
