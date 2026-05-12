# 🔍 Simple Vulnerability Scanner

A Python-based educational vulnerability scanner demonstrating the **Scanning Phase of Ethical Hacking**.

> ⚠️ **Legal Notice:** Only scan systems you own or have **written permission** to test.  
> Unauthorised scanning is illegal and unethical.

---

## 📂 Project Structure

```
simple-vulnerability-scanner/
│
├── scanner.py          ← Main entry point (run this)
├── ports.py            ← Port scanning & banner grabbing
├── vulnerabilities.py  ← CVE database & matching logic
├── report.py           ← TXT / CSV / JSON report generation
├── requirements.txt    ← No external dependencies needed
└── results/            ← Scan reports are saved here
```

---

## ⚙️ Requirements

- **Python 3.10 or higher**
- No external packages needed (uses standard library only)

---

## 🚀 How to Run

### Option 1 — Interactive Menu (easiest)
```bash
python scanner.py
```
You will be prompted to enter:
- Target IP or hostname
- Port scan mode (common / range / specific)
- Whether to save reports

### Option 2 — Command Line

**Scan common ports:**
```bash
python scanner.py -t 192.168.1.1
```

**Scan a port range:**
```bash
python scanner.py -t 192.168.1.1 -p 1-1024
```

**Scan specific ports:**
```bash
python scanner.py -t 192.168.1.1 --ports 22,80,443,3306
```

**Verbose output + skip saving report:**
```bash
python scanner.py -t 192.168.1.1 --verbose --no-report
```

**Scan a hostname:**
```bash
python scanner.py -t scanme.nmap.org
```
> `scanme.nmap.org` is a legal, authorised target provided by the Nmap team for testing.

---

## 📋 All CLI Options

| Flag | Description |
|---|---|
| `-t`, `--target` | Target IP or hostname (required) |
| `-p`, `--range` | Port range, e.g. `1-1024` |
| `--ports` | Specific ports, e.g. `22,80,443` |
| `--timeout` | Seconds per port (default `1.0`) |
| `--threads` | Worker threads (default `100`) |
| `-v`, `--verbose` | Print each open port live as found |
| `--no-report` | Skip saving reports to `results/` |

---

## 📤 Output Example

```
  Target: 192.168.1.1
  Resolved → 192.168.1.1
  Scanning … done (3.21s)

  Open Ports
  ──────────────────────────────────────────────────────
  [+] Port    22  SSH             OpenSSH 7.9
  [+] Port    80  HTTP            Apache/2.4.49
  [+] Port   443  HTTPS

  Vulnerability Analysis
  ──────────────────────────────────────────────────────
  [CRITICAL] CVE-2021-41773
       Port     : 80  (HTTP)
       Service  : Apache HTTP Server
       CVSS     : 9.8
       Info     : Path traversal and RCE via mod_cgi.
       Fix      : Upgrade to Apache 2.4.50 or later.

  Reports Saved
  ──────────────────────────────────────────────────────
  [TXT]   results/scan_192_168_1_1_20250112_143021.txt
  [CSV]   results/scan_192_168_1_1_20250512_143021.csv
  [JSON]  results/scan_192_168_1_1_20250512_143021.json
```

---

## 🧠 How It Works

1. **Resolve target** — hostname → IP via `socket.gethostbyname()`
2. **Port scan** — TCP `connect_ex()` across all target ports using a thread pool
3. **Banner grabbing** — send a small probe, read the first response line
4. **Vulnerability matching** — compare banners against a local CVE database
5. **Report generation** — write results to TXT, CSV, and JSON in `results/`

---

## 📚 CVEs in the Local Database

| CVE | Service | Severity |
|---|---|---|
| CVE-2021-41773 | Apache 2.4.49 | CRITICAL |
| CVE-2021-42013 | Apache 2.4.50 | CRITICAL |
| CVE-2024-6387 (regreSSHion) | OpenSSH < 9.8p1 | CRITICAL |
| CVE-2023-38408 | OpenSSH < 9.3p2 | CRITICAL |
| CVE-2011-2523 | vsftpd 2.3.4 backdoor | CRITICAL |
| CVE-2017-0144 (EternalBlue) | SMBv1 | CRITICAL |
| CVE-2019-0708 (BlueKeep) | RDP | CRITICAL |
| CVE-2022-0543 | Redis | CRITICAL |
| CVE-2019-12815 | ProFTPD | CRITICAL |
| CVE-2021-2154 | MySQL | HIGH |
| GENERAL-001 | Telnet (plaintext) | HIGH |
| GENERAL-002 | Unauthenticated MongoDB | HIGH |

---

## 🔒 Ethical Use

This tool is for **learning and authorised security testing only**.  
Always obtain written permission before scanning any network or system.
