"""
ports.py — Port Scanner Module
Simple Vulnerability Scanner | Educational Use Only
"""

import socket
import concurrent.futures
from datetime import datetime

# Common ports and their service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve target '{target}': {e}")


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Attempt a TCP connection to a single port.
    Returns a result dict if open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = grab_banner(ip, port, timeout)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
    except (socket.error, OSError):
        pass
    return None


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to grab a service banner from an open port.
    Sends a generic probe and reads the response.
    """
    banner = ""
    probes = {
        21: b"",           # FTP sends banner on connect
        22: b"",           # SSH sends banner on connect
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
        443: b"",
        25: b"",
        110: b"",
        143: b"",
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            probe = probes.get(port, b"\r\n")
            if probe:
                sock.send(probe)
            raw = sock.recv(1024)
            banner = raw.decode("utf-8", errors="ignore").strip()
            # Keep only the first meaningful line
            banner = banner.split("\n")[0].strip()[:120]
    except Exception:
        pass
    return banner


def scan_ports(
    ip: str,
    ports: list[int] | None = None,
    port_range: tuple[int, int] | None = None,
    max_workers: int = 100,
    timeout: float = 1.0,
    callback=None,
) -> list[dict]:
    """
    Scan multiple ports using a thread pool.

    Args:
        ip           : Target IP address
        ports        : Explicit list of ports to scan
        port_range   : (start, end) range of ports to scan
        max_workers  : Thread pool size
        timeout      : Per-port connection timeout in seconds
        callback     : Optional callable(port, result) for live updates

    Returns:
        List of open-port result dicts, sorted by port number.
    """
    if ports is None:
        if port_range:
            start, end = port_range
            ports = list(range(start, end + 1))
        else:
            ports = list(COMMON_PORTS.keys())

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                if callback:
                    callback(port, result)
            except Exception:
                pass

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def quick_scan(target: str) -> dict:
    """
    Convenience function: resolve target and scan common ports.
    Returns a full scan info dict.
    """
    ip = resolve_target(target)
    start_time = datetime.now()
    open_ports = scan_ports(ip, ports=list(COMMON_PORTS.keys()))
    end_time = datetime.now()

    return {
        "target": target,
        "ip": ip,
        "scan_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "open_ports": open_ports,
        "total_open": len(open_ports),
    }
