"""
Network scanning engine: host discovery + TCP port scanning.

This is a defensive/audit tool — it only performs standard TCP connect
attempts and banner reads. Only ever point it at hosts you own or have
explicit permission to test; scanning systems without authorization can
be illegal in many jurisdictions.
"""
import socket
import subprocess
import platform
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import config


def resolve_target(target: str) -> str:
    """Accepts a hostname or IP and returns the resolved IP address."""
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host '{target}': {exc}")


def is_host_up(ip: str, timeout: float = 1.5) -> bool:
    """
    Cross-platform 'is this host alive' check.
    Tries the OS ping utility first (ICMP), falls back to a TCP connect
    attempt on a couple of common ports if ping is blocked/unavailable.
    """
    system = platform.system().lower()
    count_flag = "-n" if system == "windows" else "-c"
    timeout_flag = "-w" if system == "windows" else "-W"
    timeout_val = str(int(timeout * 1000)) if system == "windows" else str(int(timeout))

    try:
        result = subprocess.run(
            ["ping", count_flag, "1", timeout_flag, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass  # fall through to TCP probe

    for port in (80, 443, 22):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            continue
    return False


def _grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.send(b"\r\n")
            except OSError:
                pass
            data = s.recv(128)
            return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def _scan_one_port(ip: str, port: int, timeout: float, grab_banners: bool):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            banner = _grab_banner(ip, port) if grab_banners else ""
            return {"port": port, "state": "open", "service": service, "banner": banner}
    return None


def scan_ports(ip: str, ports: list, max_threads: int = 100, timeout: float = 0.6, grab_banners: bool = True):
    """
    Scans the given list of ports concurrently.
    Returns a list of dicts for OPEN ports only: {port, state, service, banner}
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_scan_one_port, ip, p, timeout, grab_banners): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda r: r["port"])
    return open_ports


def run_full_scan(target: str, plan_limits: dict, custom_port_range=None) -> dict:
    """
    High-level entry point used by the GUI. Respects the caller's plan
    limits (max_port / thread count) so free-tier users automatically get
    a smaller, slower scan.
    """
    start = time.time()
    ip = resolve_target(target)
    host_up = is_host_up(ip)

    if custom_port_range:
        ports_to_scan = [p for p in custom_port_range if p <= plan_limits["max_port"]]
    else:
        ports_to_scan = [p for p in config.COMMON_PORTS_TOP_100 if p <= plan_limits["max_port"]]

    open_ports = []
    if host_up:
        open_ports = scan_ports(
            ip, ports_to_scan, max_threads=plan_limits["port_scan_threads"]
        )

    duration = round(time.time() - start, 2)
    return {
        "target": target,
        "resolved_ip": ip,
        "host_up": host_up,
        "ports_scanned": len(ports_to_scan),
        "open_ports": open_ports,
        "duration_seconds": duration,
    }
