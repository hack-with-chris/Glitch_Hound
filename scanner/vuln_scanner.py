"""
Website security audit engine.

Performs PASSIVE reconnaissance only — it reads what a server voluntarily
exposes (headers, certificate info, well-known file presence, cookie flags).
It never attempts to inject payloads, brute-force credentials, or actively
exploit anything. Only run this against sites you own or are authorized to
test.
"""
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from scanner.email_trust_scanner import EmailTrustScanner

REQUEST_TIMEOUT = 6
USER_AGENT = "GlitchHoundApp/1.0 (+security-audit-tool)"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against protocol downgrade / cookie hijacking (HSTS).",
    "Content-Security-Policy": "Mitigates XSS and data-injection attacks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Mitigates clickjacking.",
    "Referrer-Policy": "Controls how much referrer info is leaked.",
    "Permissions-Policy": "Restricts which browser features the page may use.",
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/backup.zip",
    "/.well-known/security.txt",
    "/server-status",
    "/phpinfo.php",
    "/admin",
]


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _check_headers(headers) -> dict:
    present, missing = [], []
    for name, explanation in SECURITY_HEADERS.items():
        if name in headers:
            present.append(name)
        else:
            missing.append({"header": name, "why_it_matters": explanation})
    return {"present": present, "missing": missing}


def _check_ssl(hostname: str) -> dict:
    info = {"has_valid_cert": False, "issuer": None, "expires": None, "days_until_expiry": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        expires_str = cert.get("notAfter")
        expires_dt = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires_dt - datetime.now(timezone.utc)).days

        info.update(
            has_valid_cert=True,
            issuer=issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            expires=expires_dt.strftime("%Y-%m-%d"),
            days_until_expiry=days_left,
        )
    except Exception as exc:
        info["error"] = str(exc)
    return info


def _check_cookies(response) -> list:
    findings = []
    for cookie in response.cookies:
        flags_missing = []
        if not cookie.secure:
            flags_missing.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
            flags_missing.append("HttpOnly")
        if flags_missing:
            findings.append({"cookie": cookie.name, "missing_flags": flags_missing})
    return findings


def _check_sensitive_paths(base_url: str) -> list:
    exposed = []
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(
                base_url + path, timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT}, allow_redirects=False,
            )
            if r.status_code == 200:
                exposed.append({"path": path, "status_code": r.status_code})
        except requests.RequestException:
            continue
    return exposed


def _check_directory_listing(response) -> bool:
    body_snippet = response.text[:2000].lower() if response.text else ""
    return "index of /" in body_snippet


def _check_banner(headers) -> dict:
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    discloses_version = any(char.isdigit() for char in server) or any(char.isdigit() for char in powered_by)
    return {"server_header": server or None, "x_powered_by": powered_by or None, "discloses_version": discloses_version}


def _grade(findings: dict) -> str:
    score = 100
    score -= len(findings.get("headers", {}).get("missing", [])) * 8
    if not findings.get("ssl", {}).get("has_valid_cert"):
        score -= 25
    elif (findings.get("ssl", {}).get("days_until_expiry") or 999) < 14:
        score -= 10
    score -= len(findings.get("exposed_paths", [])) * 15
    score -= len(findings.get("cookie_issues", [])) * 5
    if findings.get("directory_listing_enabled"):
        score -= 15
    if findings.get("banner", {}).get("discloses_version"):
        score -= 5

    score = max(0, min(100, score))
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def run_audit(url: str, enabled_checks: list) -> dict:
    """
    enabled_checks controls plan-based feature gating, e.g. free plan
    passes ["headers", "ssl"] while pro passes the full list.
    """
    start = time.time()
    url = _normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.netloc

    findings = {"target": url, "hostname": hostname}

    try:
        response = requests.get(
            url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True
        )
    except requests.RequestException as exc:
        findings["error"] = f"Could not reach {url}: {exc}"
        findings["duration_seconds"] = round(time.time() - start, 2)
        return findings

    findings["status_code"] = response.status_code
    findings["final_url"] = response.url

    if "headers" in enabled_checks:
        findings["headers"] = _check_headers(response.headers)
        findings["banner"] = _check_banner(response.headers)

    if "ssl" in enabled_checks and parsed.scheme == "https":
        findings["ssl"] = _check_ssl(hostname)

    if "email_trust" in enabled_checks:
        findings["email_trust"] = EmailTrustScanner().scan_domain(hostname)

    if "cookies" in enabled_checks:
        findings["cookie_issues"] = _check_cookies(response)

    if "exposed_paths" in enabled_checks:
        base = f"{parsed.scheme}://{hostname}"
        findings["exposed_paths"] = _check_sensitive_paths(base)

    if "directory_listing" in enabled_checks:
        findings["directory_listing_enabled"] = _check_directory_listing(response)

    findings["grade"] = _grade(findings)
    findings["duration_seconds"] = round(time.time() - start, 2)
    return findings
