"""Check for third-party script dependencies on a website."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse

import requests


def scan_third_party_scripts(url: str, timeout: int = 8) -> Dict[str, Any]:
    """Find external scripts loaded from domains other than the page itself."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return {
            "target_url": url,
            "status": "error",
            "error": "Third-party script scanning requires beautifulsoup4. Install the project requirements first.",
            "script_count": 0,
            "third_party_count": 0,
            "third_party_scripts": [],
            "risk_level": "unknown",
        }

    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "GlitchHoundApp/1.0"})
        response.raise_for_status()
    except requests.RequestException as exc:
        return {
            "target_url": url,
            "status": "error",
            "error": f"Request failed: {exc}",
            "script_count": 0,
            "third_party_count": 0,
            "third_party_scripts": [],
            "risk_level": "unknown",
        }

    soup = BeautifulSoup(response.text, "html.parser")
    parsed_url = urlparse(url)
    page_host = (parsed_url.netloc or "").lower()

    third_party: List[Dict[str, str]] = []
    seen = set()
    scripts = soup.find_all("script", src=True)

    for tag in scripts:
        src = (tag.get("src") or "").strip()
        if not src:
            continue
        parsed_src = urlparse(src)
        if not parsed_src.scheme and not parsed_src.netloc:
            continue
        src_host = (parsed_src.netloc or page_host).lower()
        if src_host == page_host:
            continue
        if src in seen:
            continue
        seen.add(src)
        third_party.append({
            "src": src,
            "domain": src_host,
            "source": "external-script",
        })

    if not third_party:
        risk = "low"
    elif len(third_party) <= 3:
        risk = "medium"
    else:
        risk = "high"

    return {
        "target_url": url,
        "status": "ok",
        "error": None,
        "script_count": len(scripts),
        "third_party_count": len(third_party),
        "third_party_scripts": third_party,
        "risk_level": risk,
    }
