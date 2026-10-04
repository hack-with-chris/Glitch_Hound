"""Email trust checks for SPF and DMARC DNS records."""

from __future__ import annotations

from typing import Any, Dict, List

try:
    import dns.exception
    import dns.resolver
except ImportError:
    dns = None


class EmailTrustScanner:
    """Fast DNS-based email trust audit for a domain."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = max(0.5, float(timeout))

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        value = (domain or "").strip().lower().rstrip(".")
        if not value:
            raise ValueError("Domain is required.")
        if value.startswith("http://") or value.startswith("https://"):
            value = value.split("//", 1)[1].split("/", 1)[0]
        return value

    def _query_txt_records(self, domain: str) -> List[str]:
        if dns is None:
            raise RuntimeError("DNS email trust scanning requires dnspython. Install the project requirements first.")
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        answers = resolver.resolve(domain, "TXT")
        values: List[str] = []
        for record in answers:
            text_values = getattr(record, "strings", [])
            if not text_values:
                values.append(str(record))
            else:
                values.extend(str(item.decode("utf-8", errors="ignore")) if isinstance(item, bytes) else str(item) for item in text_values)
        return values

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Return SPF/DMARC existence and reliability information for a domain."""
        try:
            normalized = self._normalize_domain(domain)
        except ValueError as exc:
            return {
                "domain": domain,
                "status": "error",
                "error": str(exc),
                "spf_record": False,
                "dmarc_record": False,
            }

        try:
            spf_values = self._query_txt_records(normalized)
            spf_found = any(value.lower().startswith("v=spf1") for value in spf_values)

            dmarc_values = self._query_txt_records(f"_dmarc.{normalized}")
            dmarc_found = any(value.lower().startswith("v=dmarc1") for value in dmarc_values)

            return {
                "domain": normalized,
                "status": "ok",
                "error": None,
                "spf_record": spf_found,
                "dmarc_record": dmarc_found,
                "spf_details": spf_values[:3] if spf_values else [],
                "dmarc_details": dmarc_values[:3] if dmarc_values else [],
            }
        except RuntimeError as exc:
            return {
                "domain": normalized,
                "status": "error",
                "error": str(exc),
                "spf_record": False,
                "dmarc_record": False,
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException) as exc:
            return {
                "domain": normalized,
                "status": "error",
                "error": f"DNS lookup failed: {exc}",
                "spf_record": False,
                "dmarc_record": False,
            }
