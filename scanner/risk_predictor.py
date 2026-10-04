"""Explainable risk scoring backed by the FIRST EPSS service."""
import asyncio
from typing import Any, Dict, List, Mapping, Sequence, Tuple

import aiohttp


class RiskPredictor:
    """Calculate a capped 0-100 hackability score for one target."""

    EPSS_URL = "https://api.first.org/data/v1/epss"
    HIGH_RISK_PORTS = frozenset({21, 22, 23, 445, 3389})
    CRITICAL_HEADERS = frozenset({"strict-transport-security", "content-security-policy"})

    def __init__(self, timeout_seconds: float = 8.0) -> None:
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _coerce_header_names(results: Mapping[str, Any]) -> List[str]:
        headers = results.get("headers", {}) if isinstance(results, Mapping) else {}
        missing = headers.get("missing", []) if isinstance(headers, Mapping) else []
        names = []
        for item in missing:
            if isinstance(item, Mapping):
                header = item.get("header")
            else:
                header = item
            names.append(str(header).strip())
        return [name for name in names if name]

    @staticmethod
    def build_house_visualizer(results: Mapping[str, Any]) -> str:
        """Translate the real audit findings into a simple house analogy."""
        if not isinstance(results, Mapping):
            return "House status unavailable."

        ssl_issue = bool(results.get("ssl") and not results.get("ssl", {}).get("has_valid_cert"))
        directory_listing = bool(results.get("directory_listing_enabled"))
        open_ports = [int(item.get("port")) for item in results.get("open_ports", []) if isinstance(item, Mapping) and item.get("port") is not None]
        risky_ports = [port for port in open_ports if port in RiskPredictor.HIGH_RISK_PORTS]
        missing_headers = RiskPredictor._coerce_header_names(results)
        cookie_issues = results.get("cookie_issues") or []
        exposed_paths = results.get("exposed_paths") or []

        door_text = "🚪 Door Unlocked\n(Missing SSL Certificate)" if ssl_issue else "🚪 Door Locked\n(Valid SSL)"
        window_text = f"🔓 Window Open\n({len(risky_ports)} risky port(s))" if risky_ports else "🔒 Window Locked\n(Ports Secured)"
        dir_text = "📂 Blinds Open\n(Directory Listing)" if directory_listing else "🪟 Blinds Closed\n(Files Hidden)"
        roof_text = f"🏚 Roof Leak\n(Missing: {', '.join(missing_headers[:2])})" if missing_headers else "🏠 Roof Secure\n(All headers present)"

        lines = [
            "Digital House Visualizer",
            "",
            "🏠 Server: " + str(results.get("target", "example.com")),
            "",
            window_text,
            dir_text,
            door_text,
            roof_text,
            "",
            "Security Translation:",
        ]

        if ssl_issue:
            lines.append("⚠️ The front door is unlocked. Anyone can intercept the data going in and out of your website.")
        if risky_ports:
            lines.append(f"⚠️ A ground-floor window is open on port(s) {', '.join(str(p) for p in risky_ports)}. Attackers can reach the server directly.")
        if directory_listing:
            lines.append("⚠️ Your filing cabinets are visible to the public. Internal files, folders, and backups are exposed.")
        if missing_headers:
            lines.append(f"⚠️ The roof has holes: {', '.join(missing_headers[:3])}. These missing protections leave the house open to XSS, downgrade attacks, and browser abuse.")
        if cookie_issues:
            lines.append("⚠️ Window locks are weak. Some cookies are missing Secure and HttpOnly protections.")
        if exposed_paths:
            lines.append(f"⚠️ Sensitive rooms are left open: {', '.join(path.get('path', '') for path in exposed_paths[:3])}.")
        if not any((ssl_issue, risky_ports, directory_listing, missing_headers, cookie_issues, exposed_paths)):
            lines.append("✅ Your digital house is fully secured. All entry points are locked and protected.")

        return "\n".join(lines)

    @staticmethod
    def generate_armor_script(results: Mapping[str, Any], server: str = "apache") -> str:
        """Generate a simple web server config for common missing security protections."""
        headers = RiskPredictor._coerce_header_names(results)
        header_map = {
            "Strict-Transport-Security": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
            "Content-Security-Policy": "Header always set Content-Security-Policy \"default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; upgrade-insecure-requests\"",
            "X-Content-Type-Options": "Header always set X-Content-Type-Options \"nosniff\"",
            "X-Frame-Options": "Header always set X-Frame-Options \"DENY\"",
            "Referrer-Policy": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            "Permissions-Policy": "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
        }
        missing = [header for header in header_map if header in headers]
        if server.lower() == "iis":
            config_lines = [
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<configuration>",
                "  <system.webServer>",
                "    <httpProtocol>",
                "      <customHeaders>",
            ]
            for header in header_map:
                if header in missing:
                    config_lines.append(f"        <add name=\"{header}\" value=\"{header_map[header].split(' ', 3)[3].strip().strip('\\\"')}\" />")
            config_lines += [
                "      </customHeaders>",
                "    </httpProtocol>",
                "    <rewrite>",
                "      <rules>",
                "        <rule name=\"RedirectToHttps\" stopProcessing=\"true\">",
                "          <match url=\".*\" />",
                "          <conditions logicalGrouping=\"MatchAll\">",
                "            <add input=\"{HTTPS}\" pattern=\"^OFF$\" />",
                "          </conditions>",
                "          <action type=\"Redirect\" url=\"https://{HTTP_HOST}{REQUEST_URI}\" redirectType=\"Permanent\" />",
                "        </rule>",
                "      </rules>",
                "    </rewrite>",
                "  </system.webServer>",
                "</configuration>",
            ]
            if results.get("directory_listing_enabled"):
                config_lines.insert(-2, "    <staticContent>\n      <mimeMap fileExtension=\".php\" mimeType=\"text/x-php\" />\n    </staticContent>")
            return "\n".join(config_lines)

        lines = [
            "# .htaccess generated by Glitch Hound",
            "<IfModule mod_headers.c>",
        ]
        for header in header_map:
            if header in missing:
                lines.append(f"    {header_map[header]}")
        lines += [
            "</IfModule>",
            "",
            "RewriteEngine On",
            "RewriteCond %{HTTPS} !=on",
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
            "",
        ]
        if results.get("directory_listing_enabled"):
            lines.extend([
                "Options -Indexes",
                "<FilesMatch \"^\\.\">",
                "    Require all denied",
                "</FilesMatch>",
            ])
        return "\n".join(lines)

    @staticmethod
    def historical_summary(scan_records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        """Estimate future website risk from previously completed audits.

        This is a frequency baseline, not a machine-learning model. It uses
        C/D/F grades as the at-risk definition and ranks findings by how often
        they appeared across historical website audits.
        """
        website_scans = [scan for scan in scan_records if scan.get("scan_type") == "vuln_scan"]
        issue_counts: Dict[str, int] = {}
        at_risk_count = 0
        for scan in website_scans:
            results = scan.get("results", {})
            if results.get("grade") in {"C", "D", "F"}:
                at_risk_count += 1

            for missing in results.get("headers", {}).get("missing", []):
                name = missing.get("header", str(missing)) if isinstance(missing, Mapping) else str(missing)
                issue_counts[f"Missing {name}"] = issue_counts.get(f"Missing {name}", 0) + 1
            if results.get("cookie_issues"):
                issue_counts["Cookie security flags"] = issue_counts.get("Cookie security flags", 0) + 1
            if results.get("exposed_paths"):
                issue_counts["Exposed sensitive paths"] = issue_counts.get("Exposed sensitive paths", 0) + 1
            if results.get("directory_listing_enabled"):
                issue_counts["Directory listing"] = issue_counts.get("Directory listing", 0) + 1
            if results.get("banner", {}).get("discloses_version"):
                issue_counts["Software version disclosure"] = issue_counts.get("Software version disclosure", 0) + 1

        audit_count = len(website_scans)
        risk_rate = (at_risk_count / audit_count * 100) if audit_count else 0.0
        common_issues = [
            {"issue": issue, "occurrences": count, "frequency_pct": round(count / audit_count * 100, 1)}
            for issue, count in sorted(issue_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ] if audit_count else []
        return {
            "website_audits": audit_count,
            "at_risk_websites": at_risk_count,
            "at_risk_rate_pct": round(risk_rate, 1),
            "next_site_baseline": "At Risk" if risk_rate >= 50 else "Lower Risk",
            "common_issues": common_issues,
        }

    async def _fetch_epss(self, session: aiohttp.ClientSession, cve_id: str) -> Tuple[str, float, str]:
        try:
            async with session.get(
                self.EPSS_URL,
                params={"cve": cve_id},
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
            ) as response:
                response.raise_for_status()
                payload = await response.json()
                records = payload.get("data", [])
                epss = float(records[0].get("epss", 0.0)) if records else 0.0
                return cve_id, max(0.0, min(1.0, epss)), ""
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError, KeyError) as exc:
            return cve_id, 0.0, f"{cve_id}: {exc}"

    async def predict(
        self,
        cve_list: Sequence[Mapping[str, Any]],
        open_ports: Sequence[int],
        missing_headers: Sequence[str],
    ) -> Dict[str, Any]:
        """Fetch EPSS values concurrently and return an explainable score."""
        cves = [cve for cve in cve_list if cve.get("id")]
        connector = aiohttp.TCPConnector(limit=max(1, len(cves)))
        async with aiohttp.ClientSession(connector=connector) as session:
            epss_results = await asyncio.gather(
                *(self._fetch_epss(session, str(cve["id"]).strip()) for cve in cves)
            )

        errors: List[str] = []
        cve_points = 0.0
        for cve, (_, epss, error) in zip(cves, epss_results):
            if error:
                errors.append(error)
            try:
                cvss = max(0.0, min(10.0, float(cve.get("cvss", 0.0))))
            except (TypeError, ValueError):
                cvss = 0.0
                errors.append(f"{cve.get('id')}: invalid CVSS value")
            cve_points += cvss * epss * 10.0

        port_points = 15.0 if any(port in self.HIGH_RISK_PORTS for port in open_ports) else 0.0
        headers = {str(header).strip().lower() for header in missing_headers}
        header_points = 10.0 if headers & self.CRITICAL_HEADERS else 0.0
        total_score = min(100.0, cve_points + port_points + header_points)
        severity = (
            "Low" if total_score < 30 else
            "Moderate" if total_score < 60 else
            "High" if total_score < 80 else "Critical"
        )
        result: Dict[str, Any] = {
            "total_score": round(total_score, 2),
            "risk_severity": severity,
            "breakdown": {
                "cves": round(cve_points, 2),
                "ports": port_points,
                "headers": header_points,
            },
        }
        if errors:
            result["errors"] = errors
        return result


async def _main() -> None:
    result = await RiskPredictor().predict(
        cve_list=[{"id": "CVE-2021-44228", "cvss": 10.0}],
        open_ports=[443, 3389],
        missing_headers=["Strict-Transport-Security"],
    )
    print(result)


if __name__ == "__main__":
    asyncio.run(_main())