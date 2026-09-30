import unittest
from unittest.mock import patch

from scanner.email_trust_scanner import EmailTrustScanner
from scanner.third_party_script_scanner import scan_third_party_scripts


class EmailTrustScannerTests(unittest.TestCase):
    def test_scan_domain_detects_spf_and_dmarc(self):
        scanner = EmailTrustScanner(timeout=2)

        with patch.object(scanner, "_query_txt_records", side_effect=[
            ["v=spf1 include:_spf.example.com ~all"],
            ["v=dmarc1; p=reject; rua=mailto:dmarc@example.com"],
        ]):
            result = scanner.scan_domain("example.com")

        self.assertTrue(result["spf_record"])
        self.assertTrue(result["dmarc_record"])
        self.assertEqual(result["status"], "ok")


class ThirdPartyScriptScannerTests(unittest.TestCase):
    def test_scan_finds_external_scripts(self):
        class FakeResponse:
            text = """
            <html><head>
                <script src="https://cdn.example.net/lib.js"></script>
                <script src="/static/site.js"></script>
                <script src="https://www.googletagmanager.com/gtm.js"></script>
            </head></html>
            """

            def raise_for_status(self):
                pass

        with patch("scanner.third_party_script_scanner.requests.get", return_value=FakeResponse()):
            result = scan_third_party_scripts("https://example.com")

        self.assertEqual(result["third_party_count"], 2)
        self.assertEqual(len(result["third_party_scripts"]), 2)
        self.assertTrue(any(item["domain"] == "cdn.example.net" for item in result["third_party_scripts"]))


if __name__ == "__main__":
    unittest.main()
