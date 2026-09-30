from scanner.risk_predictor import RiskPredictor


def test_house_visualizer_reports_core_findings():
    results = {
        "headers": {"missing": [{"header": "Strict-Transport-Security"}, {"header": "Content-Security-Policy"}]},
        "ssl": {"has_valid_cert": False},
        "directory_listing_enabled": True,
        "open_ports": [{"port": 22}, {"port": 3389}],
    }

    visual = RiskPredictor.build_house_visualizer(results)

    assert "DOOR" in visual.upper()
    assert "WINDOW" in visual.upper()
    assert "CABINETS" in visual.upper()


def test_armor_script_includes_required_security_headers():
    results = {
        "headers": {"missing": [{"header": "Strict-Transport-Security"}, {"header": "Content-Security-Policy"}]},
        "directory_listing_enabled": True,
    }

    script = RiskPredictor.generate_armor_script(results, server="apache")

    assert "Strict-Transport-Security" in script
    assert "Content-Security-Policy" in script
    assert "Options -Indexes" in script
