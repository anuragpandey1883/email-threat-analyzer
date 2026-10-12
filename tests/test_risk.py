from app.risk import score, build_findings, calculate_confidence
from app.models import Finding


def test_score_deduplicates_identical_findings():
    f = Finding(severity="medium", title="Same", detail="same evidence")
    assert score([f, f]) == ("LOW", 12)


def test_private_received_ip_is_informational():
    findings = build_findings({}, {}, [{"ips": [{"ip": "192.168.1.1", "scope": "private_or_local"}]}], [], [])
    assert findings[0].severity == "info"


def test_unknown_coverage_is_not_high_confidence():
    assert calculate_confidence({}, [], []) == "unknown"


def test_link_mismatch_is_high_severity():
    findings = build_findings({}, {}, [], [{"url": "https://evil.example", "visible_text": "https://bank.example", "link_mismatch": True}], [])
    assert any(f.severity == "high" and "Visible URL" in f.title for f in findings)


def test_critical_reputation_evidence_escalates():
    findings = build_findings({}, {}, [], [{
        "url": "https://bad.example/a", "normalized_url": "https://bad.example/a",
        "indicators": [], "link_mismatch": False,
        "reputation": {"urlhaus": {"query_status": "ok", "threat": "malware_download"}},
    }], [])
    assert score(findings)[0] == "CRITICAL"



def test_repeated_generic_url_heuristics_are_capped():
    findings = [
        Finding(severity="medium", title="URL heuristic indicator", detail=f"heuristic {i}")
        for i in range(5)
    ]
    assert score(findings) == ("LOW", 15)


def test_strong_reputation_evidence_is_not_hidden_by_heuristic_cap():
    findings = [
        Finding(severity="medium", title="URL heuristic indicator", detail=f"heuristic {i}")
        for i in range(5)
    ]
    findings.append(Finding(severity="critical", title="URL flagged", detail="reputation match"))
    assert score(findings)[0] == "CRITICAL"


def test_critical_reputation_evidence_is_not_hidden_by_heuristic_cap():
    findings = [
        Finding(severity="medium", title="URL heuristic indicator", detail=f"heuristic {i}")
        for i in range(5)
    ]
    findings.append(Finding(severity="critical", title="URL flagged", detail="reputation match"))
    assert score(findings)[0] == "CRITICAL"


def test_url_ip_literal_and_nonstandard_port_indicators(monkeypatch):
    import sys, types
    # The indicators helper itself does not need tldextract; stub that optional
    # module for this focused unit test when project dependencies are not installed.
    monkeypatch.setitem(sys.modules, "tldextract", types.ModuleType("tldextract"))
    from app.urls import indicators
    found = indicators("http://192.168.1.10:8081/login")
    assert "URL uses an IP address instead of a domain name" in found
    assert "URL points to a private or reserved IP address" in found
    assert "URL uses a non-standard port (8081)" in found
