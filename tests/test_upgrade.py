import hashlib
import sys
import types

# Lightweight import stubs allow pure-logic tests to run in minimal CI images.
# Real integrations are still exercised when the declared requirements are installed.
if "dkim" not in sys.modules:
    dkim_stub = types.ModuleType("dkim")
    dkim_stub.verify = lambda raw: False
    sys.modules["dkim"] = dkim_stub
if "tldextract" not in sys.modules:
    tld_stub = types.ModuleType("tldextract")
    class _Extracted:
        domain = "example"
        suffix = "com"
    tld_stub.extract = lambda host: _Extracted()
    sys.modules["tldextract"] = tld_stub

from app.auth import evaluate_dmarc_alignment
from app.attachments import analyze_attachment
from app.urls import analyze_url, normalize_url, indicators


def test_normalize_url_drops_fragment_and_default_port():
    assert normalize_url("HTTPS://Example.COM:443/path#fragment") == "https://example.com/path"


def test_private_ip_literal_is_reported_without_fetching():
    found = indicators("http://192.168.1.10/login")
    assert any("private or reserved" in item.lower() for item in found)


def test_malformed_url_does_not_trigger_reputation_lookup():
    result = analyze_url("javascript:alert(1)")
    assert result["reputation"]["status"] == "not_checked"
    assert "Malformed or unsupported URL" in result["indicators"]


def test_dmarc_alignment_is_explicitly_exact_domain_only():
    result = evaluate_dmarc_alignment({}, "mail.example.com", "example.com", "example.com")
    assert result["alignment_mode"] == "exact_domain_only"
    assert "not a complete DMARC evaluation" in result["alignment_note"]
    assert result["spf_alignment"] is False


def test_oversized_attachment_skips_deep_analysis(monkeypatch):
    monkeypatch.setenv("MAX_ATTACHMENT_ANALYSIS_MB", "1")
    data = b"MZ" + (b"x" * (1024 * 1024))
    item = {"filename": "invoice.txt", "data": data, "mime_type": "text/plain",
            "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    result = analyze_attachment(item)
    assert result["detected_type"] == "PE/executable"
    assert result["document_analysis"]["reason"] == "size_limit"
    assert any("size limit" in x.lower() for x in result["indicators"])
