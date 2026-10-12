from .models import Finding
from urllib.parse import urlsplit
import ipaddress

WEIGHTS = {"info": 0, "low": 5, "medium": 12, "high": 28, "critical": 50}


def add(findings, severity, title, detail, source="analysis"):
    findings.append(Finding(severity=severity, title=title, detail=detail))


def _rep_is_flagged(rep):
    if not isinstance(rep, dict):
        return False
    # URLhaus response
    if rep.get("query_status") == "ok" and rep.get("threat"):
        return True
    # VirusTotal API v3 URL response
    attrs = rep.get("data", {}).get("attributes", {}) if isinstance(rep.get("data"), dict) else {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    if isinstance(stats, dict) and (stats.get("malicious", 0) or stats.get("suspicious", 0)):
        return True
    # Normalize explicit service status responses
    return rep.get("status") in {"malicious", "flagged", "threat_found"}


def build_findings(sender, auth, received, urls, attachments):
    findings = []
    fd, rd, rpd = sender.get("from_domain"), sender.get("reply_to_domain"), sender.get("return_path_domain")
    if fd and rd and fd != rd:
        add(findings, "medium", "From/Reply-To domain mismatch", f"From domain: {fd}; Reply-To domain: {rd}.")
    if fd and rpd and fd != rpd:
        add(findings, "low", "From/Return-Path domain mismatch", f"From domain: {fd}; Return-Path domain: {rpd}.")

    auth_results = auth.get("authentication_results_header", {})
    for name in ("spf", "dkim", "dmarc"):
        result = str(auth_results.get(name, "unknown")).lower()
        if result in {"fail", "softfail", "permerror", "temperror", "neutral"}:
            sev = "high" if name == "dmarc" and result == "fail" else "medium"
            add(findings, sev, f"{name.upper()} authentication result: {result}",
                f"The Authentication-Results header reports {name.upper()} as {result}; headers may be forged unless added by a trusted receiving system.")

    dmarc = auth.get("dmarc", {})
    if dmarc.get("record_found") and dmarc.get("authentication_result") == "pass":
        pass
    elif dmarc.get("record_found") and dmarc.get("authentication_result") == "fail":
        add(findings, "high", "DMARC reported failure", "DMARC failed according to Authentication-Results; verify this header was added by your trusted mail provider.")
    dkim = auth.get("dkim", {})
    if dkim.get("signature_present") and dkim.get("verification_status") == "failed":
        add(findings, "medium", "DKIM signature verification failed", "A DKIM signature is present but local cryptographic verification failed. Forwarding or message modification can also cause failure.")
    elif dkim.get("signature_present") and dkim.get("verification_status") == "unavailable":
        add(findings, "low", "DKIM verification unavailable", "A DKIM signature is present, but local verification could not complete; this is not a pass or a fail verdict.")

    for hop in received:
        for ip in hop.get("ips", []):
            if ip.get("scope") == "private_or_local":
                add(findings, "info", "Private/local IP in Received chain", f"Received header contains {ip.get('ip')} classified as non-public; this is common in internal mail infrastructure.")
            abuse = ip.get("abuseipdb", {})
            if abuse.get("status") == "success" and isinstance(abuse.get("abuse_confidence_score"), int) and abuse["abuse_confidence_score"] >= 75:
                add(findings, "high", "Received IP has high AbuseIPDB score", f"{ip.get('ip')} has AbuseIPDB abuse-confidence score {abuse['abuse_confidence_score']} (reports: {abuse.get('total_reports', 'unknown')}).")
            vt = ip.get("virustotal", {})
            if vt.get("status") == "success" and (vt.get("malicious", 0) >= 2 or vt.get("suspicious", 0) >= 3):
                add(findings, "high", "Received IP flagged by VirusTotal", f"{ip.get('ip')}: {vt.get('malicious', 0)} malicious and {vt.get('suspicious', 0)} suspicious detections.")

    # A single indicator is counted once across all URLs; reputation hits are stronger evidence.
    seen = set()
    for u in urls:
        for ind in u.get("indicators", []):
            key = ("url_indicator", str(ind).strip().lower())
            if key in seen: continue
            seen.add(key)
            low = str(ind).lower()
            severity = "low" if "not https" in low or "sensitive-looking keyword" in low or "unusually long" in low else "medium"
            add(findings, severity, "URL heuristic indicator", str(ind))
        if u.get("link_mismatch"):
            add(findings, "high", "Visible URL differs from destination domain", f"Visible text: {u.get('visible_text')!r}; destination: {u.get('url')!r}.")
        rep = u.get("reputation", {})
        for service, result in rep.items():
            if not isinstance(result, dict): continue
            flagged = False
            if service == "urlhaus":
                flagged = result.get("query_status") == "ok" and bool(result.get("threat"))
            elif service == "google_safe_browsing":
                flagged = bool(result.get("matches"))
            elif service == "virustotal":
                flagged = _rep_is_flagged(result)
            if flagged:
                key = ("url_rep", service, u.get("normalized_url", u.get("url", "")))
                if key not in seen:
                    seen.add(key)
                    add(findings, "critical" if service in {"urlhaus", "google_safe_browsing"} else "high",
                        f"URL flagged by {service.replace('_', ' ').title()}",
                        f"A reputation service returned a threat indicator for {u.get('normalized_url', u.get('url', 'the URL'))}.")

    for a in attachments:
        for ind in a.get("indicators", []):
            key = ("attachment_indicator", a.get("sha256", a.get("filename", "")), str(ind).lower())
            if key in seen: continue
            seen.add(key)
            low = str(ind).lower()
            sev = "high" if any(x in low for x in ("executable", "yara match", "signature despite", "dangerous archive")) else "medium"
            if "macro-enabled" in low: sev = "medium"  # Macro capability alone is not proof of maliciousness.
            add(findings, sev, "Attachment indicator", f"{a.get('filename', 'attachment')}: {ind}")
        for item in a.get("archive_analysis", {}).get("suspicious_members", []):
            add(findings, "high", "Suspicious archive content", f"{a.get('filename', 'archive')}: {item}")
        vt = a.get("virustotal", {})
        attrs = vt.get("data", {}).get("data", {}).get("attributes", {}) if isinstance(vt, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
        if isinstance(stats, dict) and stats.get("malicious", 0):
            add(findings, "critical", "Attachment hash flagged by VirusTotal", f"{a.get('filename', 'attachment')} SHA-256 {a.get('sha256', '')}: {stats.get('malicious')} malicious detections.")
    return findings


def score(findings):
    # Deduplicate identical evidence and cap the influence of repeated low-quality heuristics.
    unique = {}
    for f in findings:
        key = (f.severity.lower(), f.title, f.detail)
        unique[key] = f
    findings = list(unique.values())
    # Correlated low-quality URL heuristics should not dominate the verdict merely
    # because one message contains many links. Reputation hits and other evidence
    # retain their full weights; generic URL heuristic points are capped as a group.
    heuristic_points = sum(
        WEIGHTS.get(f.severity.lower(), 0)
        for f in findings
        if f.title == "URL heuristic indicator"
    )
    other_points = sum(
        WEIGHTS.get(f.severity.lower(), 0)
        for f in findings
        if f.title != "URL heuristic indicator"
    )
    total = other_points + min(heuristic_points, 15)
    value = min(100, total)
    if any(f.severity.lower() == "critical" for f in findings): level = "CRITICAL"
    elif value >= 40 and any(f.severity.lower() == "high" for f in findings): level = "HIGH"
    elif value >= 18: level = "MEDIUM"
    else: level = "LOW"
    return level, value


def calculate_confidence(auth, urls, attachments):
    """Confidence means evidence strength/coverage, not probability of maliciousness."""
    strong = 0
    checked = 0
    auth_results = auth.get("authentication_results_header", {}) if isinstance(auth, dict) else {}
    for key in ("spf", "dkim", "dmarc"):
        if str(auth_results.get(key, "unknown")).lower() not in {"unknown", "none", ""}:
            checked += 1
            if str(auth_results[key]).lower() in {"pass", "fail", "softfail", "permerror", "temperror"}: strong += 1
    for u in urls or []:
        rep = u.get("reputation", {}) if isinstance(u, dict) else {}
        if rep:
            checked += 1
            if any(isinstance(v, dict) and (v.get("matches") or v.get("query_status") == "ok" or v.get("status") == "ok" or v.get("data")) for v in rep.values()): strong += 1
    for a in attachments or []:
        if isinstance(a, dict):
            checked += 1
            if a.get("sha256") and a.get("detected_type") != "Unknown": strong += 1
    if strong >= 4: return "high"
    if strong >= 2: return "medium"
    if checked >= 1: return "low"
    return "unknown"
