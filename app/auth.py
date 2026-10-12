import re
import dns.resolver
import dkim
from .parser import parse_authentication_results

def txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=3)
        return ["".join(part.decode() if isinstance(part, bytes) else part for part in r.strings) for r in answers]
    except Exception:
        return []

def spf_record(domain):
    records = txt_records(domain)
    return next((r for r in records if r.lower().startswith("v=spf1")), None)

def dmarc_record(domain):
    records = txt_records(f"_dmarc.{domain}")
    return next((r for r in records if r.lower().startswith("v=dmarc1")), None)

def dkim_signature_info(msg):
    value = msg.get("DKIM-Signature")
    if not value:
        return {"signature_present": False, "domain": None, "selector": None}
    d = re.search(r"\bd=([^;\s]+)", value, re.I)
    s = re.search(r"\bs=([^;\s]+)", value, re.I)
    return {"signature_present": True, "domain": d.group(1).lower() if d else None, "selector": s.group(1) if s else None}

def verify_dkim(raw: bytes):
    try:
        return {"status": "verified" if dkim.verify(raw) else "failed", "error": None}
    except Exception as exc:
        return {"status": "unavailable", "error": type(exc).__name__}

def parse_spf_mechanisms(record):
    if not record:
        return []
    return record.split()[1:]

def dmarc_tags(record):
    tags = {}
    if not record:
        return tags
    for part in record.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            tags[k.lower()] = v.strip()
    return tags

def evaluate_dmarc_alignment(auth_results, from_domain, dkim_domain, return_path_domain):
    dmarc_result = auth_results.get("dmarc", "unknown")
    spf_result = auth_results.get("spf", "unknown")
    dkim_result = auth_results.get("dkim", "unknown")
    # Exact-domain comparisons are intentionally conservative. DMARC permits
    # relaxed organizational-domain alignment, which requires a public-suffix-aware
    # organizational-domain calculation and the published adkim/aspf modes.
    spf_aligned = bool(from_domain and return_path_domain and from_domain.lower().rstrip(".") == return_path_domain.lower().rstrip("."))
    dkim_aligned = bool(from_domain and dkim_domain and from_domain.lower().rstrip(".") == dkim_domain.lower().rstrip("."))
    return {
        "authentication_result": dmarc_result,
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "spf_alignment": spf_aligned,
        "dkim_alignment": dkim_aligned,
        "alignment_mode": "exact_domain_only",
        "alignment_note": "This is an exact-domain hint, not a complete DMARC evaluation. Relaxed organizational-domain alignment, adkim/aspf modes, trusted Authentication-Results provenance, and SMTP client-IP SPF evaluation are not independently verified.",
    }

def authentication_summary(msg, raw, from_domain, return_path_domain):
    auth_results = parse_authentication_results(msg.get_all("Authentication-Results", []))
    dkim_info = dkim_signature_info(msg)
    spf = spf_record(from_domain) if from_domain else None
    dmarc = dmarc_record(from_domain) if from_domain else None
    alignment = evaluate_dmarc_alignment(
        auth_results, from_domain, dkim_info["domain"], return_path_domain
    )
    dkim_verification = verify_dkim(raw) if dkim_info["signature_present"] else {"status": "not_checked", "error": None}
    return {
        "spf": {
            "record_found": bool(spf),
            "record": spf,
            "mechanisms": parse_spf_mechanisms(spf),
            "authentication_result": auth_results.get("spf", "unknown"),
            "note": "Header result is reported when present; full SMTP-client-IP SPF evaluation is outside this local parser.",
        },
        "dkim": {
            **dkim_info,
            "verified": dkim_verification["status"] == "verified",
            "verification_status": dkim_verification["status"],
            "verification_error": dkim_verification["error"],
        },
        "dmarc": {
            "record_found": bool(dmarc),
            "record": dmarc,
            "policy": dmarc_tags(dmarc),
            **alignment,
        },
        "authentication_results_header": auth_results,
    }
