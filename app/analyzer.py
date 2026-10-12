import os
from .parser import parse_email, header_summary, domain_of, extract_content, parse_received_headers
from .auth import authentication_summary
from .received import enrich_received
from .urls import analyze_url
from .attachments import analyze_attachment
from .risk import build_findings, score

def env_int(name, default):
    try: return int(os.getenv(name, default))
    except Exception: return default

def analyze(raw):
    msg = parse_email(raw)
    summary = header_summary(msg)
    from_domain = domain_of(summary["from"])
    sender = {**summary,
              "from_domain":from_domain,
              "reply_to_domain":domain_of(summary["reply_to"]),
              "return_path_domain":domain_of(summary["return_path"])}

    auth = authentication_summary(msg, raw, from_domain, sender["return_path_domain"])
    received = enrich_received(parse_received_headers(msg))
    raw_urls, raw_attachments = extract_content(msg)

    urls = [analyze_url(x["url"],x.get("visible_text")) for x in raw_urls[:env_int("MAX_URLS",100)]]
    attachments = [analyze_attachment(x) for x in raw_attachments[:env_int("MAX_ATTACHMENTS",20)]]

    findings = build_findings(sender,auth,received,urls,attachments)
    level, risk_score = score(findings)

    from .risk import calculate_confidence
    confidence = calculate_confidence(auth, urls, attachments)

    return {
        "risk_level":level,"risk_score":risk_score,"confidence":confidence,
        "assessment_note":"Heuristic defensive analysis. A LOW result is not a guarantee of safety and a HIGH/CRITICAL result is not by itself proof of malicious intent.",
        "sender":sender,"authentication":auth,"received_chain":received,
        "urls":urls,"attachments":attachments,"findings":findings
    }
