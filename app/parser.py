from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import hashlib
import re
from bs4 import BeautifulSoup

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)

def parse_email(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)

def domain_of(address: str | None):
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().lower()

def address_value(msg, header):
    return parseaddr(msg.get(header, ""))[1] or None

def parse_authentication_results(values):
    result = {}
    for value in values or []:
        text = str(value)
        for key in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{key}\s*=\s*([a-zA-Z]+)", text, re.I)
            if m:
                result[key] = m.group(1).lower()
    return result

def extract_received(msg):
    return [str(x) for x in msg.get_all("Received", [])]

def parse_received_headers(msg):
    records = []
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,}\b")
    for raw in extract_received(msg):
        ips = ip_re.findall(raw)
        records.append({"raw": raw, "candidate_ips": list(dict.fromkeys(ips))})
    return records

def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()

def extract_content(msg):
    urls, attachments = [], []
    plain_parts, html_parts = [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "unnamed_attachment",
                "mime_type": part.get_content_type(),
                "size": len(payload),
                "data": payload,
                "sha256": sha256(payload),
            })
            continue

        try:
            content = part.get_content()
        except Exception:
            content = ""

        if part.get_content_type() == "text/html":
            html_parts.append(content)
        elif part.get_content_type() == "text/plain":
            plain_parts.append(content)

    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href")
            if href and href.lower().startswith(("http://", "https://")):
                urls.append({"url": href.strip(), "visible_text": a.get_text(" ", strip=True) or None})

    for text in plain_parts + [BeautifulSoup(x, "html.parser").get_text(" ") for x in html_parts]:
        for match in URL_RE.findall(text):
            urls.append({"url": match.rstrip(".,);]"), "visible_text": None})

    unique = {}
    for item in urls:
        key = item["url"]
        if key not in unique or (item.get("visible_text") and not unique[key].get("visible_text")):
            unique[key] = item
    return list(unique.values()), attachments

def header_summary(msg):
    return {
        "from": address_value(msg, "From"),
        "reply_to": address_value(msg, "Reply-To"),
        "return_path": address_value(msg, "Return-Path"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
    }
