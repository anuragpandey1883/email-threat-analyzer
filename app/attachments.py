import io
import math
import os
import re
import zipfile
import httpx
from pathlib import Path
from .yara_scan import scan_bytes

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

try:
    from oletools.olevba import VBA_Parser
except Exception:
    VBA_Parser = None

SIGNATURES = {
    b"%PDF-": "PDF",
    b"MZ": "PE/executable",
    b"PK\x03\x04": "ZIP/container",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF8": "GIF",
}
EXEC_EXTENSIONS = {".exe",".dll",".scr",".msi",".bat",".cmd",".ps1",".vbs",".js",".jse",".wsf",".wsh",".hta",".com",".cpl",".jar"}
MACRO_EXTENSIONS = {".docm",".dotm",".xlsm",".xltm",".pptm",".ppsm"}
OFFICE_EXTENSIONS = {".doc",".docx",".docm",".dot",".dotm",".xls",".xlsx",".xlsm",".xltm",".ppt",".pptx",".pptm",".ppsm"}

def magic_type(data):
    for sig, name in SIGNATURES.items():
        if data.startswith(sig): return name
    return "Unknown"

def entropy(data):
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts if c)

def pdf_analysis(data):
    result = {}
    if not PdfReader: return {"available": False}
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        result["available"] = True
        result["pages"] = len(reader.pages)
        result["encrypted"] = bool(reader.is_encrypted)
        text = ""
        for page in reader.pages[:10]:
            try: text += page.extract_text() or ""
            except Exception: pass
        result["text_preview_length"] = len(text)
        result["javascript"] = any("/JavaScript" in str(k) or "/JS" in str(k) for p in reader.pages[:10] for k in getattr(p, "keys", lambda: [])())
        result["embedded_files_hint"] = b"/EmbeddedFile" in data
    except Exception as exc:
        result["error"] = type(exc).__name__
    return result

def office_analysis(data, filename):
    if not VBA_Parser:
        return {"available": False}
    result = {"available": True}
    try:
        vb = VBA_Parser(filename, data=data)
        result["is_macro_file"] = vb.detect_vba_macros()
        macros = []
        if result["is_macro_file"]:
            for (_, _, vba_filename, vba_code) in vb.extract_macros():
                macros.append({"filename": vba_filename, "code_length": len(vba_code)})
        result["macros"] = macros[:20]
        vb.close()
    except Exception as exc:
        result["error"] = type(exc).__name__
    return result

def archive_analysis(data):
    result = {"is_zip": False, "members": [], "total_uncompressed": 0, "suspicious_members": []}
    if not data.startswith(b"PK"):
        return result
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            result["is_zip"] = True
            infos = z.infolist()
            max_files = int(os.getenv("MAX_ARCHIVE_FILES", "100"))
            max_total = int(os.getenv("MAX_ARCHIVE_TOTAL_MB", "50")) * 1024 * 1024
            max_member = int(os.getenv("MAX_ARCHIVE_MEMBER_MB", "10")) * 1024 * 1024
            total = 0
            for info in infos[:max_files]:
                total += info.file_size
                result["members"].append({"name": info.filename, "size": info.file_size})
                if info.file_size > max_member:
                    result["suspicious_members"].append("Oversized archive member: " + info.filename)
                if Path(info.filename).suffix.lower() in EXEC_EXTENSIONS | MACRO_EXTENSIONS:
                    result["suspicious_members"].append("Potentially dangerous archive member: " + info.filename)
                if total > max_total:
                    result["suspicious_members"].append("Archive exceeds configured uncompressed-size limit")
                    break
            result["total_uncompressed"] = total
            result["file_count"] = len(infos)
            result["truncated"] = len(infos) > max_files
    except Exception as exc:
        result["error"] = type(exc).__name__
    return result



def virustotal_file_report(sha256):
    """Fetch an existing VirusTotal file report by hash; never upload file bytes."""
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "message": "VirusTotal API key is not configured."}

    if not sha256 or not re.fullmatch(r"[a-fA-F0-9]{64}", str(sha256)):
        return {"status": "invalid_hash", "message": "A valid SHA-256 hash is required."}

    try:
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=httpx.Timeout(10.0, connect=4.0),
            follow_redirects=False,
        )
        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "This SHA-256 is not present in VirusTotal. The file was not uploaded."
            }
        if response.status_code == 429:
            return {"status": "rate_limited", "message": "VirusTotal API rate limit reached."}
        if response.status_code in (401, 403):
            return {"status": "api_key_error", "message": "VirusTotal rejected the API key or access."}
        try:
            payload = response.json()
        except Exception:
            payload = {"message": "VirusTotal returned a non-JSON response."}

        if response.is_error:
            return {
                "status": "http_error",
                "http_status": response.status_code,
                "message": payload.get("error", {}).get("message", "VirusTotal request failed."),
                "raw": payload,
            }

        return {"status": "ok", "data": payload}
    except Exception as exc:
        return {"status": "request_error", "message": type(exc).__name__}


def analyze_attachment(item):
    name, data, ext = item["filename"], item["data"], Path(item["filename"]).suffix.lower()
    indicators = []
    detected = magic_type(data)
    try:
        max_bytes = max(1, int(os.getenv("MAX_ATTACHMENT_ANALYSIS_MB", "10"))) * 1024 * 1024
    except (TypeError, ValueError):
        max_bytes = 10 * 1024 * 1024
    if len(data) > max_bytes:
        indicators.append(f"Attachment exceeds analysis size limit ({max_bytes // (1024 * 1024)} MB); deep parsing skipped")
        return {
            "filename": name, "mime_type": item["mime_type"], "size": item["size"],
            "sha256": item["sha256"],
            "virustotal": {"status": "skipped_size_limit", "message": "Hash reputation lookup skipped for oversized attachment."},
            "detected_type": detected, "indicators": indicators, "yara_matches": [],
            "document_analysis": {"available": False, "reason": "size_limit"},
            "archive_analysis": {"is_zip": False, "members": [], "suspicious_members": [], "reason": "size_limit"},
        }

    if ext in EXEC_EXTENSIONS: indicators.append("Executable or script attachment extension")
    if ext in MACRO_EXTENSIONS: indicators.append("Macro-enabled Office document")
    if len(Path(name).name.split(".")) > 2: indicators.append("Multiple-extension filename")
    if detected == "PE/executable" and ext not in EXEC_EXTENSIONS: indicators.append("Executable file signature despite non-executable extension")
    if detected == "PDF":
        if b"/JavaScript" in data or b"/JS" in data: indicators.append("PDF JavaScript-related object")
        if b"/EmbeddedFile" in data: indicators.append("PDF contains an embedded file")
    if len(data) > 100_000 and entropy(data) > 7.5: indicators.append("High-entropy content (heuristic)")

    ymatches = scan_bytes(data)
    for m in ymatches: indicators.append("YARA match: " + m["rule"])

    doc = {}
    if detected == "PDF": doc = pdf_analysis(data)
    elif ext in OFFICE_EXTENSIONS: doc = office_analysis(data, name)

    archive = archive_analysis(data)

    return {
        "filename": name, "mime_type": item["mime_type"], "size": item["size"],
        "sha256": item["sha256"], "virustotal": virustotal_file_report(item["sha256"]), "detected_type": detected,
        "indicators": sorted(set(indicators)), "yara_matches": ymatches,
        "document_analysis": doc, "archive_analysis": archive,
    }
