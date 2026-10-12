import base64
import os
import socket
import ipaddress
import ipaddress
from urllib.parse import urlsplit, urlunsplit
import httpx
import tldextract

SENSITIVE_WORDS = {"login","verify","password","credential","wallet","invoice","account","signin","reset"}

def normalize_url(url):
    try:
        p = urlsplit((url or "").strip())
        host = (p.hostname or "").lower().rstrip(".")
        scheme = p.scheme.lower()
        port = p.port  # Raises ValueError for malformed ports.
        if not host or scheme not in {"http", "https"}:
            raise ValueError("URL must be absolute HTTP(S)")
        try:
            host = f"[{host}]" if ipaddress.ip_address(host).version == 6 else host
        except ValueError:
            pass
        netloc = host
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc += f":{port}"
        return urlunsplit((scheme, netloc, p.path or "/", p.query, ""))
    except Exception:
        return (url or "").strip()

def indicators(url):
    out = []
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        if p.scheme.lower() != "https": out.append("URL is not HTTPS")
        try:
            parsed_ip = ipaddress.ip_address(host)
            out.append("URL uses an IP address instead of a domain name")
            if not parsed_ip.is_global:
                out.append("URL points to a private or reserved IP address")
        except ValueError:
            pass
        if "xn--" in host.lower(): out.append("Punycode hostname detected")
        try:
            unicode_host = host.encode("ascii").decode("idna")
            if unicode_host != host:
                out.append("Internationalized hostname (IDN); visually similar characters may be used")
        except (UnicodeError, UnicodeEncodeError):
            pass
        if len(url) > 200: out.append("Unusually long URL")
        if "@" in p.netloc: out.append("URL contains @ in authority")
        try:
            if p.port and p.port not in {80, 443}:
                out.append(f"URL uses a non-standard port ({p.port})")
        except ValueError:
            out.append("Malformed URL port")
        target = (p.path + "?" + p.query).lower()
        for word in SENSITIVE_WORDS:
            if word in target: out.append(f"Sensitive-looking keyword: {word}")
    except Exception:
        out.append("Malformed URL")
    return sorted(set(out))

def registered_domain(host):
    e = tldextract.extract(host or "")
    return ".".join(x for x in (e.domain, e.suffix) if x)

def visible_link_mismatch(href, visible_text):
    if not visible_text or not visible_text.strip().lower().startswith(("http://","https://")):
        return False
    return registered_domain(urlsplit(visible_text.strip()).hostname) != registered_domain(urlsplit(href).hostname)

def dns_info(host):
    result = {"hostname": host, "addresses": []}
    if not host: return result
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        result["addresses"] = sorted(set(x[4][0] for x in infos))
    except Exception:
        result["error"] = "DNS resolution failed"
    return result

def reputation(url):
    result = {}
    timeout = httpx.Timeout(5.0, connect=3.0)
    try:
        r = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=timeout, follow_redirects=False)
        result["urlhaus"] = r.json()
    except Exception as exc:
        result["urlhaus"] = {"error": type(exc).__name__}

        # VirusTotal URL reputation check
    vt_key = os.getenv("VT_API_KEY", "").strip()

    if not vt_key:
        result["virustotal"] = {
            "status": "not_configured",
            "message": "VirusTotal API key is missing"
        }
    else:
        try:
            # Convert URL into VirusTotal URL ID
            url_id = (
                base64.urlsafe_b64encode(url.encode())
                .decode()
                .rstrip("=")
            )

            # Send request to VirusTotal
            r = httpx.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": vt_key},
                timeout=timeout
            )

            try:
                vt_data = r.json()
            except Exception:
                vt_data = {}

            if r.status_code == 200:
                result["virustotal"] = vt_data

            elif r.status_code == 404:
                result["virustotal"] = {
                    "status": "not_found",
                    "http_status": 404,
                    "message": (
                        "This URL is not present in VirusTotal. "
                        "No URL submission was performed."
                    )
                }

            elif r.status_code == 401:
                result["virustotal"] = {
                    "status": "api_key_error",
                    "http_status": 401,
                    "message": "VirusTotal rejected the API key."
                }

            elif r.status_code == 403:
                result["virustotal"] = {
                    "status": "access_denied",
                    "http_status": 403,
                    "message": (
                        "VirusTotal denied access. "
                        "Check API permissions and account access."
                    )
                }

            elif r.status_code == 429:
                result["virustotal"] = {
                    "status": "rate_limited",
                    "http_status": 429,
                    "message": "VirusTotal API rate limit reached."
                }

            else:
                error_data = vt_data.get("error", {})

                if isinstance(error_data, dict):
                    error_message = error_data.get(
                        "message", "VirusTotal request failed"
                    )
                else:
                    error_message = str(error_data)

                result["virustotal"] = {
                    "status": "error",
                    "http_status": r.status_code,
                    "message": error_message
                }

        except Exception as exc:
            result["virustotal"] = {
                "status": "error",
                "message": str(exc)
            }

        # Google Safe Browsing URL check
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    if not gsb_key:
        result["google_safe_browsing"] = {
            "status": "not_configured",
            "message": "Google Safe Browsing API key is missing"
        }
    else:
        try:
            endpoint = (
                "https://safebrowsing.googleapis.com/v4/"
                f"threatMatches:find?key={gsb_key}"
            )

            payload = {
                "client": {
                    "clientId": "local-email-threat-analyzer",
                    "clientVersion": "0.4"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [
                        {"url": url}
                    ]
                }
            }

            r = httpx.post(
                endpoint,
                json=payload,
                timeout=timeout
            )

            try:
                gsb_data = r.json()
            except Exception:
                gsb_data = {}

            if r.status_code == 200:
                result["google_safe_browsing"] = gsb_data

            elif r.status_code == 400:
                result["google_safe_browsing"] = {
                    "status": "error",
                    "message": "The URL could not be checked due to an invalid request."
                }

            elif r.status_code == 401:
                result["google_safe_browsing"] = {
                    "status": "unavailable",
                    "message": (
                        "Google Safe Browsing could not verify this URL "
                        "because the API credentials were not accepted. "
                        "The URL's safety remains unverified."
                    )
                }

            elif r.status_code == 403:
                result["google_safe_browsing"] = {
                    "status": "unavailable",
                    "message": (
                        "Google Safe Browsing access is restricted. "
                        "No threat verdict was returned. "
                        "The URL's safety remains unverified."
                    )
                }

            elif r.status_code == 429:
                result["google_safe_browsing"] = {
                    "status": "unavailable",
                    "message": (
                        "Google Safe Browsing's request limit has been reached. "
                        "Please try again later. The URL's safety remains unverified."
                    )
                }

            else:
                result["google_safe_browsing"] = {
                    "status": "unavailable",
                    "message": (
                        "Google Safe Browsing is temporarily unable to check "
                        "this URL. Its safety remains unverified."
                    )
                }

        except Exception as exc:
            result["google_safe_browsing"] = {
                "status": "error",
                "message": str(exc)
            }
    return result

def analyze_url(url, visible_text=None):
    normalized = normalize_url(url)
    try:
        parsed = urlsplit(normalized)
        host = parsed.hostname or ""
        _ = parsed.port  # Validate malformed/out-of-range ports before network lookups.
        valid = parsed.scheme.lower() in {"http", "https"} and bool(host)
    except Exception:
        host, valid = "", False
    if not valid:
        return {"url": url, "normalized_url": normalized, "visible_text": visible_text,
                "link_mismatch": False, "indicators": ["Malformed or unsupported URL"],
                "dns": {"hostname": host, "addresses": [], "error": "URL is not a valid absolute HTTP(S) URL"},
                "reputation": {"status": "not_checked", "message": "Malformed URL was not sent to reputation services."}}
    return {
        "url": url,
        "normalized_url": normalized,
        "visible_text": visible_text,
        "link_mismatch": visible_link_mismatch(url, visible_text),
        "indicators": indicators(normalized),
        "dns": dns_info(host),
        "reputation": reputation(normalized),
    }
