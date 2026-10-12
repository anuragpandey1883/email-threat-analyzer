
import os
import ipaddress
import re
import socket
import json
import urllib.request
import urllib.parse
import urllib.error


IP_RE = re.compile(
    r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])"
    r"|(?<![\w:])[0-9a-fA-F:]{3,}(?![\w:])"
)


def classify_ip(value):
    try:
        ip = ipaddress.ip_address(value)

        if not ip.is_global:
            return "private_or_local"

        return "public"

    except ValueError:
        return "unknown"


def api_request(url, headers=None, params=None):
    if params:
        url += "?" + urllib.parse.urlencode(params)

    request = urllib.request.Request(
        url,
        headers=headers or {},
        method="GET"
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"status": "unauthorized"}

        if e.code == 403:
            return {"status": "access_denied"}

        if e.code == 429:
            return {"status": "rate_limited"}

        return {"status": "lookup_failed", "http_status": e.code}

    except Exception:
        return {"status": "lookup_failed"}


def abuseipdb_lookup(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {"status": "not_configured"}

    result = api_request(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key": api_key,
            "Accept": "application/json"
        },
        params={
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
    )

    if result.get("status"):
        return result

    data = result.get("data", {})

    if not data:
        return {"status": "lookup_failed"}

    return {
        "status": "success",
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp")
    }


def virustotal_lookup(ip):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {"status": "not_configured"}

    result = api_request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    )

    if result.get("status"):
        return result

    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    if not stats:
        return {"status": "lookup_failed"}

    return {
        "status": "success",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }


def enrich_received(records):
    output = []

    for rec in records:
        ips = []

        for candidate in rec.get("candidate_ips", []):
            try:
                ip_obj = ipaddress.ip_address(candidate)
            except ValueError:
                continue

            category = classify_ip(candidate)

            reverse = None

            if category == "public":
                try:
                    reverse = socket.gethostbyaddr(candidate)[0]
                except Exception:
                    pass

            ip_result = {
                "ip": candidate,
                "scope": category,
                "reverse_dns": reverse,
                "abuseipdb": {"status": "not_checked"},
                "virustotal": {"status": "not_checked"}
            }

            if category == "public":
                ip_result["abuseipdb"] = abuseipdb_lookup(candidate)
                ip_result["virustotal"] = virustotal_lookup(candidate)

            ips.append(ip_result)

        output.append({
            "raw": rec.get("raw", ""),
            "ips": ips
        })

    return output