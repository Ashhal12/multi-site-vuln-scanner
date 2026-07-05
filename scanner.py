"""
Multi-Site Vulnerability Assessment Engine
Scans multiple websites in parallel for common security issues:
- Missing/weak security headers
- SSL/TLS certificate issues
- Server info disclosure
- Common exposed files/paths
- Basic risk scoring (Critical/High/Medium/Low)
"""

import ssl
import socket
import requests
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

# ---------- Individual Check Functions ----------

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def check_security_headers(resp) -> list:
    """Check for missing important security headers."""
    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    important_headers = {
        "strict-transport-security": ("Missing HSTS header", "Medium"),
        "content-security-policy": ("Missing Content-Security-Policy", "Medium"),
        "x-frame-options": ("Missing X-Frame-Options (Clickjacking risk)", "Medium"),
        "x-content-type-options": ("Missing X-Content-Type-Options", "Low"),
        "referrer-policy": ("Missing Referrer-Policy header", "Low"),
    }

    for header, (msg, sev) in important_headers.items():
        if header not in headers:
            findings.append({"issue": msg, "severity": sev, "category": "Header Misconfiguration"})

    # Server banner disclosure
    if "server" in headers:
        findings.append({
            "issue": f"Server header discloses software: '{headers['server']}'",
            "severity": "Low",
            "category": "Information Disclosure"
        })
    if "x-powered-by" in headers:
        findings.append({
            "issue": f"X-Powered-By discloses tech stack: '{headers['x-powered-by']}'",
            "severity": "Low",
            "category": "Information Disclosure"
        })

    return findings


def check_ssl_cert(hostname: str, port: int = 443) -> list:
    """Check SSL certificate validity and expiry."""
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        findings.append({"issue": "SSL certificate has EXPIRED", "severity": "Critical", "category": "SSL/TLS"})
                    elif days_left < 15:
                        findings.append({"issue": f"SSL certificate expires in {days_left} days", "severity": "High", "category": "SSL/TLS"})
    except ssl.SSLCertVerificationError:
        findings.append({"issue": "SSL certificate verification failed (invalid/self-signed)", "severity": "High", "category": "SSL/TLS"})
    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        findings.append({"issue": "Could not establish SSL connection (site may not support HTTPS)", "severity": "Medium", "category": "SSL/TLS"})
    except Exception as e:
        findings.append({"issue": f"SSL check error: {str(e)[:80]}", "severity": "Low", "category": "SSL/TLS"})
    return findings


def check_common_exposed_paths(base_url: str) -> list:
    """Check for commonly exposed sensitive files/paths (safe, read-only)."""
    findings = []
    paths_to_check = [
        (".env", "Critical", "Exposed environment file (may leak secrets/credentials)"),
        (".git/config", "High", "Exposed .git directory (source code leak risk)"),
        ("wp-config.php.bak", "High", "Exposed WordPress config backup"),
        ("phpinfo.php", "Medium", "Exposed phpinfo() page (server info disclosure)"),
        ("admin/login", "Low", "Admin login panel publicly accessible"),
        ("backup.zip", "Medium", "Possible exposed backup archive"),
    ]
    for path, sev, msg in paths_to_check:
        try:
            r = requests.get(f"{base_url.rstrip('/')}/{path}", timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                findings.append({"issue": msg, "severity": sev, "category": "Exposed Path"})
        except requests.RequestException:
            continue
    return findings


# ---------- Risk Scoring ----------

SEVERITY_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}


def compute_risk_score(findings: list) -> dict:
    score = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    if score >= 10:
        level = "Critical"
    elif score >= 6:
        level = "High"
    elif score >= 2:
        level = "Medium"
    else:
        level = "Low"
    return {"score": score, "level": level}


# ---------- Main Per-Site Scan ----------

def scan_site(url: str) -> dict:
    url = normalize_url(url)
    hostname = urlparse(url).hostname
    result = {
        "url": url,
        "hostname": hostname,
        "scanned_at": datetime.now(timezone.utc).isoformat() + "Z",
        "reachable": False,
        "findings": [],
        "risk": {"score": 0, "level": "Unknown"},
        "error": None,
    }

    try:
        resp = requests.get(url, timeout=8, verify=False, allow_redirects=True)
        result["reachable"] = True
        result["status_code"] = resp.status_code
        result["findings"].extend(check_security_headers(resp))
    except requests.RequestException as e:
        result["error"] = str(e)[:150]
        result["risk"] = {"score": 0, "level": "Unreachable"}
        return result

    if hostname:
        result["findings"].extend(check_ssl_cert(hostname))

    result["findings"].extend(check_common_exposed_paths(url))
    result["risk"] = compute_risk_score(result["findings"])
    return result


def scan_multiple(urls: list, max_workers: int = 10) -> list:
    """Scan multiple URLs in parallel, return results sorted by risk (highest first)."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(scan_site, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            results.append(future.result())

    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unreachable": 4, "Unknown": 5}
    results.sort(key=lambda r: risk_order.get(r["risk"]["level"], 5))
    return results


if __name__ == "__main__":
    test_urls = ["https://example.com", "http://testphp.vulnweb.com"]
    import json
    output = scan_multiple(test_urls)
    print(json.dumps(output, indent=2))
