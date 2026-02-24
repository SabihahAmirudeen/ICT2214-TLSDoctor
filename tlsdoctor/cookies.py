import requests
from urllib.parse import urlparse
from http.cookies import SimpleCookie

def get_set_cookie_headers(response):
    """
    Requests collapses headers, but raw headers are accessible via response.raw in urllib3.
    This function tries both.
    """
    headers = []
    # Preferred: urllib3 HTTPResponse stores original header list
    try:
        raw = response.raw.headers
        if hasattr(raw, "getlist"):
            headers.extend(raw.getlist("Set-Cookie"))
    except Exception:
        pass

    # Fallback: may be a single combined header (not always reliable)
    if not headers:
        sc = response.headers.get("Set-Cookie")
        if sc:
            headers.append(sc)
    return headers

def parse_set_cookie(set_cookie_value):
    """
    Parse a single Set-Cookie header into name, value, and attributes.
    Note: SimpleCookie doesn't preserve all attrs perfectly, but works well for common flags.
    """
    c = SimpleCookie()
    c.load(set_cookie_value)
    morsels = list(c.values())
    if not morsels:
        return None

    m = morsels[0]
    attrs = {k.lower(): v for k, v in m.items()}  # includes 'secure', 'httponly', 'samesite', 'domain', 'path', 'max-age', 'expires'
    # Flags show up as '' when present
    attrs["secure"] = ("secure" in attrs and attrs["secure"] != None and set_cookie_value.lower().find("secure") != -1)
    attrs["httponly"] = (set_cookie_value.lower().find("httponly") != -1)

    return {
        "name": m.key,
        "value": m.value,
        "attrs": attrs,
        "raw": set_cookie_value
    }

def evaluate_cookie(cookie, origin_host, origin_scheme):
    name = cookie["name"]
    a = cookie["attrs"]
    raw = cookie["raw"]

    findings = []

    # Heuristic: treat likely-session cookies as high value
    likely_session = any(x in name.lower() for x in ["session", "sess", "sid", "auth", "token", "jwt"])

    # Rule: Secure on HTTPS sites (especially for session cookies)
    if origin_scheme == "https" and not a.get("secure", False):
        findings.append({
            "severity": "HIGH" if likely_session else "MEDIUM",
            "issue": "Cookie missing Secure flag",
            "cookie": name,
            "evidence": raw,
            "remediation": "Set the Secure attribute on cookies, especially session/auth cookies."
        })

    # Rule: HttpOnly for session/auth cookies
    if likely_session and not a.get("httponly", False):
        findings.append({
            "severity": "HIGH",
            "issue": "Session/auth cookie missing HttpOnly flag",
            "cookie": name,
            "evidence": raw,
            "remediation": "Set HttpOnly on session/auth cookies to reduce XSS cookie theft impact."
        })

    # Rule: SameSite presence & correctness
    samesite = (a.get("samesite") or "").strip().lower()
    if likely_session and not samesite:
        findings.append({
            "severity": "MEDIUM",
            "issue": "Session/auth cookie missing SameSite attribute",
            "cookie": name,
            "evidence": raw,
            "remediation": "Set SameSite=Lax or SameSite=Strict for session cookies where possible."
        })
    if samesite == "none" and not a.get("secure", False):
        findings.append({
            "severity": "HIGH",
            "issue": "SameSite=None without Secure",
            "cookie": name,
            "evidence": raw,
            "remediation": "If using SameSite=None, you must also set Secure (required by modern browsers)."
        })

    # Rule: __Host- prefix rules
    if name.startswith("__Host-"):
        # Must be Secure, Path=/, no Domain
        domain = (a.get("domain") or "").strip()
        path = (a.get("path") or "").strip()
        if not a.get("secure", False) or domain or path != "/":
            findings.append({
                "severity": "MEDIUM",
                "issue": "__Host- cookie prefix rules violated",
                "cookie": name,
                "evidence": raw,
                "remediation": "For __Host- cookies: include Secure, Path=/, and omit Domain to force host-only scope."
            })

    # Rule: Domain scoping overly broad
    domain = (a.get("domain") or "").lstrip(".").lower()
    if domain and domain == origin_host.lower():
        # domain attribute makes it available to subdomains (even if same host)
        findings.append({
            "severity": "MEDIUM" if likely_session else "LOW",
            "issue": "Cookie sets Domain attribute (subdomain scope)",
            "cookie": name,
            "evidence": raw,
            "remediation": "Avoid Domain=.example.com for session cookies unless required; prefer host-only cookies (omit Domain)."
        })

    return findings

def scan_cookie_hygiene(url, timeout=10):
    s = requests.Session()
    r = s.get(url, allow_redirects=True, timeout=timeout)

    parsed = urlparse(r.url)
    origin_host = parsed.hostname or ""
    origin_scheme = parsed.scheme

    results = []
    # check all responses in redirect chain plus final
    chain = list(r.history) + [r]

    for resp in chain:
        scheme = urlparse(resp.url).scheme
        host = urlparse(resp.url).hostname or origin_host
        for sc in get_set_cookie_headers(resp):
            c = parse_set_cookie(sc)
            if not c:
                continue
            results.extend(evaluate_cookie(c, host, scheme))

    return results

if __name__ == "__main__":
    findings = scan_cookie_hygiene("https://example.com")
    for f in findings:
        print(f"[{f['severity']}] {f['issue']} | {f['cookie']}")
        print(f"  Evidence: {f['evidence']}")
        print(f"  Fix: {f['remediation']}\n")