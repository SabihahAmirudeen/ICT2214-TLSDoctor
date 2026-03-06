from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any
from urllib.parse import urlparse
from http.cookies import SimpleCookie

import requests
import certifi


from ..models import Finding, Status, Severity


@dataclass
class CookieIssue:
    severity: str          # "HIGH" | "MEDIUM" | "LOW"
    issue: str
    cookie: str
    evidence: str
    remediation: str


def _get_set_cookie_headers(response) -> List[str]:
    headers: List[str] = []
    try:
        raw = response.raw.headers
        if hasattr(raw, "getlist"):
            headers.extend(raw.getlist("Set-Cookie"))
    except Exception:
        pass

    if not headers:
        sc = response.headers.get("Set-Cookie")
        if sc:
            headers.append(sc)
    return headers


def _parse_set_cookie(set_cookie_value: str):
    c = SimpleCookie()
    c.load(set_cookie_value)
    morsels = list(c.values())
    if not morsels:
        return None

    m = morsels[0]
    attrs = {k.lower(): v for k, v in m.items()}
    vlow = set_cookie_value.lower()
    attrs["secure"] = ("secure" in vlow)
    attrs["httponly"] = ("httponly" in vlow)

    return {"name": m.key, "value": m.value, "attrs": attrs, "raw": set_cookie_value}


def _evaluate_cookie(cookie, origin_host: str, origin_scheme: str) -> List[CookieIssue]:
    name = cookie["name"]
    a = cookie["attrs"]
    raw = cookie["raw"]

    issues: List[CookieIssue] = []
    likely_session = any(x in name.lower() for x in ["session", "sess", "sid", "auth", "token", "jwt"])

    if origin_scheme == "https" and not a.get("secure", False):
        issues.append(CookieIssue(
            severity="HIGH" if likely_session else "MEDIUM",
            issue="Cookie missing Secure flag",
            cookie=name,
            evidence=raw,
            remediation="Set the Secure attribute on cookies, especially session/auth cookies."
        ))

    if likely_session and not a.get("httponly", False):
        issues.append(CookieIssue(
            severity="HIGH",
            issue="Session/auth cookie missing HttpOnly flag",
            cookie=name,
            evidence=raw,
            remediation="Set HttpOnly on session/auth cookies to reduce XSS cookie theft impact."
        ))

    samesite = (a.get("samesite") or "").strip().lower()
    if likely_session and not samesite:
        issues.append(CookieIssue(
            severity="MEDIUM",
            issue="Session/auth cookie missing SameSite attribute",
            cookie=name,
            evidence=raw,
            remediation="Set SameSite=Lax or SameSite=Strict for session cookies where possible."
        ))
    if samesite == "none" and not a.get("secure", False):
        issues.append(CookieIssue(
            severity="HIGH",
            issue="SameSite=None without Secure",
            cookie=name,
            evidence=raw,
            remediation="If using SameSite=None, you must also set Secure (required by modern browsers)."
        ))

    if name.startswith("__Host-"):
        domain = (a.get("domain") or "").strip()
        path = (a.get("path") or "").strip()
        if (not a.get("secure", False)) or domain or path != "/":
            issues.append(CookieIssue(
                severity="MEDIUM",
                issue="__Host- cookie prefix rules violated",
                cookie=name,
                evidence=raw,
                remediation="For __Host- cookies: include Secure, Path=/, and omit Domain to force host-only scope."
            ))

    domain = (a.get("domain") or "").lstrip(".").lower()
    if domain and domain == origin_host.lower():
        issues.append(CookieIssue(
            severity="MEDIUM" if likely_session else "LOW",
            issue="Cookie sets Domain attribute (subdomain scope)",
            cookie=name,
            evidence=raw,
            remediation="Avoid Domain=.example.com for session cookies unless required; prefer host-only cookies (omit Domain)."
        ))

    return issues


def check_cookie_hygiene(url: str, timeout: int = 10) -> Finding:
    """
    Returns ONE Finding:
      - PASS if no cookie issues found (or no cookies set)
      - WARN if request/parsing fails
      - FAIL if any cookie issues found
    """
    try:
        s = requests.Session()
        r = s.get(
            url,
            allow_redirects=True,
            timeout=timeout,
            verify=certifi.where()   # ⭐ THIS FIXES TLS
        )

        results: List[Dict[str, Any]] = []
        issue_count = 0

        chain = list(r.history) + [r]
        for resp in chain:
            parsed = urlparse(resp.url)
            scheme = parsed.scheme
            host = parsed.hostname or ""
            for sc in _get_set_cookie_headers(resp):
                c = _parse_set_cookie(sc)
                if not c:
                    continue
                for iss in _evaluate_cookie(c, host, scheme):
                    issue_count += 1
                    results.append({
                        "severity": iss.severity,
                        "issue": iss.issue,
                        "cookie": iss.cookie,
                        "evidence": iss.evidence,
                        "remediation": iss.remediation,
                        "url": resp.url,
                    })

        if issue_count == 0:
            return Finding(
                check_id="cookie_hygiene",
                status=Status.PASS,
                severity=Severity.LOW,
                summary="No cookie hygiene issues detected (or no cookies were set).",
                evidence={"url": url, "issues": []},
                fix="No action required.",
                refs=["OWASP Session Management Cheat Sheet"],
            )

        # Map highest severity seen to Finding severity
        worst = "LOW"
        for x in results:
            if x["severity"] == "HIGH":
                worst = "HIGH"; break
            if x["severity"] == "MEDIUM":
                worst = "MEDIUM"

        sev = Severity.HIGH if worst == "HIGH" else (Severity.MEDIUM if worst == "MEDIUM" else Severity.LOW)

        return Finding(
            check_id="cookie_hygiene",
            status=Status.FAIL,
            severity=sev,
            summary=f"Cookie hygiene issues found: {issue_count}",
            evidence={"url": url, "issues": results},
            fix="Add Secure/HttpOnly/SameSite, tighten Domain/Path, and follow __Host- prefix rules as applicable.",
            refs=["OWASP Session Management Cheat Sheet"],
        )

    except Exception as e:
        return Finding(
            check_id="cookie_hygiene",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            summary="Cookie hygiene check failed (request/parsing error).",
            evidence={"url": url, "error": str(e)},
            fix="Verify the URL is reachable and TLS verification succeeds; ensure requests is installed and CA certs are available.",
            refs=["OWASP Session Management Cheat Sheet"],
        )