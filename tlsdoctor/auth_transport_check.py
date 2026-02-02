from typing import Dict, Any, List
import requests

from .models import Finding, Status, Severity


AUTH_COOKIE_KEYWORDS = [
    "session", "sess", "sid", "token", "auth", "jwt", "remember", "csrf"
]


def _get_set_cookie_list(resp: requests.Response) -> List[str]:
    raw = getattr(resp.raw, "headers", None)
    if raw is not None and hasattr(raw, "get_all"):
        return raw.get_all("Set-Cookie") or []
    sc = resp.headers.get("Set-Cookie")
    return [sc] if sc else []


def _looks_like_auth_cookie(set_cookie_header: str) -> bool:
    # cookie name is before the first "="
    name = set_cookie_header.split("=", 1)[0].strip().lower()
    return any(k in name for k in AUTH_COOKIE_KEYWORDS)


def _has_secure_flag(set_cookie_header: str) -> bool:
    return "secure" in set_cookie_header.lower()


def check_auth_over_http(http_url: str, timeout: float = 8.0) -> Finding:
    """
    Passive check:
    - Requests HTTP URL (port 80)
    - Follows redirects
    - Flags if authentication/session cookies are set via HTTP or without Secure
    - Also flags if Authorization headers appear (rare, but severe)
    """
    evidence: Dict[str, Any] = {
        "http_url": http_url,
        "final_url": None,
        "redirect_chain": [],
        "authorization_header_seen": False,
        "set_cookie_seen": [],
        "auth_like_cookies": [],
        "auth_like_cookie_missing_secure": [],
        "error": None,
    }

    try:
        resp = requests.get(http_url, allow_redirects=True, timeout=timeout)

        # Build redirect chain
        chain = []
        for h in resp.history:
            chain.append({
                "url": h.url,
                "status_code": h.status_code,
                "location": h.headers.get("Location"),
            })
        chain.append({
            "url": resp.url,
            "status_code": resp.status_code,
            "location": resp.headers.get("Location"),
        })

        evidence["redirect_chain"] = chain
        evidence["final_url"] = resp.url

        # Check for Authorization header in response (uncommon but bad practice)
        # Note: "Authorization" is typically a request header, but some systems echo tokens back.
        if "authorization" in (k.lower() for k in resp.headers.keys()):
            evidence["authorization_header_seen"] = True

        # Look at Set-Cookie headers on the final response AND all redirect responses
        cookie_headers: List[str] = []

        for h in resp.history:
            cookie_headers.extend(_get_set_cookie_list(h))
        cookie_headers.extend(_get_set_cookie_list(resp))

        evidence["set_cookie_seen"] = cookie_headers

        # Filter to "auth-like" cookies
        auth_like = [c for c in cookie_headers if _looks_like_auth_cookie(c)]
        evidence["auth_like_cookies"] = auth_like

        # Among auth-like cookies, see if Secure is missing
        missing_secure = [c for c in auth_like if not _has_secure_flag(c)]
        evidence["auth_like_cookie_missing_secure"] = missing_secure

        # Decision logic
        final_is_http = resp.url.lower().startswith("http://")

        # High severity if: auth cookies set over HTTP OR final stayed HTTP and set cookies
        if auth_like and (final_is_http or missing_secure):
            # If still HTTP at the end, treat as FAIL/HIGH
            if final_is_http:
                return Finding(
                    check_id="auth_over_http",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    summary="Authentication/session cookies are exposed over HTTP (unencrypted), enabling interception.",
                    evidence=evidence,
                    fix="Force HTTP→HTTPS redirect; ensure session/auth cookies include Secure; serve login/session endpoints only over HTTPS.",
                    refs=["OWASP A02: Identification and Authentication Failures", "OWASP A04: Cryptographic Failures"],
                )

            # Redirects to HTTPS but cookies missing Secure is still serious
            return Finding(
                check_id="auth_over_http",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="Auth-like cookies observed; some are missing Secure (risk if ever sent over HTTP).",
                evidence=evidence,
                fix="Set Secure on session/auth cookies; ensure cookies are never issued on HTTP endpoints.",
                refs=["OWASP A02: Identification and Authentication Failures", "OWASP A04: Cryptographic Failures"],
            )

        # If any cookies were set during HTTP phase (even non-auth-like), warn if final is HTTP
        if cookie_headers and final_is_http:
            return Finding(
                check_id="auth_over_http",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="Cookies were set during an HTTP request; sensitive cookies may be exposed if used for sessions.",
                evidence=evidence,
                fix="Force HTTP→HTTPS redirect and set Secure on all session/auth cookies.",
                refs=["OWASP A02: Identification and Authentication Failures", "OWASP A04: Cryptographic Failures"],
            )

        # PASS if HTTP immediately redirects to HTTPS and no auth material observed
        return Finding(
            check_id="auth_over_http",
            status=Status.PASS,
            severity=Severity.LOW,
            summary="No authentication material was observed over HTTP (redirects/headers appear safe).",
            evidence=evidence,
            fix="No action required.",
            refs=["OWASP A02: Identification and Authentication Failures"],
        )

    except Exception as e:
        evidence["error"] = str(e)
        return Finding(
            check_id="auth_over_http",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            summary="Could not verify authentication material exposure over HTTP (request failed).",
            evidence=evidence,
            fix="Verify the host is reachable on HTTP (port 80) and try again.",
            refs=["OWASP A02: Identification and Authentication Failures"],
        )
