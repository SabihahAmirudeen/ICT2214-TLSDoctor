import requests
import email.utils
from datetime import datetime, timezone
from .models import Finding, Status, Severity


THIRTY_DAYS = 30 * 24 * 60 * 60

def check_session_cookie_lifetime(url: str):

    response = requests.get(url, timeout=10)

    cookies = []

    for c in response.cookies:
        max_age = c._rest.get("max-age")

        if max_age:
            try:
                max_age = int(max_age)
            except ValueError:
                max_age = None

        cookies.append({
            "name": c.name,
            "max_age": max_age,
            "expires_unix": c.expires,
            "expires_utc": None
        })

    return evaluate_session_cookie_lifetime(cookies)

def evaluate_session_cookie_lifetime(cookies: list):
    findings = []

    SESSION_KEYWORDS = [
        "session",
        "auth",
        "token",
        "sid",
        "jwt",
        "bearer",
        "sess"
    ]

    SESSION_EXACT = [
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid"
    ]

    for cookie in cookies:
        name = cookie.get("name", "").lower()

        # targets common server-side session/auth cookies  
        if not (
            any(keyword in name for keyword in SESSION_KEYWORDS)
            or name in SESSION_EXACT
        ):
            continue

        max_age = cookie.get("max_age")
        expires = cookie.get("expires_unix")

        # case 1: Non-persistent (BEST PRACTICE)
        if not max_age and not expires:
            findings.append(
                Finding(
                    check_id="session_cookie_persistence",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    summary=f"Session cookie '{name}' is non-persistent.",
                    evidence=cookie,
                    fix="No action required.",
                    refs=["OWASP A07:2025", "OWASP Session Management Cheat Sheet"]
                )
            )
            continue

        # case 2: Persistent cookie (OWASP warns against)
        findings.append(
            Finding(
                check_id="session_cookie_persistence",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary=f"Session cookie '{name}' is persistent (uses Max-Age or Expires).",
                evidence=cookie,
                fix="Use non-persistent cookies for session management (remove Max-Age/Expires).",
                refs=["OWASP A07:2025", "OWASP Session Management Cheat Sheet"]
            )
        )

        # case 3: excessive lifetime
        if max_age and max_age > THIRTY_DAYS:
            findings.append(
                Finding(
                    check_id="session_cookie_long_lived",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    summary=f"Session cookie '{name}' has excessive lifetime (>30 days).",
                    evidence=cookie,
                    fix="Reduce session lifetime to short duration or use non-persistent cookies.",
                    refs=["OWASP A07:2025", "OWASP Session Management Cheat Sheet"]
                )
            )

        # if only Expires exists, try calculating lifetime
        elif expires:
            try:
                if isinstance(expires, (int, float)):
                    expire_dt = datetime.fromtimestamp(expires, tz=timezone.utc)
                else:
                    expire_dt = email.utils.parsedate_to_datetime(expires)

                lifetime = (expire_dt - datetime.now(timezone.utc)).total_seconds()
                cookie["expires_utc"] = expire_dt.isoformat()

                if lifetime > THIRTY_DAYS:
                    findings.append(
                        Finding(
                            check_id="session_cookie_long_lived",
                            status=Status.FAIL,
                            severity=Severity.HIGH,
                            summary=f"Session cookie '{name}' expires far in the future (>30 days).",
                            evidence=cookie,
                            fix="Reduce expiration time to limit session persistence.",
                            refs=["OWASP A07:2025", "OWASP Session Management Cheat Sheet"]
                        )
                    )
            except Exception:
                pass

    return findings
