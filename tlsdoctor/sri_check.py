from typing import Dict, Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .models import Finding, Status, Severity


def _is_third_party(resource_url: str, page_host: str) -> bool:
    host = urlparse(resource_url).hostname
    if not host:
        return False
    return host.lower() != page_host.lower()


def check_sri(https_url: str, timeout: float = 8.0) -> Finding:
    """
    Check Subresource Integrity usage for third-party JS/CSS resources.
    Flags external <script src=...> and <link rel=stylesheet href=...> without integrity=...
    """
    evidence: Dict[str, Any] = {
        "url": https_url,
        "page_host": None,
        "external_resources_missing_sri": [],
        "external_resources_with_sri": [],
        "error": None,
    }

    try:
        r = requests.get(https_url, allow_redirects=True, timeout=timeout)
        content_type = (r.headers.get("Content-Type") or "").lower()
        if "text/html" not in content_type:
            return Finding(
                check_id="sri_check",
                status=Status.WARN,
                severity=Severity.LOW,
                summary="SRI check skipped (response is not HTML).",
                evidence=evidence,
                fix="Run SRI checks on HTML pages that load external JS/CSS.",
                refs=["W3C Subresource Integrity"],
            )

        page_host = urlparse(r.url).hostname or ""
        evidence["page_host"] = page_host

        soup = BeautifulSoup(r.text, "html.parser")

        # External scripts
        for s in soup.find_all("script"):
            src = s.get("src")
            if not src:
                continue
            if src.startswith("http://") or src.startswith("https://"):
                if _is_third_party(src, page_host):
                    if s.get("integrity"):
                        evidence["external_resources_with_sri"].append(
                            {"type": "script", "url": src, "integrity": s.get("integrity")}
                        )
                    else:
                        evidence["external_resources_missing_sri"].append(
                            {"type": "script", "url": src}
                        )

        # External stylesheets
        for l in soup.find_all("link"):
            rel = l.get("rel") or []
            rel = [x.lower() for x in rel] if isinstance(rel, list) else [str(rel).lower()]
            if "stylesheet" not in rel:
                continue
            href = l.get("href")
            if not href:
                continue
            if href.startswith("http://") or href.startswith("https://"):
                if _is_third_party(href, page_host):
                    if l.get("integrity"):
                        evidence["external_resources_with_sri"].append(
                            {"type": "stylesheet", "url": href, "integrity": l.get("integrity")}
                        )
                    else:
                        evidence["external_resources_missing_sri"].append(
                            {"type": "stylesheet", "url": href}
                        )

        missing = evidence["external_resources_missing_sri"]
        if not missing:
            return Finding(
                check_id="sri_check",
                status=Status.PASS,
                severity=Severity.LOW,
                summary="No third-party JS/CSS resources missing SRI were detected.",
                evidence=evidence,
                fix="No action required.",
                refs=["W3C Subresource Integrity"],
            )

        # If scripts missing SRI -> higher impact than CSS
        has_script_missing = any(x["type"] == "script" for x in missing)
        sev = Severity.MEDIUM if has_script_missing else Severity.LOW

        return Finding(
            check_id="sri_check",
            status=Status.WARN,
            severity=sev,
            summary="Third-party resources are loaded without Subresource Integrity (SRI).",
            evidence=evidence,
            fix="Add integrity= and crossorigin= to third-party <script>/<link> tags. Consider self-hosting critical resources.",
            refs=["W3C Subresource Integrity"],
        )

    except Exception as e:
        evidence["error"] = str(e)
        return Finding(
            check_id="sri_check",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            summary="Could not perform SRI check (request/parse failed).",
            evidence=evidence,
            fix="Verify the HTTPS URL is reachable and returns HTML.",
            refs=["W3C Subresource Integrity"],
        )
