from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import re

from bs4 import BeautifulSoup  # pip install beautifulsoup4

HTTP_URL_RE = re.compile(r'url\(\s*[\'"]?(http://[^\'")\s]+)[\'"]?\s*\)', re.IGNORECASE)

ACTIVE_TAG_ATTRS = [
    ("script", "src"),
    ("iframe", "src"),
    ("object", "data"),
    ("embed", "src"),
    ("link", "href"),  # rel=stylesheet handled by rel check
]
PASSIVE_TAG_ATTRS = [
    ("img", "src"),
    ("audio", "src"),
    ("video", "src"),
    ("source", "src"),
    ("track", "src"),
]
SPECIAL_HIGH = [
    ("form", "action"),
]

@dataclass
class MixedContentHit:
    check_id: str
    title: str
    severity: str
    evidence: str
    url: str
    resource_type: str
    is_active: bool

def _is_http(url: str) -> bool:
    try:
        return urlparse(url).scheme.lower() == "http"
    except Exception:
        return False

def _classify(tag: str, attr: str, extra: Optional[str] = None) -> Tuple[bool, str]:
    # Returns (is_active, severity)
    if (tag, attr) in SPECIAL_HIGH:
        return True, "HIGH"
    if (tag, attr) in ACTIVE_TAG_ATTRS:
        # stylesheet as active-ish
        return True, "HIGH"
    if (tag, attr) in PASSIVE_TAG_ATTRS:
        return False, "MEDIUM"
    return False, "LOW"

def scan_mixed_content(base_url: str, html: str, http_get_text=None) -> List[Finding]:
    """
    base_url: the HTTPS page URL you fetched
    html: HTML content of that page
    http_get_text: optional callable(url)->str for fetching CSS for deeper scanning
    """
    findings: List[Finding] = []
    soup = BeautifulSoup(html, "html.parser")

    # 1) Tag attribute scanning
    def scan_tag_attr(tag: str, attr: str):
        nonlocal findings
        for el in soup.find_all(tag):
            val = el.get(attr)
            if not val:
                continue
            abs_url = urljoin(base_url, val)
            if _is_http(abs_url):
                is_active, sev = _classify(tag, attr)
                # link rel=stylesheet only
                if tag == "link":
                    rel = (el.get("rel") or [])
                    rel = [r.lower() for r in rel]
                    if "stylesheet" not in rel:
                        continue
                evidence = f"<{tag} {attr}=\"{val}\">"
                findings.append(Finding(
                    check_id="MIXED_CONTENT",
                    title="Mixed content resource over HTTP",
                    severity=sev,
                    evidence=evidence,
                    url=abs_url,
                    resource_type=tag,
                    is_active=is_active
                ))

    for t, a in ACTIVE_TAG_ATTRS + PASSIVE_TAG_ATTRS + SPECIAL_HIGH:
        scan_tag_attr(t, a)

    # 2) Inline <style> blocks
    for style_el in soup.find_all("style"):
        css = style_el.get_text() or ""
        for m in HTTP_URL_RE.finditer(css):
            http_url = m.group(1)
            abs_url = urljoin(base_url, http_url)
            if _is_http(abs_url):
                findings.append(Finding(
                    check_id="MIXED_CONTENT",
                    title="Mixed content URL in inline CSS",
                    severity="MEDIUM",
                    evidence=f"<style> url({http_url})",
                    url=abs_url,
                    resource_type="css-inline",
                    is_active=False
                ))

    # 3) External CSS content scanning (optional but recommended)
    if http_get_text:
        for link in soup.find_all("link"):
            rel = (link.get("rel") or [])
            rel = [r.lower() for r in rel]
            if "stylesheet" not in rel:
                continue
            href = link.get("href")
            if not href:
                continue
            css_url = urljoin(base_url, href)
            # Only fetch CSS over HTTPS to avoid causing insecure fetches
            if urlparse(css_url).scheme.lower() != "https":
                continue
            try:
                css_text = http_get_text(css_url) or ""
            except Exception:
                continue
            for m in HTTP_URL_RE.finditer(css_text):
                http_url = m.group(1)
                abs_url = urljoin(css_url, http_url)
                if _is_http(abs_url):
                    findings.append(Finding(
                        check_id="MIXED_CONTENT",
                        title="Mixed content URL in external CSS",
                        severity="MEDIUM",
                        evidence=f"{css_url} contains url({http_url})",
                        url=abs_url,
                        resource_type="css-external",
                        is_active=False
                    ))

    return findings