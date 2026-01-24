from __future__ import annotations
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright  # pip install playwright && playwright install

@dataclass
class HeadlessFinding:
    check_id: str
    title: str
    severity: str
    evidence: str
    url: str

def scan_headless_mixed_content(page_url: str, timeout_ms: int = 15000) -> List[HeadlessFinding]:
    findings: List[HeadlessFinding] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        def on_request(req):
            u = req.url
            if urlparse(page_url).scheme == "https" and urlparse(u).scheme == "http":
                findings.append(HeadlessFinding(
                    check_id="MIXED_CONTENT_HEADLESS",
                    title="Mixed content request observed in headless browser",
                    severity="HIGH",
                    evidence=f"Request: {req.method} {u}",
                    url=u
                ))

        page.on("request", on_request)
        page.goto(page_url, wait_until="networkidle", timeout=timeout_ms)

        context.close()
        browser.close()

    return findings