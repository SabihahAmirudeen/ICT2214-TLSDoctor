import re
from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    """
    Ensure the URL has a scheme.
    If the user enters example.com, convert it to https://example.com
    """
    url = url.strip()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    return url


def get_host(url: str) -> str:
    """
    Extract hostname from a URL (hostname only, without port).
    """
    parsed = urlparse(url)
    return parsed.hostname or ""


def to_https(url: str) -> str:
    """
    Convert any URL to its HTTPS version.
    """
    parsed = urlparse(url)
    return urlunparse((
        "https",
        parsed.netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment
    ))


def to_http(url: str) -> str:
    """
    Convert any URL to its HTTP version.
    """
    parsed = urlparse(url)
    return urlunparse((
        "http",
        parsed.netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
