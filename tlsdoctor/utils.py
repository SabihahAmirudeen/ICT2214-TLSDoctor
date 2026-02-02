import re
from urllib.parse import urlparse, urlunparse
import sys
import threading
import itertools
import time


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


class Spinner:
    """A simple terminal spinner context manager.

    Usage:
        with Spinner("Working..."):
            long_running_task()
    """

    def __init__(self, msg: str = "Processing"):
        self.msg = msg
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for ch in itertools.cycle("|/-\\"):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r{self.msg} {ch}")
            sys.stdout.flush()
            time.sleep(0.12)

    def __enter__(self):
        self._stop.clear()
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        self._thread.join()
        sys.stdout.write("\r")
        sys.stdout.flush()


class ProgressSpinner:
    """Terminal spinner with a percentage indicator.

    The spinner will automatically advance the percentage slowly up to a cap
    while a blocking operation runs. Call `finish(percent)` to complete.
    """

    def __init__(self, msg: str = "Processing", cap: int = 95, step_delay: float = 0.5):
        self.msg = msg
        self.cap = min(max(cap, 1), 99)
        self.step_delay = step_delay
        self._stop = threading.Event()
        self._pct = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._spinner_cycle = itertools.cycle("|/-\\")

    def _run(self):
        while not self._stop.is_set():
            ch = next(self._spinner_cycle)
            with self._lock:
                pct = self._pct
            sys.stdout.write(f"\r{self.msg} {ch} {pct:3d}%")
            sys.stdout.flush()
            time.sleep(0.12)

    def start(self):
        self._stop.clear()
        self._thread.start()
        # start a background adder thread that bumps percent toward cap
        def _bump():
            while not self._stop.is_set():
                with self._lock:
                    if self._pct < self.cap:
                        self._pct += 1
                time.sleep(self.step_delay)

        self._bump_thread = threading.Thread(target=_bump, daemon=True)
        self._bump_thread.start()

    def update(self, percent: int):
        with self._lock:
            self._pct = max(0, min(100, int(percent)))

    def finish(self, percent: int = 100):
        with self._lock:
            self._pct = max(0, min(100, int(percent)))
        self._stop.set()
        if hasattr(self, "_bump_thread"):
            self._bump_thread.join(timeout=0.5)
        self._thread.join(timeout=0.5)
        sys.stdout.write(f"\r{self.msg} ✓ {self._pct:3d}%\n")
        sys.stdout.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        # If not finished explicitly, finish with current pct (or 100 on error)
        if exc_type is None:
            self.finish(100)
        else:
            self.finish(self._pct)
