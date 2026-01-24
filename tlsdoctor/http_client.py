import requests

def get_text(url: str, timeout: int = 10) -> str:
    r = requests.get(url, timeout=timeout, allow_redirects=True, headers={
        "User-Agent": "TLSDoctor/0.1"
    })
    r.raise_for_status()
    return r.text