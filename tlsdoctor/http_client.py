import requests
import certifi

def get_text(url: str, timeout: int = 10) -> str:
    r = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={
            "User-Agent": "TLSDoctor/0.1"
        },
        verify=certifi.where()   # ✅ FIX: use certifi CA bundle
    )
    r.raise_for_status()
    return r.text