import argparse
import json

from .models import Target
from .utils import normalize_url, get_host, to_https, to_http


def build_target(input_url: str) -> Target:
    norm = normalize_url(input_url)
    host = get_host(norm)
    return Target(
        input_url=input_url,
        host=host,
        https_url=to_https(norm),
        http_url=to_http(norm),
    )


def main():
    parser = argparse.ArgumentParser(description="TLSDoctor (baseline)")
    parser.add_argument("url", help="Target URL or hostname")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    args = parser.parse_args()

    target = build_target(args.url)

    report = {
        "target": {
            "input": target.input_url,
            "host": target.host,
            "https_url": target.https_url,
            "http_url": target.http_url,
        }
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("TLSDoctor target:")
        for k, v in report["target"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
