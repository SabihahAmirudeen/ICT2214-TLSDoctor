import argparse
import json
from pathlib import Path

from .models import Target, Finding, Status, Severity
from .utils import normalize_url, get_host, to_https, to_http
from .testssl_engine import run_testssl
from .testssl_parse import parse_testssl_to_findings



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

    findings = []

    project_root = Path(__file__).resolve().parents[1]  # ICT2214-TLSDoctor/
    testssl_script = project_root / "testssl.sh" / "testssl.sh"
    out_json = project_root / "tlsdoctor" / "data" / "testssl_output.json"

    try:
        testssl_json = run_testssl(target.host, testssl_script, out_json)
        findings.extend(parse_testssl_to_findings(testssl_json))
    except Exception as e:
        findings.append(
            Finding(
                check_id="testssl_engine",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="testssl.sh execution failed.",
                evidence={"error": str(e), "testssl_script": str(testssl_script)},
                fix="Check testssl.sh path and dependencies (openssl/curl) in WSL."
            )
        )


    report = {
        "target": {
            "input": target.input_url,
            "host": target.host,
            "https_url": target.https_url,
            "http_url": target.http_url,
        },
        "findings": [
            {
                "check_id": f.check_id,
                "status": f.status.value,
                "severity": f.severity.value,
                "summary": f.summary,
                "evidence": f.evidence,
                "fix": f.fix,
                "refs": f.refs,
            }
            for f in findings
        ],
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"TLSDoctor scan for {target.host}\n")
        for f in findings:
            print(f"[{f.status.value}] {f.check_id} ({f.severity.value})")
            print(f"  {f.summary}")
            print(f"  Fix: {f.fix}\n")


if __name__ == "__main__":
    main()
