import argparse
import json
from pathlib import Path

from .models import Target, Finding, Status, Severity
from .utils import normalize_url, get_host, to_https, to_http
from .testssl_engine import run_testssl
from .testssl_parse import parse_testssl_to_findings
from .sri_check import check_sri
from .redirect_hsts import analyze_domain
from .reporting import generate_report, write_csv


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
    parser.add_argument("--report", action="store_true", help="Write JSON report to tlsdoctor/data/report.json")
    parser.add_argument("--csv", help="Write CSV report to path (e.g. tlsdoctor/data/report.csv)")
    args = parser.parse_args()

    target = build_target(args.url)

    findings = []

    project_root = Path(__file__).resolve().parents[1]  # ICT2214-TLSDoctor/
    testssl_script = project_root / "testssl.sh" / "testssl.sh"
    out_json = project_root / "tlsdoctor" / "data" / "testssl_output.json"

    # 1) Transport-layer scan (testssl.sh)
    try:
        testssl_json = run_testssl(target.host, testssl_script, out_json)
        findings.extend(parse_testssl_to_findings(testssl_json))

        redirect_hsts = analyze_domain(out_json)
        findings.extend(redirect_hsts)

    except Exception as e:
        findings.append(
            Finding(
                check_id="testssl_engine",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="testssl.sh execution failed.",
                evidence={"error": str(e), "testssl_script": str(testssl_script)},
                fix="Check testssl.sh path and dependencies (openssl/curl/bc) in WSL.",
                refs=["testssl.sh"],
            )
        )

    # 2) Application/browser-side cryptographic integrity (SRI)
    try:
        findings.append(check_sri(target.https_url))
    except Exception as e:
        findings.append(
            Finding(
                check_id="sri_check",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="SRI check failed unexpectedly.",
                evidence={"error": str(e), "https_url": target.https_url},
                fix="Verify the HTTPS URL is reachable and returns HTML content.",
                refs=["W3C Subresource Integrity"],
            )
        )

    target_obj = {
        "input": target.input_url,
        "host": target.host,
        "https_url": target.https_url,
        "http_url": target.http_url,
    }

    report = generate_report(target_obj, findings)

    # Optionally write report JSON to disk
    project_root = Path(__file__).resolve().parents[1]
    report_file = project_root / "tlsdoctor" / "data" / "report.json"
    if args.report:
        with open(report_file, "w") as fh:
            json.dump(report, fh, indent=2)

    if args.csv:
        try:
            write_csv(report, args.csv)
        except Exception as e:
            print(f"Failed to write CSV to {args.csv}: {e}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"TLSDoctor scan for {target.host}\n")
        rs = report.get("risk_summary", {})
        print(f"Overall risk: {rs.get('risk_level')} ({rs.get('score')}%)\n")
        for f in findings:
            print(f"[{f.status.value}] {f.check_id} ({f.severity.value})")
            print(f"  {f.summary}")
            print(f"  Fix: {f.fix}\n")


if __name__ == "__main__":
    main()
