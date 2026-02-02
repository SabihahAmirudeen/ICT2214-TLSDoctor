import argparse
import json
from pathlib import Path

from .models import Target, Finding, Status, Severity
from .utils import normalize_url, get_host, to_https, to_http
from .testssl_engine import run_testssl
from .testssl_parse import parse_testssl_to_findings
from .checks.mixed_content import scan_mixed_content
from .http_client import get_text
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


def mixed_hit_to_finding(hit) -> Finding:
    # hit is MixedContentHit from checks/mixed_content.py
    return Finding(
        check_id="mixed_content",
        status=Status.FAIL,
        severity=Severity.HIGH if hit.severity == "HIGH" else Severity.MEDIUM,
        summary=f"Mixed content detected: {hit.resource_type} loaded over HTTP",
        evidence={
            "resource_url": hit.url,
            "resource_type": hit.resource_type,
            "active": hit.is_active,
            "evidence": hit.evidence,
        },
        fix=(
            "Serve the resource over HTTPS, or use a relative/https:// URL. "
            "Ensure all third-party assets support HTTPS."
        ),
        refs=["OWASP A04:2025"]
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

        # Phase 5: Browser Integrity (Static) - Mixed Content
    try:
        html = get_text(target.https_url)
        hits = scan_mixed_content(
            base_url=target.https_url,
            html=html,
            http_get_text=get_text,  # enables external CSS scanning
        )
        for h in hits:
            findings.append(mixed_hit_to_finding(h))

        if not hits:
            findings.append(
                Finding(
                    check_id="mixed_content",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    summary="No mixed content detected (static scan).",
                    evidence={"scanned_url": target.https_url},
                    fix="No action required.",
                    refs=["OWASP A04:2025"]
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                check_id="mixed_content",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="Mixed content scan failed.",
                evidence={"error": str(e), "url": target.https_url},
                fix="Check if the site is reachable over HTTPS and requests is installed.",
                refs=["OWASP A04:2025"]
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
