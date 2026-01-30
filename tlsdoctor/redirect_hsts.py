import json
from pathlib import Path
from .models import Finding, Status, Severity

project_root = Path(__file__).resolve().parents[1] 
path = project_root / "tlsdoctor" / "data" / "testssl_output.json"

def load_testssl_results(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
    
def extract_hsts(results):
    hsts = {
        "present": False,
        "max_age": None,
        "include_subdomains": False,
        "preload": False
    }

    for item in results:
        if item.get("id") in ("HSTS_time", "HSTS_subdomains"):
            hsts["present"] = True


        if item.get("id") == "HSTS_time":
            # Extract seconds if present
            finding = item.get("finding", "")
            if "seconds" in finding:
                try:
                    hsts["max_age"] = int(finding.split("=")[1].split()[0])
                except:
                    pass

        if item.get("id") == "HSTS_subdomains":
            if "includes subdomains" in item.get("finding", "").lower():
                hsts["include_subdomains"] = True

        if item.get("id") == "HSTS_preload":
            finding = item.get("finding", "").lower()
            if "preload" in finding and "not" not in finding:
                hsts["preload"] = True

    return hsts

def extract_redirect(results):
    redirect = {
        "http_to_https": False,
        "status_code": None
    }

    for item in results:
        if item.get("id") == "HTTP_status_code":
            finding = item.get("finding", "").lower()
            redirect["status_code"] = finding

            # testssl prints redirect info elsewhere, but HTTPS status implies redirect
            if "301" in finding or "302" in finding:
                redirect["http_to_https"] = True

    return redirect

def evaluate_transport_policy(redirect, hsts):
    findings = []

    # HTTP → HTTPS
    if not redirect["http_to_https"]:
        findings.append(
            Finding(
                check_id="http_to_https_redirect",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                summary="HTTP does not redirect to HTTPS",
                evidence=redirect,
                fix="Configure the server to redirect all HTTP traffic to HTTPS.",
                refs="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
            )
        )
    else:
        findings.append(
            Finding(
                check_id="http_to_https_redirect",
                status=Status.PASS,
                severity=Severity.LOW,
                summary="HTTP redirects to HTTPS",
                evidence=redirect,
                fix="No action required.",
                refs="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
            )
        )

    # HSTS missing
    if not hsts["present"]:
        findings.append(
            Finding(
                check_id="hsts",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="HSTS is not enabled",
                evidence=hsts,
                fix="Enable HSTS with max-age more than or equal to 31536000 and includeSubDomains.",
                refs="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
            )
        )
        return findings  
    else:
        findings.append(
            Finding(
                check_id="hsts",
                status=Status.PASS,
                severity=Severity.LOW,
                summary="HSTS is enabled",
                evidence=hsts,
                fix="No action required.",
                refs="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
            )
        )
        
    # HSTS max-age
    one_year = 31536000
    if not hsts["max_age"] or hsts["max_age"] < one_year:
        findings.append(
            Finding(
                check_id="hsts_max_age",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="HSTS max-age is less than 1 year",
                evidence=hsts,
                fix="Increase HSTS max-age to at least 31536000 seconds.",
                refs="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
            )
        )
   
    # HSTS includeSubDomains
    if not hsts["include_subdomains"]:
        findings.append(
            Finding(
                check_id="hsts_include_subdomains",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="HSTS includeSubDomains directive is missing",
                evidence=hsts,
                fix="Add includeSubDomains to the HSTS policy.",
                refs="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
            )
        )

    # Preload evaluation (ONLY if enabled)
    if hsts["preload"]:
        preload_issues = []

        if not hsts["include_subdomains"]:
            preload_issues.append("includeSubDomains is required for preload")

        if not hsts["max_age"] or hsts["max_age"] < one_year:
            preload_issues.append("max-age must be at least 31536000 seconds for preload")

        if preload_issues:
            findings.append(
                Finding(
                    check_id="hsts_preload_misconfig",
                    status=Status.WARN,
                    severity=Severity.MEDIUM,
                    summary="HSTS preload is enabled but configuration is unsafe",
                    evidence={
                        "hsts": hsts,
                        "issues": preload_issues
                    },
                    fix=(
                        "Ensure max-age ≥ 31536000 and includeSubDomains are set "
                        "before using the preload directive. "
                        "Misconfigured preload can permanently break site access."
                    ),
                    refs="https://hstspreload.org/"
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="hsts_preload",
                    status=Status.INFO,
                    severity=Severity.LOW,
                    summary="HSTS preload directive is enabled",
                    evidence=hsts,
                    fix=(
                        "No action required. Ensure all present and future subdomains "
                        "support HTTPS before remaining on the preload list."
                    ),
                    refs="https://hstspreload.org/"
                )
            )

    return findings


def analyze_domain(json_path):
    results = load_testssl_results(json_path)
    redirect = extract_redirect(results)
    hsts = extract_hsts(results)

    return evaluate_transport_policy(redirect, hsts)

