from .models import Finding, Status, Severity

DEPRECATED_TLS = ["TLSv1", "TLSv1_1"]


def check_tls_versions(tls_support: dict):
    findings = []

    # FAIL if deprecated TLS versions are enabled
    for version in DEPRECATED_TLS:
        if tls_support.get(version):
            findings.append(
                Finding(
                    check_id="tls_versions",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    summary=f"Deprecated TLS version enabled: {version}",
                    evidence={version: "enabled"},
                    fix="Disable deprecated TLS versions and enforce TLS 1.2 or TLS 1.3 only.",
                    refs=["OWASP A04:2025"],
                )
            )

    # PASS if only modern TLS versions are enabled
    if not any(tls_support.get(v) for v in DEPRECATED_TLS):
        strongest = "TLS 1.2"
        if tls_support.get("TLSv1_3"):
            strongest = "TLS 1.3"

        findings.append(
            Finding(
                check_id="tls_versions",
                status=Status.PASS,
                severity=Severity.LOW,
                summary=f"Only modern TLS versions are enabled ({strongest})",
                evidence=tls_support,
                fix="No action required.",
                refs=["OWASP A04:2025"],
            )
        )

    return findings
