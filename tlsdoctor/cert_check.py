import ssl
import socket
from datetime import datetime
from .models import Finding, Status, Severity


def check_certificate(hostname, port=443):
    findings = []
    cert_ok = True
    cert = None

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Expiry check
        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            if expiry < datetime.utcnow():
                cert_ok = False
                findings.append(
                    Finding(
                        check_id="certificate",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        summary="Expired TLS certificate",
                        evidence={"expiry": not_after},
                        fix="Renew the TLS certificate immediately.",
                        refs=["OWASP A04:2025"],
                    )
                )

        # Self-signed check
        issuer = cert.get("issuer")
        subject = cert.get("subject")
        if issuer == subject:
            cert_ok = False
            findings.append(
                Finding(
                    check_id="certificate",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    summary="Self-signed certificate detected",
                    evidence={"issuer": issuer},
                    fix="Use a certificate issued by a trusted Certificate Authority.",
                    refs=["OWASP A04:2025"],
                )
            )

    except ssl.CertificateError as e:
        cert_ok = False
        findings.append(
            Finding(
                check_id="certificate",
                status=Status.FAIL,
                severity=Severity.HIGH,
                summary="Certificate hostname mismatch",
                evidence={"error": str(e)},
                fix="Ensure the certificate matches the requested hostname.",
                refs=["OWASP A04:2025"],
            )
        )

    except Exception as e:
        cert_ok = False
        findings.append(
            Finding(
                check_id="certificate",
                status=Status.FAIL,
                severity=Severity.HIGH,
                summary="TLS certificate validation failed",
                evidence={"error": str(e)},
                fix="Investigate TLS configuration and certificate chain.",
                refs=["OWASP A04:2025"],
            )
        )

    # PASS only if everything is valid
    if cert_ok and cert is not None:
        findings.append(
            Finding(
                check_id="certificate",
                status=Status.PASS,
                severity=Severity.LOW,
                summary="TLS certificate is valid and trusted",
                evidence={
                    "hostname": hostname,
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject"),
                    "not_after": cert.get("notAfter"),
                },
                fix="No action required.",
                refs=["OWASP A04:2025"],
            )
        )

    return findings
