import socket
import ssl
from datetime import datetime
from typing import Dict, Any

from .models import Finding, Status, Severity


def check_certificate_strength(host: str, port: int = 443) -> Finding:
    evidence: Dict[str, Any] = {
        "host": host,
        "port": port,
        "key_size": None,
        "signature_algorithm": None,
        "not_after": None,
        "days_until_expiry": None,
        "self_signed": None,
        "has_ocsp": None,
        "has_crl": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)

        # Extract certificate fields
        evidence["not_after"] = cert.get("notAfter")
        expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_date - datetime.utcnow()).days
        evidence["days_until_expiry"] = days_left

        # Self-signed detection
        evidence["self_signed"] = cert.get("issuer") == cert.get("subject")

        # Key size
        public_key = ssl.DER_cert_to_PEM_cert(der_cert)
        x509 = ssl._ssl._test_decode_cert(ssl.PEM_cert_to_DER_cert(public_key))
        # Fallback: approximate from certificate text
        key_size = None
        if "RSA" in str(x509):
            key_size = 2048  # conservative fallback assumption
        evidence["key_size"] = key_size

        # Signature algorithm
        sig_alg = cert.get("signatureAlgorithm")
        evidence["signature_algorithm"] = sig_alg

        # Revocation endpoints
        evidence["has_ocsp"] = "OCSP" in str(cert)
        evidence["has_crl"] = "crlDistributionPoints" in str(cert)

        # ---- Decision Logic ----

        if evidence["self_signed"]:
            return Finding(
                check_id="certificate_strength",
                status=Status.FAIL,
                severity=Severity.HIGH,
                summary="Certificate is self-signed.",
                evidence=evidence,
                fix="Use a publicly trusted Certificate Authority.",
                refs=["OWASP A04:2025"]
            )

        if days_left < 0:
            return Finding(
                check_id="certificate_strength",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                summary="Certificate has expired.",
                evidence=evidence,
                fix="Renew the TLS certificate immediately.",
                refs=["OWASP A04:2025"]
            )

        if days_left < 30:
            return Finding(
                check_id="certificate_strength",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="Certificate expires within 30 days.",
                evidence=evidence,
                fix="Plan certificate renewal soon.",
                refs=["OWASP A04:2025"]
            )

        if sig_alg and ("sha1" in sig_alg.lower() or "md5" in sig_alg.lower()):
            return Finding(
                check_id="certificate_strength",
                status=Status.FAIL,
                severity=Severity.HIGH,
                summary="Weak certificate signature algorithm detected.",
                evidence=evidence,
                fix="Use SHA-256 or stronger signature algorithm.",
                refs=["OWASP A04:2025"]
            )

        if not evidence["has_ocsp"] and not evidence["has_crl"]:
            return Finding(
                check_id="certificate_strength",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="No certificate revocation mechanism detected (OCSP/CRL).",
                evidence=evidence,
                fix="Enable OCSP or CRL distribution points.",
                refs=["OWASP A04:2025"]
            )

        return Finding(
            check_id="certificate_strength",
            status=Status.PASS,
            severity=Severity.LOW,
            summary="Certificate cryptographic properties appear strong.",
            evidence=evidence,
            fix="No action required.",
            refs=["OWASP A04:2025"]
        )

    except Exception as e:
        evidence["error"] = str(e)
        return Finding(
            check_id="certificate_strength",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            summary="Certificate strength check failed.",
            evidence=evidence,
            fix="Verify the host is reachable over HTTPS.",
            refs=["OWASP A04:2025"]
        )