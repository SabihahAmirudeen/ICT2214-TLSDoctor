



import socket
import ssl
from datetime import datetime
from typing import Dict, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

from .models import Finding, Status, Severity


def check_certificate_strength(host: str, port: int = 443) -> Finding:
    evidence: Dict[str, Any] = {"host": host, "port": port}

    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # -------- Public Key --------
        pubkey = cert.public_key()

        if isinstance(pubkey, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
            key_size = pubkey.key_size
        else:
            key_type = type(pubkey).__name__
            key_size = None

        evidence["key_type"] = key_type
        evidence["key_size"] = key_size

        # -------- Signature Algorithm --------
        sig_alg = cert.signature_hash_algorithm
        sig_name = sig_alg.name if sig_alg else "Unknown"
        evidence["signature_algorithm"] = sig_name

        # -------- Expiry --------
        not_after = cert.not_valid_after
        days_left = (not_after - datetime.utcnow()).days
        evidence["not_after"] = str(not_after)
        evidence["days_until_expiry"] = days_left

        # -------- Self-Signed --------
        evidence["self_signed"] = cert.issuer == cert.subject

        # -------- Revocation Extensions --------
        try:
            cert.extensions.get_extension_for_class(x509.OCSPNoCheck)
            evidence["has_ocsp"] = True
        except Exception:
            evidence["has_ocsp"] = False

        try:
            cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            evidence["has_crl"] = True
        except Exception:
            evidence["has_crl"] = False

        # ==============================
        # DECISION LOGIC
        # ==============================

        if evidence["self_signed"]:
            return Finding(
                check_id="certificate_strength",
                status=Status.FAIL,
                severity=Severity.HIGH,
                summary="Certificate is self-signed.",
                evidence=evidence,
                fix="Use a publicly trusted Certificate Authority.",
                refs=["OWASP A04:2025"],
            )

        if days_left < 0:
            return Finding(
                check_id="certificate_strength",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                summary="Certificate has expired.",
                evidence=evidence,
                fix="Renew the TLS certificate immediately.",
                refs=["OWASP A04:2025"],
            )

        if key_type == "RSA" and key_size and key_size < 2048:
            return Finding(
                check_id="certificate_strength",
                status=Status.FAIL,
                severity=Severity.HIGH,
                summary="Weak RSA key size detected (<2048 bits).",
                evidence=evidence,
                fix="Use RSA key size >= 2048 bits.",
                refs=["OWASP A04:2025"],
            )

        if sig_name.lower() in ["md5", "sha1"]:
            return Finding(
                check_id="certificate_strength",
                status=Status.FAIL,
                severity=Severity.HIGH,
                summary="Weak certificate signature algorithm detected.",
                evidence=evidence,
                fix="Use SHA-256 or stronger signature algorithm.",
                refs=["OWASP A04:2025"],
            )

        if days_left < 30:
            return Finding(
                check_id="certificate_strength",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                summary="Certificate expires within 30 days.",
                evidence=evidence,
                fix="Plan certificate renewal soon.",
                refs=["OWASP A04:2025"],
            )

        return Finding(
            check_id="certificate_strength",
            status=Status.PASS,
            severity=Severity.LOW,
            summary="Certificate cryptographic properties appear strong.",
            evidence=evidence,
            fix="No action required.",
            refs=["OWASP A04:2025"],
        )

    except Exception as e:
        evidence["error"] = str(e)
        return Finding(
            check_id="certificate_strength",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            summary="Certificate strength check failed.",
            evidence=evidence,
            fix="Verify host connectivity and TLS availability.",
            refs=["OWASP A04:2025"],
        )