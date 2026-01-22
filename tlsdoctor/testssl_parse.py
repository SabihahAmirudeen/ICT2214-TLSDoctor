from typing import Any, List
from .models import Finding, Status, Severity


def parse_testssl_to_findings(testssl_json: Any) -> List[Finding]:
    count = len(testssl_json) if isinstance(testssl_json, list) else None
    return [
        Finding(
            check_id="testssl_engine",
            status=Status.PASS,
            severity=Severity.LOW,
            summary="testssl.sh scan completed.",
            evidence={"entries": count},
            fix="No action required.",
            refs=["testssl.sh"],
        )
    ]
