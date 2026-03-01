from typing import Any, Dict, List
from pathlib import Path
import csv
import json

from .models import Finding, Severity, Status


def _impact_score(sev: Severity) -> float:
    return {
        Severity.LOW: 2.0,
        Severity.MEDIUM: 5.0,
        Severity.HIGH: 8.0,
        Severity.CRITICAL: 10.0,
    }.get(sev, 2.0)


def _likelihood_score(status: Status) -> float:
    return {
        Status.PASS: 0.0,
        Status.INFO: 2.0,
        Status.WARN: 5.0,
        Status.FAIL: 8.0,
    }.get(status, 5.0)


def rate_findings(findings: List[Finding]) -> Dict[str, Any]:
    """Compute a numeric risk score (0-100) and risk level from findings.

    Returns a dict with `score`, `risk_level` and per-finding breakdown.
    """
    if not findings:
        return {"score": 0.0, "risk_level": "LOW", "by_finding": []}

    by_finding = []
    total_score = 0.0
    max_per_finding = 10.0 * 8.0  # max impact (10) × max likelihood (8)
    
    for f in findings:
        impact = _impact_score(f.severity)
        likelihood = _likelihood_score(f.status)
        fs = impact * likelihood
        total_score += fs
        by_finding.append(
            {
                "check_id": f.check_id,
                "severity": f.severity.value,
                "status": f.status.value,
                "summary": f.summary,
                "score": round(fs, 2),
            }
        )

    max_total = len(findings) * max_per_finding
    normalized = (total_score / max_total) * 100.0 if max_total > 0 else 0.0
    score = round(normalized, 2)

    if score <= 10:
        level = "LOW"
    elif score <= 40:
        level = "MEDIUM"
    elif score <= 70:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {"score": score, "risk_level": level, "by_finding": by_finding}


def generate_report(target: Dict[str, Any], findings: List[Finding]) -> Dict[str, Any]:
    report = {
        "target": target,
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

    risk = rate_findings(findings)
    report["risk_summary"] = risk
    return report


def write_csv(report: Dict[str, Any], csv_path: str) -> None:
    """
    Write a single CSV containing:
    1) Summary section (top)
    2) Blank row
    3) Detailed findings section
    """

    p = Path(csv_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    tgt = report.get("target", {})
    rs = report.get("risk_summary", {})
    findings = report.get("findings", [])

    # Build score lookup
    score_map = {
        item["check_id"]: item["score"]
        for item in rs.get("by_finding", [])
    }

    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)

        # =============================
        # SUMMARY SECTION
        # =============================
        writer.writerow(["=== TLSDoctor Scan Summary ==="])
        writer.writerow(["Target Input", tgt.get("input")])
        writer.writerow(["Host", tgt.get("host")])
        writer.writerow(["HTTPS URL", tgt.get("https_url")])
        writer.writerow(["Overall Risk Score", rs.get("score")])
        writer.writerow(["Overall Risk Level", rs.get("risk_level")])
        writer.writerow(["Total Findings", len(findings)])

        statuses = [f["status"] for f in findings]
        writer.writerow(["PASS Count", statuses.count("PASS")])
        writer.writerow(["WARN Count", statuses.count("WARN")])
        writer.writerow(["FAIL Count", statuses.count("FAIL")])

        # Blank separator row
        writer.writerow([])
        writer.writerow(["=== Detailed Findings ==="])

        # =============================
        # FINDINGS TABLE HEADER
        # =============================
        writer.writerow([
            "check_id",
            "status",
            "severity",
            "summary",
            "fix",
            "refs",
            "evidence_json",
            "finding_score",
        ])

        # =============================
        # FINDINGS ROWS
        # =============================
        for f in findings:
            writer.writerow([
                f.get("check_id"),
                f.get("status"),
                f.get("severity"),
                f.get("summary"),
                f.get("fix"),
                json.dumps(f.get("refs") or []),
                json.dumps(f.get("evidence") or {}, ensure_ascii=False),
                score_map.get(f.get("check_id")),
            ])