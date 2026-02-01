from typing import Any, Dict, List
from pathlib import Path
import csv
import json

from .models import Finding, Severity, Status


def _severity_weight(sev: Severity) -> int:
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 3,
        Severity.HIGH: 6,
        Severity.CRITICAL: 10,
    }.get(sev, 1)


def _status_multiplier(status: Status) -> float:
    return {
        Status.PASS: 0.0,
        Status.INFO: 0.2,
        Status.WARN: 0.7,
        Status.FAIL: 1.0,
    }.get(status, 0.5)


def rate_findings(findings: List[Finding]) -> Dict[str, Any]:
    """Compute a numeric risk score (0-100) and risk level from findings.

    Returns a dict with `score`, `risk_level` and per-finding breakdown.
    """
    if not findings:
        return {"score": 0.0, "risk_level": "LOW", "by_finding": []}

    by_finding = []
    total_score = 0.0
    max_per_finding = 10.0  # severity weight max (10) * status mult (1)

    for f in findings:
        sw = _severity_weight(f.severity)
        sm = _status_multiplier(f.status)
        fs = sw * sm
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
    """Write the report to a CSV file.

    Columns: target_input, host, https_url, check_id, status, severity,
    summary, fix, refs (semicolon-separated), evidence (JSON), finding_score
    """
    p = Path(csv_path)
    if not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)

    # map check_id -> score from risk_summary
    score_map = {}
    rs = report.get("risk_summary", {})
    for item in rs.get("by_finding", []):
        score_map[item.get("check_id")] = item.get("score")

    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "target_input",
            "host",
            "https_url",
            "check_id",
            "status",
            "severity",
            "summary",
            "fix",
            "refs",
            "evidence",
            "finding_score",
        ])

        tgt = report.get("target", {})
        for f in report.get("findings", []):
            refs = ";".join(f.get("refs") or [])
            evidence = json.dumps(f.get("evidence") or {})
            score = score_map.get(f.get("check_id"))
            writer.writerow([
                tgt.get("input"),
                tgt.get("host"),
                tgt.get("https_url"),
                f.get("check_id"),
                f.get("status"),
                f.get("severity"),
                f.get("summary"),
                f.get("fix"),
                refs,
                evidence,
                score,
            ])
