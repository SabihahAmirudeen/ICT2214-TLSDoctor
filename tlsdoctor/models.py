from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, List


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Target:
    input_url: str
    host: str
    https_url: str
    http_url: str


@dataclass
class Finding:
    check_id: str
    status: Status
    severity: Severity
    summary: str
    evidence: Dict[str, Any]
    fix: str
    refs: Optional[List[str]] = None
