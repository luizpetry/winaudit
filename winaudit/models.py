"""Modelos de dados do WinAudit."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class Finding:
    id: str
    title: str
    status: Status
    severity: Severity = Severity.NONE
    details: str = ""
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    # o que pode acontecer se o problema nao for corrigido (ex.: riscos de manter uma versao)
    risks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d


@dataclass
class CheckResult:
    check: str
    category: str
    findings: list[Finding]
    duration_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "category": self.category,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


def passed(id: str, title: str, details: str = "") -> Finding:
    return Finding(id, title, Status.PASS, Severity.NONE, details)


def failed(id: str, title: str, severity: Severity, details: str, remediation: str,
           evidence: list[str] | None = None) -> Finding:
    return Finding(id, title, Status.FAIL, severity, details, remediation, evidence or [])


def warn(id: str, title: str, severity: Severity, details: str, remediation: str,
         evidence: list[str] | None = None) -> Finding:
    return Finding(id, title, Status.WARN, severity, details, remediation, evidence or [])


def info(id: str, title: str, details: str = "", evidence: list[str] | None = None) -> Finding:
    return Finding(id, title, Status.INFO, Severity.NONE, details, "", evidence or [])
