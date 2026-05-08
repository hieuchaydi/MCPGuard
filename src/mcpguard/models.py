from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    WARNING = "warning"


class Finding(BaseModel):
    tool_name: str
    severity: Severity
    rule: str
    message: str


class ToolReport(BaseModel):
    tool_name: str
    findings: list[Finding] = Field(default_factory=list)

    @property
    def highest_severity(self) -> Severity | None:
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.WARNING,
        ]
        for severity in order:
            if any(f.severity == severity for f in self.findings):
                return severity
        return None


class Report(BaseModel):
    server_command: str
    tools: list[ToolReport] = Field(default_factory=list)

    @property
    def score(self) -> int:
        deductions = sum(
            {
                Severity.CRITICAL: 25,
                Severity.HIGH: 12,
                Severity.MEDIUM: 6,
                Severity.LOW: 2,
                Severity.WARNING: 1,
            }[f.severity]
            for t in self.tools
            for f in t.findings
        )
        return max(0, 100 - deductions)

    @property
    def status(self) -> str:
        score = self.score
        if score >= 90:
            return "PASS"
        if score >= 70:
            return "WARN"
        if score >= 50:
            return "FAIL"
        return "CRITICAL"

    @property
    def all_findings(self) -> list[Finding]:
        return [f for t in self.tools for f in t.findings]
