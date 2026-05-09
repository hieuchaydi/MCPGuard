from enum import Enum

from pydantic import BaseModel, Field

from mcpguard.risk import (
    risk_level_from_findings,
    risk_score_from_findings,
    severity_counts,
    trust_classification,
)


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
    def highest_severity(self) -> str:
        return risk_level_from_findings(self.findings)

    @property
    def risk_score(self) -> int:
        return risk_score_from_findings(self.findings)

    @property
    def trust_classification(self) -> str:
        return trust_classification(self.risk_score)

    @property
    def status(self) -> str:
        return "pass" if not self.findings else "fail"


class Report(BaseModel):
    server_command: str
    tools: list[ToolReport] = Field(default_factory=list)

    @property
    def score(self) -> int:
        total_risk = self.risk_score
        return max(0, 100 - total_risk)

    @property
    def status(self) -> str:
        return "pass" if not self.all_findings else "fail"

    @property
    def all_findings(self) -> list[Finding]:
        return [f for t in self.tools for f in t.findings]

    @property
    def risk_score(self) -> int:
        return risk_score_from_findings(self.all_findings)

    @property
    def overall_risk_level(self) -> str:
        return risk_level_from_findings(self.all_findings)

    @property
    def trust_classification(self) -> str:
        return trust_classification(self.risk_score)

    @property
    def severity_summary(self) -> dict[str, int]:
        return severity_counts(self.all_findings)
