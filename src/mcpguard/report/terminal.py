from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpguard.models import Report, ToolReport
from mcpguard.risk import recommendation_for_rule, severity_counts, summarize_tool

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "dark_orange3",
    "medium": "yellow",
    "low": "blue",
}

STATUS_STYLE = {
    "pass": "green",
    "fail": "red",
}


def _tool_sort_key(tool: ToolReport) -> tuple[int, str]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    level = tool.highest_severity
    return order.get(level, 4), tool.tool_name


def _print_summary(report: Report, console: Console) -> None:
    counts = severity_counts(report.all_findings)
    summary = Table.grid(padding=(0, 2))
    summary.add_row("Status", f"[{STATUS_STYLE[report.status]}]{report.status.upper()}[/{STATUS_STYLE[report.status]}]")
    summary.add_row("Overall Risk", f"[{SEVERITY_STYLE[report.overall_risk_level]}]{report.overall_risk_level.upper()}[/{SEVERITY_STYLE[report.overall_risk_level]}]")
    summary.add_row("Risk Score", str(report.risk_score))
    summary.add_row("Tools Tested", str(len(report.tools)))
    summary.add_row("Findings", str(len(report.all_findings)))
    summary.add_row("Critical", str(counts["critical"]))
    summary.add_row("High", str(counts["high"]))
    summary.add_row("Medium", str(counts["medium"]))
    summary.add_row("Low", str(counts["low"]))
    console.print(summary)


def print_terminal_report(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    console.print(
        Panel(
            f"Target: {report.server_command}\nTools: {len(report.tools)} discovered",
            title="MCPGuard Report",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    _print_summary(report, console)
    console.rule("Tool Findings")

    for tool in sorted(report.tools, key=_tool_sort_key):
        summary = summarize_tool(tool.tool_name, tool.findings)
        risk_style = SEVERITY_STYLE[summary["risk_level"]]
        status_style = STATUS_STYLE[summary["status"]]
        console.print(
            f"[{status_style}]{summary['status'].upper()}[/{status_style}] "
            f"{summary['name']} "
            f"risk=[{risk_style}]{summary['risk_level'].upper()}[/{risk_style}] "
            f"score={summary['risk_score']}"
        )
        for finding in summary["findings"]:
            sev = finding["severity"]
            sev_style = SEVERITY_STYLE[sev]
            console.print(
                f"  [{sev_style}][{sev.upper()}][/{sev_style}] "
                f"{finding['rule']}: {finding['message']}"
            )
        if not summary["findings"]:
            console.print("  [green]No findings[/green]")
        console.print()

    recommendations: list[str] = []
    seen_rules: set[str] = set()
    for finding in report.all_findings:
        if finding.rule in seen_rules:
            continue
        seen_rules.add(finding.rule)
        recommendations.append(recommendation_for_rule(finding.rule))

    if recommendations:
        console.rule("Recommendations")
        for line in recommendations:
            console.print(f"- {line}")
