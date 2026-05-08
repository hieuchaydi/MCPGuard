from __future__ import annotations

from collections import Counter

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpguard.models import Report, Severity, ToolReport

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.WARNING: 4,
    None: 5,
}

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.WARNING: "dim",
}

STATUS_STYLE = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "dark_orange3",
    "CRITICAL": "red",
}

RECOMMENDATIONS = {
    "missing_tool_name": "Add explicit tool names for stable selection and auditing.",
    "missing_description": "Write clear tool descriptions to guide agent behavior.",
    "description_too_short": "Expand descriptions with intent, constraints, and safe usage.",
    "missing_input_schema": "Define a complete inputSchema for every tool.",
    "no_properties_defined": "Declare input properties with strict type constraints.",
    "missing_required_declaration": "Declare required fields in inputSchema.required.",
    "property_missing_type": "Add explicit type annotations for each input property.",
    "number_missing_maximum": "Set maximum bounds for numeric inputs.",
    "number_missing_minimum": "Set minimum bounds for numeric inputs.",
    "string_missing_maxlength": "Set maxLength for string inputs.",
    "bounded_field_missing_maximum": "Add maximum constraints to limit/count/page fields.",
    "allows_additional_properties": "Set additionalProperties to false.",
    "stack_trace_exposed": "Return sanitized errors without stack traces.",
    "fuzz_server_crash": "Handle malformed input defensively to prevent crashes.",
    "poor_error_message": "Return actionable validation errors for malformed input.",
    "secret_leaked": "Mask secrets and remove sensitive fields from outputs.",
    "timeout_exceeded": "Reduce latency or optimize tool execution path.",
    "slow_response": "Profile and optimize tool performance.",
    "fuzz_timeout": "Ensure invalid input fails fast with clear errors.",
    "path_outside_allowlist": "Restrict file access to explicit allow_paths.",
    "path_matches_denylist": "Block denied paths and return sanitized authorization errors.",
    "prompt_injection_in_description": "Remove instruction-like text from tool descriptions.",
    "prompt_injection_in_output": "Sanitize tool outputs to prevent instruction injection.",
    "no_tools_discovered": "Verify MCP server startup and tool registration.",
    "tool_not_found": "Check tool naming or remove incompatible --tool filter.",
}


def _supports_glyph(console: Console, text: str) -> bool:
    encoding = getattr(getattr(console, "file", None), "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


def _score_bar(score: int, width: int = 10, unicode_style: bool = True) -> str:
    filled = max(0, min(width, round((score / 100) * width)))
    if unicode_style:
        return ("█" * filled) + ("░" * (width - filled))
    return ("#" * filled) + ("-" * (width - filled))


def _sort_tools(tools: list[ToolReport]) -> list[ToolReport]:
    return sorted(
        tools,
        key=lambda t: (SEVERITY_ORDER.get(t.highest_severity, 5), t.tool_name),
    )


def _generate_recommendations(report: Report) -> list[str]:
    seen: set[str] = set()
    lines: list[str] = []
    for finding in report.all_findings:
        if finding.rule in seen:
            continue
        seen.add(finding.rule)
        lines.append(RECOMMENDATIONS.get(finding.rule, f"Investigate rule: {finding.rule}"))
    return lines


def print_terminal_report(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    tools = _sort_tools(report.tools)
    unicode_style = _supports_glyph(console, "█░─│┌")
    panel_box = box.ROUNDED if unicode_style else box.ASCII

    header = Text()
    header.append(f"Server: {report.server_command}\n")
    header.append(f"Tools:  {len(tools)} discovered")
    console.print(
        Panel(header, title="MCPGuard Report", border_style="cyan", box=panel_box)
    )

    status_style = STATUS_STYLE.get(report.status, "white")
    console.print(
        f"Score: {report.score}/100  {_score_bar(report.score, unicode_style=unicode_style)}  [{status_style}]{report.status}[/{status_style}]"
    )

    findings_by_sev = Counter(f.severity for f in report.all_findings)
    passed_tools = sum(1 for t in tools if not t.findings)
    failed_findings = (
        findings_by_sev[Severity.HIGH]
        + findings_by_sev[Severity.MEDIUM]
        + findings_by_sev[Severity.LOW]
    )
    summary = Table.grid(padding=(0, 2))
    summary.add_row("Passed", str(passed_tools))
    summary.add_row("Warnings", str(findings_by_sev[Severity.WARNING]))
    summary.add_row("Failed", str(failed_findings))
    summary.add_row("Critical", str(findings_by_sev[Severity.CRITICAL]))
    console.print()
    console.print(summary)
    console.rule(characters="-" if not unicode_style else "━")

    for tool_report in tools:
        if not tool_report.findings:
            console.print(f"[green]PASS[/green] {tool_report.tool_name}")
            continue

        highest = tool_report.highest_severity
        style = SEVERITY_STYLE.get(highest, "white")
        label = highest.value.upper() if highest else "UNKNOWN"
        console.print(f"[{style}]{label:<8}[/{style}] {tool_report.tool_name}")
        for finding in tool_report.findings:
            f_style = SEVERITY_STYLE.get(finding.severity, "white")
            bullet = "•" if unicode_style else "-"
            console.print(f"  [{f_style}]{bullet} {finding.rule}: {finding.message}[/{f_style}]")
        console.print()

    recommendations = _generate_recommendations(report)
    if recommendations:
        console.rule(characters="-" if not unicode_style else "━")
        console.print("[bold]Recommendations[/bold]")
        for line in recommendations:
            console.print(f"  -> {line}")
