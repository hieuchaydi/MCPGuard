from __future__ import annotations

from typing import Any

from mcpguard.checks.fuzz_inputs import check_fuzz_inputs
from mcpguard.checks.schema_quality import check_schema_quality
from mcpguard.checks.timeout_check import check_timeout
from mcpguard.client import connect, discover_tools
from mcpguard.config import MCPGuardConfig
from mcpguard.models import Finding, Report, Severity, ToolReport


def _tool_name(tool: Any) -> str:
    return getattr(tool, "name", None) or "<unknown>"


def _warning_report(message: str, rule: str) -> ToolReport:
    tool_name = "__server__"
    return ToolReport(
        tool_name=tool_name,
        findings=[
            Finding(
                tool_name=tool_name,
                severity=Severity.WARNING,
                rule=rule,
                message=message,
            )
        ],
    )


async def run(config: MCPGuardConfig, only_tool: str | None = None) -> Report:
    report = Report(server_command=config.server_command)

    async with connect(config.server_command) as client:
        tools = await discover_tools(client, timeout_seconds=5.0)

        if only_tool:
            tools = [tool for tool in tools if _tool_name(tool) == only_tool]
            if not tools:
                report.tools.append(
                    _warning_report(
                        message=f"Requested tool '{only_tool}' was not found on server.",
                        rule="tool_not_found",
                    )
                )
                return report

        if not tools:
            report.tools.append(
                _warning_report(
                    message="Server returned an empty tool list.",
                    rule="no_tools_discovered",
                )
            )
            return report

        for tool in tools:
            tool_report = ToolReport(tool_name=_tool_name(tool))
            tool_report.findings.extend(check_schema_quality(tool, config.schema))
            tool_report.findings.extend(await check_timeout(tool, client, config.timeout))
            tool_report.findings.extend(await check_fuzz_inputs(tool, client, config))
            report.tools.append(tool_report)

    return report
