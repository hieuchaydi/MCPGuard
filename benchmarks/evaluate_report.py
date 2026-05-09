from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _rules_by_tool(report: dict[str, Any]) -> dict[str, set[str]]:
    observed: dict[str, set[str]] = {}
    for tool in report.get("tools", []):
        name = tool.get("name")
        if not name:
            continue
        observed[name] = {finding["rule"] for finding in tool.get("findings", [])}
    return observed


def evaluate(report_path: Path, expected_path: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    observed = _rules_by_tool(report)

    expected_count = 0
    matched_count = 0
    missing: list[dict[str, str]] = []

    for item in expected.get("expected_findings", []):
        tool_name = item["tool_name"]
        observed_rules = observed.get(tool_name, set())
        for rule in item.get("rules", []):
            expected_count += 1
            if rule in observed_rules:
                matched_count += 1
            else:
                missing.append({"tool_name": tool_name, "rule": rule})

    detection_rate = matched_count / expected_count if expected_count else 1.0
    return {
        "status": "pass" if not missing else "fail",
        "expected": expected_count,
        "matched": matched_count,
        "detection_rate": round(detection_rate, 4),
        "missing": missing,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate an MCPGuard JSON report against expected detections.")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    args = parser.parse_args()

    result = evaluate(args.report, args.expected)
    print(json.dumps(result, indent=2))
    if result["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
