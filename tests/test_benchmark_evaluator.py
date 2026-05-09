from __future__ import annotations

import json

from benchmarks.evaluate_report import evaluate


def test_evaluate_report_matches_expected_findings(tmp_path):
    report_path = tmp_path / "report.json"
    expected_path = tmp_path / "expected.json"
    report_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "tool",
                        "findings": [
                            {"rule": "secret_leaked"},
                            {"rule": "prompt_injection_in_output"},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    expected_path.write_text(
        json.dumps(
            {
                "expected_findings": [
                    {
                        "tool_name": "tool",
                        "rules": ["secret_leaked", "prompt_injection_in_output"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = evaluate(report_path, expected_path)

    assert result["status"] == "pass"
    assert result["detection_rate"] == 1.0
