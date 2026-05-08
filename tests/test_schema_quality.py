from __future__ import annotations

from types import SimpleNamespace

from mcpguard.config import SchemaPolicy
from mcpguard.checks.schema_quality import check_schema_quality


def test_schema_quality_passes_for_strict_schema(make_tool):
    tool = make_tool()
    findings = check_schema_quality(tool, SchemaPolicy())
    assert findings == []


def test_schema_quality_reports_missing_description_and_schema(make_tool):
    tool = SimpleNamespace(name="tool", description="")
    findings = check_schema_quality(tool, SchemaPolicy())
    rules = {f.rule for f in findings}
    assert "missing_description" in rules
    assert "missing_input_schema" in rules


def test_schema_quality_reports_missing_required(make_tool):
    schema = {
        "type": "object",
        "properties": {"query": {"type": "string", "maxLength": 100}},
        "additionalProperties": False,
    }
    tool = make_tool(input_schema=schema)
    findings = check_schema_quality(tool, SchemaPolicy())
    assert any(f.rule == "missing_required_declaration" for f in findings)


def test_schema_quality_reports_numeric_and_string_bounds(make_tool):
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        },
        "required": ["query"],
        "additionalProperties": False,
    }
    tool = make_tool(input_schema=schema)
    findings = check_schema_quality(tool, SchemaPolicy())
    rules = {f.rule for f in findings}
    assert "string_missing_maxlength" in rules
    assert "number_missing_maximum" in rules
    assert "number_missing_minimum" in rules
    assert "bounded_field_missing_maximum" in rules


def test_schema_quality_reports_additional_properties(make_tool):
    schema = {
        "type": "object",
        "properties": {"query": {"type": "string", "maxLength": 100}},
        "required": ["query"],
        "additionalProperties": True,
    }
    tool = make_tool(input_schema=schema)
    findings = check_schema_quality(tool, SchemaPolicy())
    assert any(f.rule == "allows_additional_properties" for f in findings)
