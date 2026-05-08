from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SchemaPolicy(BaseModel):
    require_input_schema: bool = True
    require_descriptions: bool = True
    require_required_fields: bool = True
    require_max_for_numbers: bool = True
    min_description_length: int = 10


class TimeoutPolicy(BaseModel):
    timeout_ms: int = 10000
    warn_after_ms: int = 3000


class SecretPolicy(BaseModel):
    enabled: bool = True
    patterns: list[str] = Field(
        default_factory=lambda: [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GROQ_API_KEY",
            "GEMINI_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            r"sk-[A-Za-z0-9]{20,}",
            r"ghp_[A-Za-z0-9]{36}",
            r"xoxb-[0-9]",
            "PRIVATE KEY",
            "password=",
            "token=",
            "secret=",
        ]
    )


class ToolPolicy(BaseModel):
    allow_paths: list[str] = Field(default_factory=list)
    deny_paths: list[str] = Field(default_factory=list)
    network: bool | None = None


class PromptInjectionPolicy(BaseModel):
    enabled: bool = True
    scan_description: bool = True
    scan_output: bool = True


class ChecksPolicy(BaseModel):
    prompt_injection: PromptInjectionPolicy = Field(default_factory=PromptInjectionPolicy)


class MCPGuardConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    server_command: str = ""
    fail_on: str = "high"
    schema_policy: SchemaPolicy = Field(default_factory=SchemaPolicy, alias="schema")
    timeout_policy: TimeoutPolicy = Field(default_factory=TimeoutPolicy, alias="timeout")
    secret_policy: SecretPolicy = Field(default_factory=SecretPolicy, alias="secret")
    tools_policy: dict[str, ToolPolicy] = Field(default_factory=dict, alias="tools")
    checks_policy: ChecksPolicy = Field(default_factory=ChecksPolicy, alias="checks")

    @field_validator("fail_on")
    @classmethod
    def _validate_fail_on(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"low", "medium", "high", "critical"}:
            raise ValueError("fail_on must be one of: low, medium, high, critical")
        return normalized

    @property
    def schema(self) -> SchemaPolicy:
        return self.schema_policy

    @property
    def timeout(self) -> TimeoutPolicy:
        return self.timeout_policy

    @property
    def secret(self) -> SecretPolicy:
        return self.secret_policy

    @property
    def tools(self) -> dict[str, ToolPolicy]:
        return self.tools_policy

    def tool_policy(self, tool_name: str) -> ToolPolicy | None:
        return self.tools.get(tool_name)

    @property
    def checks(self) -> ChecksPolicy:
        return self.checks_policy


def _load_yaml(config_file: Path) -> dict[str, Any]:
    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_file}")
    with config_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must be a mapping: {config_file}")
    return data


def load_config(
    config_file: Path | None = None,
    command_override: str | None = None,
    fail_on_override: str | None = None,
) -> MCPGuardConfig:
    raw: dict[str, Any] = {}
    if config_file is not None:
        raw = _load_yaml(config_file)

    payload: dict[str, Any] = {
        "server_command": raw.get("server", {}).get("command", ""),
        "fail_on": raw.get("policy", {}).get("fail_on", "high"),
        "schema": raw.get("schema", {}),
        "timeout": raw.get("timeout", {}),
        "secret": raw.get("secret", {}),
        "tools": raw.get("tools", {}),
        "checks": raw.get("checks", {}),
    }

    if command_override is not None:
        payload["server_command"] = command_override
    if fail_on_override is not None:
        payload["fail_on"] = fail_on_override

    return MCPGuardConfig.model_validate(payload)
