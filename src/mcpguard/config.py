from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SchemaPolicy(BaseModel):
    require_input_schema: bool = True
    require_descriptions: bool = True
    require_required_fields: bool = True
    require_max_for_numbers: bool = True
    min_description_length: int = 10

    @field_validator("min_description_length")
    @classmethod
    def _validate_min_description_length(cls, value: int) -> int:
        if value < 0:
            raise ValueError("min_description_length must be greater than or equal to 0")
        return value


class TimeoutPolicy(BaseModel):
    timeout_ms: int = 10000
    warn_after_ms: int = 3000

    @model_validator(mode="after")
    def _validate_timeouts(self) -> TimeoutPolicy:
        if self.timeout_ms <= 0:
            raise ValueError("timeout.timeout_ms must be greater than 0")
        if self.warn_after_ms <= 0:
            raise ValueError("timeout.warn_after_ms must be greater than 0")
        if self.warn_after_ms > self.timeout_ms:
            if "warn_after_ms" not in self.model_fields_set:
                self.warn_after_ms = self.timeout_ms
                return self
            raise ValueError("timeout.warn_after_ms must be less than or equal to timeout.timeout_ms")
        return self


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

    @field_validator("patterns")
    @classmethod
    def _validate_patterns(cls, value: list[str]) -> list[str]:
        return [pattern.strip() for pattern in value if pattern.strip()]


class ToolPolicy(BaseModel):
    allow_paths: list[str] = Field(default_factory=list)
    deny_paths: list[str] = Field(default_factory=list)
    network: bool | None = None

    @field_validator("allow_paths", "deny_paths")
    @classmethod
    def _normalize_paths(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for item in value:
            path = item.strip()
            if path and path not in seen:
                seen.add(path)
                normalized.append(path)
        return normalized


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


def _mapping_section(raw: Mapping[str, Any], section: str) -> dict[str, Any]:
    value = raw.get(section, {})
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"Config section '{section}' must be a mapping.")
    return dict(value)


def load_config(
    config_file: Path | None = None,
    command_override: str | None = None,
    fail_on_override: str | None = None,
) -> MCPGuardConfig:
    raw: dict[str, Any] = {}
    if config_file is not None:
        raw = _load_yaml(config_file)

    server = _mapping_section(raw, "server")
    policy = _mapping_section(raw, "policy")
    schema = _mapping_section(raw, "schema")
    timeout = _mapping_section(raw, "timeout")
    secret = _mapping_section(raw, "secret")
    tools = _mapping_section(raw, "tools")
    checks = _mapping_section(raw, "checks")

    payload: dict[str, Any] = {
        "server_command": server.get("command", ""),
        "fail_on": policy.get("fail_on", "high"),
        "schema": schema,
        "timeout": timeout,
        "secret": secret,
        "tools": tools,
        "checks": checks,
    }

    if command_override is not None:
        payload["server_command"] = command_override
    if fail_on_override is not None:
        payload["fail_on"] = fail_on_override

    return MCPGuardConfig.model_validate(payload)
