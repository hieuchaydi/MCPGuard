from __future__ import annotations

from mcpguard.checks.secret_scan import scan_for_secrets


def test_secret_scan_matches_literal_patterns():
    patterns = ["GROQ_API_KEY", "password="]
    response = "config: GROQ_API_KEY=gsk_demo password=abc"
    findings = scan_for_secrets("get_config", response, patterns)
    assert len(findings) == 2
    assert all(f.rule == "secret_leaked" for f in findings)


def test_secret_scan_matches_regex_patterns():
    patterns = [r"sk-[A-Za-z0-9]{20,}", r"ghp_[A-Za-z0-9]{36}"]
    response = "token=sk-123456789012345678901234 and ghp_123456789012345678901234567890123456"
    findings = scan_for_secrets("get_config", response, patterns)
    assert len(findings) == 2


def test_secret_scan_no_match_returns_empty():
    patterns = ["OPENAI_API_KEY", r"ghp_[A-Za-z0-9]{36}"]
    response = "nothing sensitive here"
    findings = scan_for_secrets("get_config", response, patterns)
    assert findings == []
