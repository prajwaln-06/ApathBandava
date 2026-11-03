"""Agent output schema (SRS 6.4) and its validator.

Every agent result passes through `validate_agent_output` before it can influence a verdict:
unknown agents/codes are dropped, strings are truncated, and anything malformed becomes
`{status: "unknown", signals: []}` (SRS 3.3.3).
"""
from __future__ import annotations

from typing import Any

from .signals import AGENTS, CODES, SEVERITY

MAX_EVIDENCE = 300
MAX_SUMMARY = 200
MAX_SIGNALS = 12

AGENT_OUTPUT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["agent", "status", "signals", "summary"],
    "properties": {
        "agent": {"type": "string", "enum": list(AGENTS)},
        "status": {"type": "string", "enum": ["ok", "unknown"]},
        "signals": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["code", "severity", "evidence"],
                "properties": {
                    "code": {"type": "string", "enum": sorted(CODES)},
                    "severity": {"type": "string", "enum": ["hard", "high", "medium", "low", "trust"]},
                    "evidence": {"type": "string"},
                    "source_url": {"type": ["string", "null"]},
                },
            },
        },
        "summary": {"type": "string"},
    },
}


def unknown(agent: str) -> dict[str, Any]:
    return {"agent": agent, "status": "unknown", "signals": [], "summary": ""}


def _clean_str(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def validate_agent_output(raw: Any, agent: str | None = None) -> dict[str, Any]:
    """Return a schema-valid copy of `raw`; never raises."""
    if not isinstance(raw, dict):
        return unknown(agent or "unknown")
    name = raw.get("agent") if raw.get("agent") in AGENTS else (agent or "unknown")
    if agent and name != agent:
        name = agent
    status = raw.get("status")
    signals_in = raw.get("signals")
    if status not in ("ok", "unknown") or not isinstance(signals_in, list):
        return unknown(name)
    signals: list[dict[str, Any]] = []
    for sig in signals_in[: MAX_SIGNALS * 2]:
        if not isinstance(sig, dict) or sig.get("code") not in CODES:
            continue
        src = sig.get("source_url")
        if not (isinstance(src, str) and src.startswith(("https://", "http://")) and len(src) < 500):
            src = None
        signals.append({
            "code": sig["code"],
            "severity": SEVERITY[sig["code"]],
            "evidence": _clean_str(sig.get("evidence"), MAX_EVIDENCE),
            "source_url": src,
        })
        if len(signals) >= MAX_SIGNALS:
            break
    return {"agent": name, "status": status, "signals": signals,
            "summary": _clean_str(raw.get("summary"), MAX_SUMMARY)}
