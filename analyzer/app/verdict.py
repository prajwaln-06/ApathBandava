"""Deterministic verdict engine (FR-25, SRS 6.5). Pure function of the findings.

Rules, in order:
1. Findings are re-validated (unknown codes dropped) — never trust the caller.
2. Any hard signal, or REGISTRY_DOMAIN_MISMATCH together with a PIN/OTP/card request, is SCAM.
3. Otherwise each distinct code counts once with its weight from weights.yaml; trust signals
   (negative weight) count only when emitted by the deterministic "rules" agent.
4. score >= scam threshold -> SCAM; >= suspicious -> SUSPICIOUS; else NO_RED_FLAGS.
The lowest verdict is NO_RED_FLAGS; the system never says "safe" (FR-28).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .schema import validate_agent_output
from .signals import ASKS_PIN_OTP_CARD, HARD, TRUST_ONLY_FROM

WEIGHTS_PATH = Path(__file__).resolve().parent.parent / "weights.yaml"


def load_weights(path: Path | str = WEIGHTS_PATH) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def decide(findings: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    weights: dict[str, int] = config["weights"]
    scam_at = config["thresholds"]["scam"]
    suspicious_at = config["thresholds"]["suspicious"]

    best: dict[str, tuple[int, str]] = {}  # code -> (weight, evidence)
    hard: list[str] = []
    for raw in findings:
        out = validate_agent_output(raw)
        for sig in out["signals"]:
            code = sig["code"]
            weight = weights.get(code, 0)
            if weight < 0 and out["agent"] not in TRUST_ONLY_FROM:
                continue
            if code in HARD and code not in hard:
                hard.append(code)
            if code not in best:  # each code counts once; first evidence is kept
                best[code] = (weight, sig["evidence"])

    if "REGISTRY_DOMAIN_MISMATCH" in best and ASKS_PIN_OTP_CARD & best.keys():
        hard.append("REGISTRY_DOMAIN_MISMATCH+ASKS_PIN_OTP_CARD")

    score = sum(w for w, _ in best.values())
    if hard or score >= scam_at:
        verdict = "SCAM"
    elif score >= suspicious_at:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO_RED_FLAGS"

    ranked = sorted(
        ((code, w, ev) for code, (w, ev) in best.items() if w > 0 or code in HARD),
        key=lambda t: (t[0] not in HARD, -t[1]),
    )
    reasons: list[str] = []
    for code, _, ev in ranked:
        text = ev or code
        if text not in reasons:
            reasons.append(text)
    reasons = reasons[:5]
    return {"verdict": verdict, "score": max(score, 0), "hard_signals": hard, "reasons": reasons}
