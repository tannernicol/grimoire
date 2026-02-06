"""Quality metrics and gating for search results.

Provides configurable thresholds to ensure the knowledge base
maintains minimum quality standards before searches are served.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    # Minimum number of evaluated cases required
    "min_cases": 5,
    # Minimum positive (relevant) test cases
    "min_positive_cases": 1,
    # Hit-rate thresholds for positive cases
    "min_positive_hit_rate": 0.2,
    # Max acceptable hit rate for negative (irrelevant) cases
    "max_negative_hit_rate": 0.6,
    # Tolerance for metric regression between evaluations
    "regression_tolerance": 0.1,
    # Whether to block searches when no evaluation exists
    "gate_on_missing_eval": False,
}


def load_quality_config(path: Optional[Path] = None) -> dict[str, Any]:
    """Load quality configuration, merging with defaults.

    Args:
        path: Optional path to a JSON config file.

    Returns:
        Merged configuration dict.
    """
    data: dict[str, Any] = {}
    if path and path.exists():
        try:
            raw = json.loads(path.read_text())
            if isinstance(raw, dict):
                data.update(raw)
        except Exception:
            pass

    merged = dict(DEFAULT_CONFIG)
    merged.update({k: v for k, v in data.items() if v is not None})
    return merged


def load_evaluation(path: Optional[Path] = None) -> Optional[dict[str, Any]]:
    """Load the latest quality evaluation results.

    Args:
        path: Path to the evaluation JSON file.

    Returns:
        Evaluation dict or None if not available.
    """
    if not path or not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def evaluate_quality(
    summary: Optional[dict[str, Any]],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate search quality against configured thresholds.

    Args:
        summary: Quality metrics summary (cases, hit rates, etc.).
        config: Quality configuration thresholds.

    Returns:
        Evaluation result with status (pass/fail/warn/unknown) and details.
    """
    if not summary:
        return {"status": "unknown", "reason": "missing_summary", "details": {}}

    details = {"summary": summary}
    cases = int(summary.get("cases", 0))
    positives = int(summary.get("positive_cases", 0))

    if cases < int(config.get("min_cases", 0)) or positives < int(
        config.get("min_positive_cases", 0)
    ):
        return {
            "status": "warn",
            "reason": "insufficient_samples",
            "details": details,
        }

    failures = []

    positive_hit = float(summary.get("positive_hit_rate", 0))
    if positive_hit < float(config.get("min_positive_hit_rate", 0)):
        failures.append("positive_hit_rate")

    negative_hit = float(summary.get("negative_hit_rate", 0))
    if negative_hit > float(config.get("max_negative_hit_rate", 1.0)):
        failures.append("negative_hit_rate")

    if failures:
        return {
            "status": "fail",
            "reason": "thresholds_failed",
            "details": {"failures": failures, **details},
        }

    return {"status": "pass", "reason": "ok", "details": details}


def detect_regression(
    previous: Optional[dict[str, Any]],
    current: dict[str, Any],
    tolerance: float = 0.1,
) -> dict[str, Any]:
    """Detect quality regression between two evaluation summaries.

    Args:
        previous: Previous evaluation summary.
        current: Current evaluation summary.
        tolerance: Maximum acceptable drop in positive metrics.

    Returns:
        Result dict with status and details.
    """
    if not previous:
        return {"status": "unknown", "reason": "no_previous"}

    def delta(key: str) -> float:
        return float(current.get(key, 0)) - float(previous.get(key, 0))

    regressions = []
    for key in ("positive_hit_rate",):
        d = delta(key)
        if d < -abs(tolerance):
            regressions.append({"metric": key, "delta": round(d, 3)})

    if regressions:
        return {"status": "fail", "reason": "regression", "details": regressions}

    return {"status": "pass", "reason": "ok"}


def check_gate(
    config: dict[str, Any],
    eval_path: Optional[Path] = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Run the quality gate check.

    Args:
        config: Quality configuration.
        eval_path: Path to latest evaluation JSON.

    Returns:
        (passed, message, details) tuple.
    """
    evaluation = load_evaluation(eval_path)
    if evaluation is None:
        if config.get("gate_on_missing_eval"):
            return False, "No quality evaluation found; gating enabled", {"status": "missing_eval"}
        return True, "No quality evaluation found; gating skipped", {"status": "missing_eval"}

    summary = evaluation.get("summary") if isinstance(evaluation, dict) else None
    result = evaluate_quality(summary, config)

    if result.get("status") == "fail":
        return False, "Quality evaluation below thresholds", result

    return True, "Quality gate passed", result
