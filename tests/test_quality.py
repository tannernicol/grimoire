"""Tests for quality metrics and gating."""

import json
from pathlib import Path

import pytest

from grimoire.quality import (
    DEFAULT_CONFIG,
    check_gate,
    detect_regression,
    evaluate_quality,
    load_quality_config,
)


class TestLoadConfig:
    def test_defaults(self):
        config = load_quality_config()
        assert config["min_cases"] == 5
        assert config["min_positive_cases"] == 1
        assert config["gate_on_missing_eval"] is False

    def test_override_from_file(self, tmp_path):
        config_file = tmp_path / "quality.json"
        config_file.write_text(json.dumps({"min_cases": 10, "min_positive_hit_rate": 0.5}))

        config = load_quality_config(config_file)
        assert config["min_cases"] == 10
        assert config["min_positive_hit_rate"] == 0.5
        # Defaults preserved for unset keys
        assert config["max_negative_hit_rate"] == 0.6

    def test_missing_file(self, tmp_path):
        config = load_quality_config(tmp_path / "nonexistent.json")
        assert config == DEFAULT_CONFIG


class TestEvaluateQuality:
    def test_pass(self):
        summary = {
            "cases": 10,
            "positive_cases": 5,
            "positive_hit_rate": 0.8,
            "negative_hit_rate": 0.1,
        }
        result = evaluate_quality(summary, DEFAULT_CONFIG)
        assert result["status"] == "pass"

    def test_fail_low_positive_rate(self):
        summary = {
            "cases": 10,
            "positive_cases": 5,
            "positive_hit_rate": 0.05,  # Below threshold
            "negative_hit_rate": 0.1,
        }
        result = evaluate_quality(summary, DEFAULT_CONFIG)
        assert result["status"] == "fail"
        assert "positive_hit_rate" in result["details"]["failures"]

    def test_fail_high_negative_rate(self):
        summary = {
            "cases": 10,
            "positive_cases": 5,
            "positive_hit_rate": 0.8,
            "negative_hit_rate": 0.9,  # Above threshold
        }
        result = evaluate_quality(summary, DEFAULT_CONFIG)
        assert result["status"] == "fail"
        assert "negative_hit_rate" in result["details"]["failures"]

    def test_warn_insufficient_samples(self):
        summary = {
            "cases": 2,  # Below min_cases
            "positive_cases": 1,
            "positive_hit_rate": 0.8,
            "negative_hit_rate": 0.1,
        }
        result = evaluate_quality(summary, DEFAULT_CONFIG)
        assert result["status"] == "warn"
        assert result["reason"] == "insufficient_samples"

    def test_missing_summary(self):
        result = evaluate_quality(None, DEFAULT_CONFIG)
        assert result["status"] == "unknown"


class TestDetectRegression:
    def test_no_regression(self):
        prev = {"positive_hit_rate": 0.8}
        curr = {"positive_hit_rate": 0.85}
        result = detect_regression(prev, curr)
        assert result["status"] == "pass"

    def test_regression_detected(self):
        prev = {"positive_hit_rate": 0.8}
        curr = {"positive_hit_rate": 0.5}  # Big drop
        result = detect_regression(prev, curr, tolerance=0.1)
        assert result["status"] == "fail"
        assert result["reason"] == "regression"

    def test_no_previous(self):
        result = detect_regression(None, {"positive_hit_rate": 0.8})
        assert result["status"] == "unknown"

    def test_within_tolerance(self):
        prev = {"positive_hit_rate": 0.8}
        curr = {"positive_hit_rate": 0.75}  # Drop of 0.05, within 0.1 tolerance
        result = detect_regression(prev, curr, tolerance=0.1)
        assert result["status"] == "pass"


class TestCheckGate:
    def test_pass_no_eval_gating_disabled(self):
        config = dict(DEFAULT_CONFIG)
        config["gate_on_missing_eval"] = False
        passed, msg, details = check_gate(config)
        assert passed is True

    def test_fail_no_eval_gating_enabled(self):
        config = dict(DEFAULT_CONFIG)
        config["gate_on_missing_eval"] = True
        passed, msg, details = check_gate(config)
        assert passed is False

    def test_pass_with_eval(self, tmp_path):
        eval_file = tmp_path / "eval.json"
        eval_file.write_text(json.dumps({
            "summary": {
                "cases": 10,
                "positive_cases": 5,
                "positive_hit_rate": 0.8,
                "negative_hit_rate": 0.1,
            }
        }))

        passed, msg, details = check_gate(DEFAULT_CONFIG, eval_file)
        assert passed is True

    def test_fail_with_bad_eval(self, tmp_path):
        eval_file = tmp_path / "eval.json"
        eval_file.write_text(json.dumps({
            "summary": {
                "cases": 10,
                "positive_cases": 5,
                "positive_hit_rate": 0.01,
                "negative_hit_rate": 0.9,
            }
        }))

        passed, msg, details = check_gate(DEFAULT_CONFIG, eval_file)
        assert passed is False
