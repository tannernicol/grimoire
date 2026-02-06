"""Tests for data ingestors."""

import json
import tempfile
from pathlib import Path

import pytest

from grimoire.core import Grimoire
from grimoire.ingest.cve import CVEIngestor
from grimoire.ingest.markdown import MarkdownIngestor, _extract_title, _extract_severity
from grimoire.ingest.csv import CSVIngestor


# ---------- CVE Ingestor ----------


class TestCVEIngestor:
    def test_simple_format(self, tmp_path):
        data = [
            {
                "id": "CVE-2024-1234",
                "description": "Buffer overflow in example library allows remote code execution.",
                "severity": "critical",
                "categories": ["CWE-120"],
            },
            {
                "id": "CVE-2024-5678",
                "description": "SQL injection in query parameter.",
                "severity": "high",
                "categories": ["CWE-89"],
                "mitigations": ["Use parameterized queries"],
            },
        ]
        json_file = tmp_path / "cves.json"
        json_file.write_text(json.dumps(data))

        ingestor = CVEIngestor()
        docs = list(ingestor.ingest(json_file))

        assert len(docs) == 2
        assert docs[0]["title"] == "CVE-2024-1234"
        assert docs[0]["source"] == "cve"
        assert docs[0]["severity"] == "critical"
        assert "Buffer overflow" in docs[0]["content"]
        assert "CWE-120" in docs[0]["categories"]

    def test_nvd20_format(self, tmp_path):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-9999",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability description."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "HIGH"}}
                            ]
                        },
                        "weaknesses": [
                            {
                                "description": [
                                    {"value": "CWE-79"}
                                ]
                            }
                        ],
                        "references": [
                            {"url": "https://example.com/advisory"}
                        ],
                    }
                }
            ]
        }
        json_file = tmp_path / "nvd.json"
        json_file.write_text(json.dumps(data))

        ingestor = CVEIngestor()
        docs = list(ingestor.ingest(json_file))

        assert len(docs) == 1
        assert docs[0]["title"] == "CVE-2024-9999"
        assert docs[0]["severity"] == "high"
        assert "CWE-79" in docs[0]["categories"]
        assert "example.com" in docs[0]["content"]

    def test_missing_file(self, tmp_path):
        ingestor = CVEIngestor()
        docs = list(ingestor.ingest(tmp_path / "nonexistent.json"))
        assert len(docs) == 0

    def test_ingest_to_grimoire(self, tmp_path):
        data = [
            {"id": "CVE-2024-0001", "description": "Test vuln one with sufficient text content."},
            {"id": "CVE-2024-0002", "description": "Test vuln two with sufficient text content."},
        ]
        json_file = tmp_path / "cves.json"
        json_file.write_text(json.dumps(data))

        g = Grimoire(db_path=tmp_path / "test.db")
        ingestor = CVEIngestor()
        count = ingestor.ingest_to_grimoire(g, json_file)
        assert count == 2

        status = g.index_status()
        assert status["document_count"] == 2
        g.close()


# ---------- Markdown Ingestor ----------


class TestMarkdownHelpers:
    def test_extract_title(self):
        assert _extract_title("# My Title\nContent") == "My Title"
        assert _extract_title("## Sub Title\nContent") == "Sub Title"
        assert _extract_title("No heading here") is None

    def test_extract_severity(self):
        assert _extract_severity("Severity: Critical") == "critical"
        assert _extract_severity("This is a HIGH risk issue") == "high"
        assert _extract_severity("No severity info") is None


class TestMarkdownIngestor:
    def test_single_file(self, tmp_path):
        md_file = tmp_path / "finding.md"
        md_file.write_text("# SQL Injection\n\nSeverity: High\n\nFound in login form.")

        ingestor = MarkdownIngestor()
        docs = list(ingestor.ingest(md_file))

        assert len(docs) == 1
        assert docs[0]["title"] == "SQL Injection"
        assert docs[0]["severity"] == "high"
        assert "login form" in docs[0]["content"]

    def test_directory_scan(self, tmp_path):
        (tmp_path / "a.md").write_text("# Finding A\n\nDescription of finding A.")
        (tmp_path / "b.md").write_text("# Finding B\n\nDescription of finding B.")
        (tmp_path / "not_md.txt").write_text("This should be ignored.")

        ingestor = MarkdownIngestor()
        docs = list(ingestor.ingest(tmp_path))

        assert len(docs) == 2
        titles = {d["title"] for d in docs}
        assert "Finding A" in titles
        assert "Finding B" in titles

    def test_custom_source_label(self, tmp_path):
        (tmp_path / "test.md").write_text("# Test\n\nContent here with enough text.")

        ingestor = MarkdownIngestor(source_label="advisories")
        docs = list(ingestor.ingest(tmp_path))

        assert len(docs) == 1
        assert docs[0]["source"] == "advisories"

    def test_skip_small_files(self, tmp_path):
        (tmp_path / "tiny.md").write_text("# H")  # Too small

        ingestor = MarkdownIngestor()
        docs = list(ingestor.ingest(tmp_path))
        assert len(docs) == 0

    def test_nested_directories(self, tmp_path):
        sub = tmp_path / "sub" / "dir"
        sub.mkdir(parents=True)
        (sub / "deep.md").write_text("# Deep Finding\n\nFound deep in directory tree.")

        ingestor = MarkdownIngestor()
        docs = list(ingestor.ingest(tmp_path))
        assert len(docs) == 1
        assert "sub" in docs[0]["path"]


# ---------- CSV Ingestor ----------


class TestCSVIngestor:
    def test_basic_csv(self, tmp_path):
        csv_file = tmp_path / "vulns.csv"
        csv_file.write_text(
            "title,description,severity,category\n"
            "XSS Bug,Cross-site scripting in search,high,XSS\n"
            "SQLi,SQL injection in login form,critical,injection\n"
        )

        ingestor = CSVIngestor()
        docs = list(ingestor.ingest(csv_file))

        assert len(docs) == 2
        assert docs[0]["title"] == "XSS Bug"
        assert docs[0]["severity"] == "high"
        assert "Cross-site scripting" in docs[0]["content"]

    def test_custom_columns(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text(
            "vuln_name,details,risk_level\n"
            "Buffer Overflow,Stack buffer overflow in parser function,critical\n"
        )

        ingestor = CSVIngestor(
            column_map={
                "vuln_name": "title",
                "details": "content",
                "risk_level": "severity",
            }
        )
        docs = list(ingestor.ingest(csv_file))

        assert len(docs) == 1
        assert docs[0]["title"] == "Buffer Overflow"
        assert docs[0]["severity"] == "critical"

    def test_content_columns(self, tmp_path):
        csv_file = tmp_path / "multi.csv"
        csv_file.write_text(
            "title,impact,root_cause,fix\n"
            "IDOR,Data leak,Missing authz check,Add ownership validation\n"
        )

        ingestor = CSVIngestor(content_columns=["impact", "root_cause", "fix"])
        docs = list(ingestor.ingest(csv_file))

        assert len(docs) == 1
        assert "impact:" in docs[0]["content"].lower()
        assert "root_cause:" in docs[0]["content"].lower()

    def test_missing_file(self, tmp_path):
        ingestor = CSVIngestor()
        docs = list(ingestor.ingest(tmp_path / "missing.csv"))
        assert len(docs) == 0

    def test_custom_source_label(self, tmp_path):
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("title,description\nTest,Test description with enough content\n")

        ingestor = CSVIngestor(source_label="custom-source")
        docs = list(ingestor.ingest(csv_file))

        assert len(docs) == 1
        assert docs[0]["source"] == "custom-source"
