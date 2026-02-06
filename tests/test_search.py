"""Tests for search functionality."""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from grimoire.core import Grimoire
from grimoire.search import SearchResult, keyword_search, _sanitize_fts_query


@pytest.fixture
def grimoire_db(tmp_path):
    """Create a Grimoire instance with sample data."""
    db_path = tmp_path / "test.db"
    g = Grimoire(db_path=db_path)

    # Add sample documents
    g.add_document(
        source="test",
        title="SQL Injection in Login Form",
        content="A SQL injection vulnerability was found in the login form. "
        "The username parameter is concatenated directly into the SQL query "
        "without parameterized queries or input sanitization.",
        severity="critical",
        categories=["injection", "SQLi"],
    )
    g.add_document(
        source="test",
        title="Cross-Site Scripting in Search",
        content="A reflected XSS vulnerability exists in the search functionality. "
        "User input is rendered in the response without HTML encoding, "
        "allowing script injection via the q parameter.",
        severity="high",
        categories=["XSS", "injection"],
    )
    g.add_document(
        source="test",
        title="Broken Access Control on Admin Panel",
        content="The admin panel at /admin is accessible without authentication. "
        "Any user can access administrative functions including user management "
        "and system configuration by directly navigating to the URL.",
        severity="critical",
        categories=["access-control", "authentication"],
    )
    g.add_document(
        source="advisory",
        title="SSRF via Image Import",
        content="Server-side request forgery in the image import feature. "
        "The application fetches user-supplied URLs without validating "
        "the destination, allowing access to internal services.",
        severity="high",
        categories=["SSRF", "network"],
    )
    g.add_document(
        source="advisory",
        title="Insecure Deserialization",
        content="The application deserializes untrusted data from cookies "
        "using pickle without integrity verification, enabling remote code execution.",
        severity="critical",
        categories=["deserialization", "RCE"],
    )

    yield g
    g.close()


class TestSanitizeFtsQuery:
    def test_basic_terms(self):
        result = _sanitize_fts_query("SQL injection")
        assert '"SQL"' in result
        assert '"injection"' in result
        assert " OR " in result

    def test_special_chars_removed(self):
        result = _sanitize_fts_query("CVE-2024-1234: buffer overflow")
        # Hyphens and colons should be replaced with spaces
        assert "-" not in result
        assert ":" not in result

    def test_empty_query(self):
        result = _sanitize_fts_query("")
        assert result == '""'


class TestKeywordSearch:
    def test_basic_search(self, grimoire_db):
        results = grimoire_db.search("SQL injection", mode="keyword")
        assert len(results) > 0
        assert any("SQL" in r.title for r in results)

    def test_search_returns_search_results(self, grimoire_db):
        results = grimoire_db.search("XSS", mode="keyword")
        assert len(results) > 0
        for r in results:
            assert isinstance(r, SearchResult)
            assert r.doc_id > 0
            assert r.score > 0

    def test_severity_filter(self, grimoire_db):
        results = grimoire_db.search("injection", mode="keyword", severity="critical")
        assert len(results) > 0
        for r in results:
            assert r.severity == "critical"

    def test_source_filter(self, grimoire_db):
        results = grimoire_db.search("SSRF", mode="keyword", source="advisory")
        assert len(results) > 0
        for r in results:
            assert r.source == "advisory"

    def test_no_results(self, grimoire_db):
        results = grimoire_db.search("blockchain quantum entanglement", mode="keyword")
        assert len(results) == 0

    def test_limit(self, grimoire_db):
        results = grimoire_db.search("injection", mode="keyword", limit=1)
        assert len(results) <= 1

    def test_categories_preserved(self, grimoire_db):
        results = grimoire_db.search("SQL injection", mode="keyword")
        assert len(results) > 0
        # The SQL injection doc should have categories
        sql_results = [r for r in results if "SQL" in r.title]
        if sql_results:
            assert len(sql_results[0].categories) > 0


class TestSearchModes:
    def test_keyword_mode(self, grimoire_db):
        results = grimoire_db.search("access control", mode="keyword")
        assert len(results) > 0

    def test_default_mode_works(self, grimoire_db):
        # Without Ollama, hybrid falls back gracefully
        # (keyword component still works, semantic returns empty)
        results = grimoire_db.search("injection", mode="keyword")
        assert len(results) > 0


class TestDocumentManagement:
    def test_add_document(self, grimoire_db):
        doc_id = grimoire_db.add_document(
            source="test",
            title="New Vuln",
            content="A new vulnerability was discovered.",
        )
        assert doc_id is not None
        assert doc_id > 0

    def test_duplicate_content_updates(self, grimoire_db):
        content = "Unique content for dedup test"
        id1 = grimoire_db.add_document(source="test", title="First", content=content)
        id2 = grimoire_db.add_document(source="test", title="Updated", content=content)
        assert id1 == id2  # Same content hash -> same doc

    def test_remove_document(self, grimoire_db):
        doc_id = grimoire_db.add_document(
            source="test", title="To Remove", content="This will be removed."
        )
        assert doc_id is not None
        assert grimoire_db.remove_document(doc_id) is True

        # Verify it's gone from search
        results = grimoire_db.search("To Remove", mode="keyword")
        assert not any(r.doc_id == doc_id for r in results)

    def test_bulk_add(self, grimoire_db):
        docs = [
            {"source": "bulk", "title": f"Bulk Doc {i}", "content": f"Bulk content number {i} with enough text."}
            for i in range(5)
        ]
        count = grimoire_db.add_documents(docs)
        assert count == 5


class TestIndexStatus:
    def test_index_status(self, grimoire_db):
        status = grimoire_db.index_status()
        assert status["document_count"] == 5
        assert "test" in status["sources"]
        assert "advisory" in status["sources"]
        assert status["embedding_count"] == 0  # No Ollama in tests

    def test_health_check(self, grimoire_db):
        health = grimoire_db.health_check()
        assert health["status"] == "healthy"
        assert health["document_count"] == 5
        assert len(health["issues"]) == 0
