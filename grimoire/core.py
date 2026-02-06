"""Core Grimoire class -- search, index, manage.

This is the main entry point. It owns the database connection, exposes
search/ingest/status methods, and coordinates the embedding pipeline.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from .embeddings import (
    batch_embeddings,
    check_ollama,
    content_hash,
    embedding_to_blob,
    get_embedding,
)
from .quality import check_gate, load_quality_config
from .search import SearchResult, hybrid_search, keyword_search, semantic_search

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    path TEXT,
    title TEXT,
    content TEXT NOT NULL,
    metadata TEXT,
    severity TEXT,
    categories TEXT,
    content_hash TEXT UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    title, content, categories,
    content='documents',
    content_rowid='id'
);

CREATE TABLE IF NOT EXISTS embeddings (
    doc_id INTEGER PRIMARY KEY,
    embedding BLOB NOT NULL,
    model TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(doc_id) REFERENCES documents(id)
);

-- Triggers to keep FTS in sync with documents table
CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
    INSERT INTO documents_fts(rowid, title, content, categories)
    VALUES (new.id, new.title, new.content, new.categories);
END;

CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, content, categories)
    VALUES ('delete', old.id, old.title, old.content, old.categories);
END;

CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, content, categories)
    VALUES ('delete', old.id, old.title, old.content, old.categories);
    INSERT INTO documents_fts(rowid, title, content, categories)
    VALUES (new.id, new.title, new.content, new.categories);
END;
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_config() -> dict[str, Any]:
    return {
        "database": {"path": "grimoire.db"},
        "ollama": {"url": "http://localhost:11434", "model": "nomic-embed-text"},
        "search": {
            "default_mode": "hybrid",
            "semantic_weight": 0.6,
            "default_limit": 20,
            "min_similarity": 0.3,
        },
        "quality": {
            "min_cases": 5,
            "min_positive_cases": 1,
            "min_positive_hit_rate": 0.2,
            "max_negative_hit_rate": 0.6,
            "gate_on_missing_eval": False,
        },
    }


class Grimoire:
    """Main interface to a Grimoire knowledge base.

    Usage::

        g = Grimoire("my_knowledge.db")
        g.add_document(source="cve", title="CVE-2024-1234", content="...")
        results = g.search("SQL injection", mode="hybrid")
    """

    def __init__(
        self,
        db_path: str | Path = "grimoire.db",
        config: Optional[dict[str, Any]] = None,
        config_path: Optional[str | Path] = None,
    ):
        self.config = _default_config()
        if config_path:
            self._load_config_file(Path(config_path))
        if config:
            self._merge_config(config)

        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
        self._cache: dict[str, Any] = {}
        self._connect()

    def _load_config_file(self, path: Path) -> None:
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text())
                if isinstance(data, dict):
                    self._merge_config(data)
            except Exception as exc:
                logger.warning("Failed to load config %s: %s", path, exc)

    def _merge_config(self, data: dict) -> None:
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(self.config.get(key), dict):
                self.config[key].update(value)
            else:
                self.config[key] = value

    def _connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_pragmas()
        self._init_schema()

    def _init_pragmas(self) -> None:
        if not self.conn:
            return
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA temp_store=MEMORY;")
        self.conn.execute("PRAGMA cache_size=-20000;")
        self.conn.execute("PRAGMA busy_timeout=5000;")

    def _init_schema(self) -> None:
        if not self.conn:
            return
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Document management
    # ------------------------------------------------------------------

    def add_document(
        self,
        *,
        source: str,
        content: str,
        title: Optional[str] = None,
        path: Optional[str] = None,
        metadata: Optional[dict] = None,
        severity: Optional[str] = None,
        categories: Optional[list[str]] = None,
    ) -> Optional[int]:
        """Add or update a document in the knowledge base.

        If the content_hash already exists, the document is updated in place.

        Args:
            source: Data source identifier (e.g. "cve", "advisory", "markdown").
            content: Full document text.
            title: Optional document title.
            path: Optional file path or URL.
            metadata: Optional JSON-serializable metadata dict.
            severity: Optional severity level.
            categories: Optional list of category tags.

        Returns:
            The document row id, or None on failure.
        """
        if not self.conn:
            return None

        c_hash = content_hash(content)
        now = _now_iso()
        meta_json = json.dumps(metadata) if metadata else None
        cats_json = json.dumps(categories) if categories else None

        try:
            # Check if document already exists (by content hash)
            existing = self.conn.execute(
                "SELECT id FROM documents WHERE content_hash = ?", (c_hash,)
            ).fetchone()

            if existing:
                doc_id = existing[0]
                self.conn.execute(
                    """UPDATE documents SET source=?, path=?, title=?, content=?,
                       metadata=?, severity=?, categories=?, updated_at=?
                       WHERE id=?""",
                    (source, path, title, content, meta_json, severity, cats_json, now, doc_id),
                )
                self.conn.commit()
                return doc_id

            cursor = self.conn.execute(
                """INSERT INTO documents
                   (source, path, title, content, metadata, severity, categories,
                    content_hash, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (source, path, title, content, meta_json, severity, cats_json, c_hash, now, now),
            )
            self.conn.commit()
            return cursor.lastrowid

        except Exception as exc:
            logger.error("Failed to add document: %s", exc)
            self.conn.rollback()
            return None

    def add_documents(self, documents: list[dict[str, Any]]) -> int:
        """Bulk-add documents.

        Each dict should have the same keys as add_document() kwargs.

        Returns:
            Number of documents successfully added/updated.
        """
        count = 0
        for doc in documents:
            doc_id = self.add_document(**doc)
            if doc_id is not None:
                count += 1
        return count

    def remove_document(self, doc_id: int) -> bool:
        """Remove a document and its embedding by id."""
        if not self.conn:
            return False
        try:
            self.conn.execute("DELETE FROM embeddings WHERE doc_id = ?", (doc_id,))
            self.conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
            self.conn.commit()
            return True
        except Exception as exc:
            logger.error("Failed to remove document %d: %s", doc_id, exc)
            return False

    # ------------------------------------------------------------------
    # Embedding management
    # ------------------------------------------------------------------

    def generate_embeddings(
        self,
        *,
        force: bool = False,
        batch_size: int = 20,
        on_progress: Optional[callable] = None,
    ) -> dict[str, int]:
        """Generate embeddings for documents that don't have them yet.

        Args:
            force: If True, regenerate all embeddings.
            batch_size: Batch size for embedding generation.
            on_progress: Optional callback(done, total).

        Returns:
            Dict with counts: generated, skipped, failed.
        """
        if not self.conn:
            return {"generated": 0, "skipped": 0, "failed": 0}

        ollama_cfg = self.config.get("ollama", {})
        ollama_url = ollama_cfg.get("url", "http://localhost:11434")
        model = ollama_cfg.get("model", "nomic-embed-text")

        ok, msg = check_ollama(ollama_url, model)
        if not ok:
            logger.error("Ollama check failed: %s", msg)
            return {"generated": 0, "skipped": 0, "failed": 0, "error": msg}

        if force:
            rows = self.conn.execute(
                "SELECT id, content FROM documents ORDER BY id"
            ).fetchall()
        else:
            rows = self.conn.execute(
                """SELECT d.id, d.content FROM documents d
                   LEFT JOIN embeddings e ON d.id = e.doc_id
                   WHERE e.doc_id IS NULL
                   ORDER BY d.id"""
            ).fetchall()

        if not rows:
            return {"generated": 0, "skipped": 0, "failed": 0}

        texts = [row[1][:8000] for row in rows]
        doc_ids = [row[0] for row in rows]

        embeddings = batch_embeddings(
            texts,
            ollama_url=ollama_url,
            model=model,
            batch_size=batch_size,
            on_progress=on_progress,
        )

        generated = 0
        failed = 0
        now = _now_iso()

        for doc_id, emb in zip(doc_ids, embeddings):
            if emb is not None:
                blob = embedding_to_blob(emb)
                try:
                    self.conn.execute(
                        """INSERT OR REPLACE INTO embeddings (doc_id, embedding, model, created_at)
                           VALUES (?, ?, ?, ?)""",
                        (doc_id, blob, model, now),
                    )
                    generated += 1
                except Exception as exc:
                    logger.error("Failed to store embedding for doc %d: %s", doc_id, exc)
                    failed += 1
            else:
                failed += 1

        self.conn.commit()
        return {"generated": generated, "skipped": len(doc_ids) - generated - failed, "failed": failed}

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        mode: Optional[str] = None,
        limit: Optional[int] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        semantic_weight: Optional[float] = None,
    ) -> list[SearchResult]:
        """Search the knowledge base.

        Args:
            query: Search query string.
            mode: Search mode -- "keyword", "semantic", or "hybrid" (default from config).
            limit: Maximum results (default from config).
            severity: Optional severity filter.
            source: Optional source filter.
            semantic_weight: Weight for semantic component in hybrid mode.

        Returns:
            List of SearchResult objects.
        """
        if not self.conn:
            return []

        search_cfg = self.config.get("search", {})
        mode = mode or search_cfg.get("default_mode", "hybrid")
        limit = limit or search_cfg.get("default_limit", 20)
        semantic_weight = semantic_weight or search_cfg.get("semantic_weight", 0.6)

        ollama_cfg = self.config.get("ollama", {})
        ollama_url = ollama_cfg.get("url", "http://localhost:11434")
        model = ollama_cfg.get("model", "nomic-embed-text")

        if mode == "keyword":
            return keyword_search(
                self.conn, query, limit=limit, severity=severity, source=source
            )
        elif mode == "semantic":
            return semantic_search(
                self.conn,
                query,
                limit=limit,
                severity=severity,
                source=source,
                ollama_url=ollama_url,
                model=model,
            )
        else:  # hybrid
            return hybrid_search(
                self.conn,
                query,
                limit=limit,
                semantic_weight=semantic_weight,
                severity=severity,
                source=source,
                ollama_url=ollama_url,
                model=model,
            )

    # ------------------------------------------------------------------
    # Index status & health
    # ------------------------------------------------------------------

    def index_status(self) -> dict[str, Any]:
        """Return statistics about the knowledge base index.

        Returns:
            Dict with doc_count, embedding_count, coverage, sources, etc.
        """
        if not self.conn:
            return {"error": "No database connection"}

        doc_count = self.conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        emb_count = self.conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]

        sources = {}
        for row in self.conn.execute(
            "SELECT source, COUNT(*) FROM documents GROUP BY source"
        ):
            sources[row[0]] = row[1]

        severities = {}
        for row in self.conn.execute(
            "SELECT severity, COUNT(*) FROM documents WHERE severity IS NOT NULL GROUP BY severity"
        ):
            severities[row[0]] = row[1]

        latest_doc = self.conn.execute(
            "SELECT MAX(updated_at) FROM documents"
        ).fetchone()[0]

        latest_emb = self.conn.execute(
            "SELECT MAX(created_at) FROM embeddings"
        ).fetchone()[0]

        return {
            "database": str(self.db_path),
            "document_count": doc_count,
            "embedding_count": emb_count,
            "embedding_coverage": f"{emb_count / doc_count * 100:.1f}%" if doc_count > 0 else "0%",
            "sources": sources,
            "severities": severities,
            "last_document_update": latest_doc,
            "last_embedding_update": latest_emb,
        }

    def health_check(self) -> dict[str, Any]:
        """Run a database integrity check.

        Returns:
            Dict with status, details, and any issues found.
        """
        if not self.conn:
            return {"status": "error", "message": "No database connection"}

        issues: list[str] = []

        # SQLite integrity check
        try:
            rows = self.conn.execute("PRAGMA quick_check").fetchall()
            for row in rows:
                if row[0] != "ok":
                    issues.append(f"integrity: {row[0]}")
        except Exception as exc:
            issues.append(f"integrity check failed: {exc}")

        # Check FTS sync
        try:
            doc_count = self.conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            fts_count = self.conn.execute("SELECT COUNT(*) FROM documents_fts").fetchone()[0]
            if doc_count != fts_count:
                issues.append(f"FTS desync: {doc_count} docs vs {fts_count} FTS entries")
        except Exception as exc:
            issues.append(f"FTS check failed: {exc}")

        # Check for orphaned embeddings
        try:
            orphans = self.conn.execute(
                """SELECT COUNT(*) FROM embeddings e
                   LEFT JOIN documents d ON e.doc_id = d.id
                   WHERE d.id IS NULL"""
            ).fetchone()[0]
            if orphans > 0:
                issues.append(f"{orphans} orphaned embeddings found")
        except Exception as exc:
            issues.append(f"Orphan check failed: {exc}")

        status = "healthy" if not issues else "degraded"
        return {
            "status": status,
            "database": str(self.db_path),
            "issues": issues,
            **self.index_status(),
        }

    def rebuild_fts(self) -> bool:
        """Rebuild the FTS5 index from the documents table.

        Useful if the FTS index gets out of sync.
        """
        if not self.conn:
            return False
        try:
            self.conn.execute("INSERT INTO documents_fts(documents_fts) VALUES('rebuild')")
            self.conn.commit()
            return True
        except Exception as exc:
            logger.error("FTS rebuild failed: %s", exc)
            return False

    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
