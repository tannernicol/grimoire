"""Hybrid search engine: FTS5 keyword + semantic embeddings.

The search pipeline:
1. Run FTS5 keyword search with BM25 scoring.
2. Run semantic search with cosine similarity on embeddings.
3. Combine: hybrid_score = (keyword_weight * fts_score) + (semantic_weight * cosine_score)
4. Deduplicate results by document id.
5. Apply quality filters (min score, max results).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from .embeddings import (
    blob_to_embedding,
    cosine_similarity,
    get_embedding,
)

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """A single search result."""

    doc_id: int
    title: str
    snippet: str
    score: float
    source: str = ""
    severity: Optional[str] = None
    categories: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def _sanitize_fts_query(query: str) -> str:
    """Escape special FTS5 characters and build an OR query from terms."""
    safe = re.sub(r"[^\w\s]", " ", query)
    terms = [f'"{t}"' for t in safe.split() if t]
    if not terms:
        return '""'
    return " OR ".join(terms)


def keyword_search(
    conn: sqlite3.Connection,
    query: str,
    *,
    limit: int = 20,
    severity: Optional[str] = None,
    source: Optional[str] = None,
) -> list[SearchResult]:
    """Full-text keyword search using FTS5 with BM25 scoring.

    Args:
        conn: SQLite connection to the grimoire database.
        query: Search query string.
        limit: Maximum number of results.
        severity: Optional severity filter.
        source: Optional source filter.

    Returns:
        List of SearchResult ordered by relevance (best first).
    """
    fts_query = _sanitize_fts_query(query)

    sql = """
        SELECT d.id, d.title, d.content, d.source, d.severity, d.categories,
               d.metadata,
               bm25(documents_fts, 2.0, 1.0, 1.0) AS rank
        FROM documents_fts
        JOIN documents d ON documents_fts.rowid = d.id
        WHERE documents_fts MATCH ?
    """
    params: list = [fts_query]

    if severity:
        sql += " AND d.severity = ?"
        params.append(severity)

    if source:
        sql += " AND d.source = ?"
        params.append(source)

    sql += " ORDER BY rank ASC LIMIT ?"
    params.append(limit)

    results: list[SearchResult] = []
    try:
        cursor = conn.execute(sql, params)
        for row in cursor:
            content = row[2] or ""
            snippet = content[:500] + "..." if len(content) > 500 else content

            cats_raw = row[5]
            categories = []
            if cats_raw:
                try:
                    categories = json.loads(cats_raw)
                except (json.JSONDecodeError, TypeError):
                    categories = [c.strip() for c in cats_raw.split(",") if c.strip()]

            meta = {}
            if row[6]:
                try:
                    meta = json.loads(row[6])
                except (json.JSONDecodeError, TypeError):
                    pass

            # BM25 scores from SQLite are negative; lower = better.
            # Normalize to 0-1 where higher is better.
            raw_rank = row[7] if row[7] is not None else 0.0
            score = 1.0 / (1.0 + abs(raw_rank))

            results.append(
                SearchResult(
                    doc_id=row[0],
                    title=row[1] or "",
                    snippet=snippet,
                    score=score,
                    source=row[3] or "",
                    severity=row[4],
                    categories=categories,
                    metadata=meta,
                )
            )
    except Exception as exc:
        logger.error("Keyword search failed: %s", exc)

    return results


def semantic_search(
    conn: sqlite3.Connection,
    query: str,
    *,
    limit: int = 20,
    min_similarity: float = 0.3,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    ollama_url: str = "http://localhost:11434",
    model: str = "nomic-embed-text",
) -> list[SearchResult]:
    """Semantic search using cosine similarity on embeddings.

    Args:
        conn: SQLite connection.
        query: Natural language query.
        limit: Maximum results.
        min_similarity: Minimum cosine similarity threshold (0-1).
        severity: Optional severity filter.
        source: Optional source filter.
        ollama_url: Ollama API URL.
        model: Embedding model name.

    Returns:
        List of SearchResult sorted by similarity (best first).
    """
    query_emb = get_embedding(query, ollama_url=ollama_url, model=model)
    if query_emb is None:
        logger.warning("Failed to get query embedding, returning empty results")
        return []

    sql = """
        SELECT d.id, d.title, d.content, d.source, d.severity, d.categories,
               d.metadata, e.embedding
        FROM embeddings e
        JOIN documents d ON e.doc_id = d.id
    """
    conditions = []
    params: list = []

    if severity:
        conditions.append("d.severity = ?")
        params.append(severity)
    if source:
        conditions.append("d.source = ?")
        params.append(source)

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    scored: list[tuple[float, SearchResult]] = []
    try:
        cursor = conn.execute(sql, params)
        for row in cursor:
            doc_emb = blob_to_embedding(row[7])
            sim = cosine_similarity(query_emb, doc_emb)

            if sim < min_similarity:
                continue

            content = row[2] or ""
            snippet = content[:500] + "..." if len(content) > 500 else content

            cats_raw = row[5]
            categories = []
            if cats_raw:
                try:
                    categories = json.loads(cats_raw)
                except (json.JSONDecodeError, TypeError):
                    categories = [c.strip() for c in cats_raw.split(",") if c.strip()]

            meta = {}
            if row[6]:
                try:
                    meta = json.loads(row[6])
                except (json.JSONDecodeError, TypeError):
                    pass

            result = SearchResult(
                doc_id=row[0],
                title=row[1] or "",
                snippet=snippet,
                score=sim,
                source=row[3] or "",
                severity=row[4],
                categories=categories,
                metadata=meta,
            )
            scored.append((sim, result))

    except Exception as exc:
        logger.error("Semantic search failed: %s", exc)

    scored.sort(key=lambda x: x[0], reverse=True)
    return [r for _, r in scored[:limit]]


def hybrid_search(
    conn: sqlite3.Connection,
    query: str,
    *,
    limit: int = 20,
    semantic_weight: float = 0.6,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    ollama_url: str = "http://localhost:11434",
    model: str = "nomic-embed-text",
) -> list[SearchResult]:
    """Hybrid search combining FTS5 keyword and semantic embedding search.

    Scores are combined as:
        hybrid = (keyword_weight * normalized_fts) + (semantic_weight * cosine_sim)

    Args:
        conn: SQLite connection.
        query: Search query.
        limit: Max results.
        semantic_weight: Weight for semantic results (0-1). Keyword gets 1-weight.
        severity: Optional severity filter.
        source: Optional source filter.
        ollama_url: Ollama API URL.
        model: Embedding model.

    Returns:
        List of SearchResult with combined scoring, best first.
    """
    keyword_weight = 1.0 - semantic_weight

    # Fetch more candidates than needed so merging has room
    fetch_limit = limit * 2

    kw_results = keyword_search(
        conn, query, limit=fetch_limit, severity=severity, source=source
    )
    sem_results = semantic_search(
        conn,
        query,
        limit=fetch_limit,
        min_similarity=0.25,
        severity=severity,
        source=source,
        ollama_url=ollama_url,
        model=model,
    )

    # Merge by doc_id
    combined: dict[int, tuple[float, SearchResult]] = {}

    # Normalize keyword scores
    if kw_results:
        max_kw = max(r.score for r in kw_results) or 1.0
        for r in kw_results:
            normalized = r.score / max_kw if max_kw > 0 else 0.0
            score = normalized * keyword_weight
            doc_id = r.doc_id
            if doc_id not in combined or score > combined[doc_id][0]:
                combined[doc_id] = (score, r)

    # Add semantic scores
    for r in sem_results:
        doc_id = r.doc_id
        sem_score = r.score * semantic_weight
        if doc_id in combined:
            existing_score, existing_result = combined[doc_id]
            combined[doc_id] = (existing_score + sem_score, existing_result)
        else:
            combined[doc_id] = (sem_score, r)

    # Sort by combined score descending
    sorted_results = sorted(combined.values(), key=lambda x: x[0], reverse=True)

    final: list[SearchResult] = []
    for score, result in sorted_results[:limit]:
        result.score = score
        final.append(result)

    return final
