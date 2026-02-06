"""Embedding generation via Ollama (nomic-embed-text).

Supports incremental updates: content is hashed so unchanged documents
are never re-embedded.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from typing import Optional

import numpy as np
import requests

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "nomic-embed-text"
# nomic-embed-text produces 768-dim vectors
DEFAULT_DIMS = 768
# Truncate input to stay within model context
MAX_INPUT_CHARS = 8000


def content_hash(text: str) -> str:
    """Deterministic hash of document content for change detection."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_embedding(
    text: str,
    *,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
    timeout: int = 30,
) -> Optional[np.ndarray]:
    """Get an embedding vector from Ollama.

    Args:
        text: Input text (truncated to MAX_INPUT_CHARS).
        ollama_url: Ollama API base URL.
        model: Embedding model name.
        timeout: Request timeout in seconds.

    Returns:
        numpy float32 array, or None on failure.
    """
    text = text[:MAX_INPUT_CHARS]
    try:
        resp = requests.post(
            f"{ollama_url}/api/embeddings",
            json={"model": model, "prompt": text},
            timeout=timeout,
        )
        if resp.status_code == 200:
            embedding = resp.json().get("embedding", [])
            if embedding:
                return np.array(embedding, dtype=np.float32)
    except Exception as exc:
        logger.warning("Embedding request failed: %s", exc)
    return None


def batch_embeddings(
    texts: list[str],
    *,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
    batch_size: int = 20,
    on_progress: Optional[callable] = None,
) -> list[Optional[np.ndarray]]:
    """Generate embeddings for a list of texts with progress reporting.

    Args:
        texts: List of input strings.
        ollama_url: Ollama API base URL.
        model: Embedding model name.
        batch_size: How many to process between progress callbacks.
        on_progress: Optional callback(done, total).

    Returns:
        List of numpy arrays (or None for failures), same length as texts.
    """
    results: list[Optional[np.ndarray]] = []
    total = len(texts)

    for i in range(0, total, batch_size):
        batch = texts[i : i + batch_size]
        for text in batch:
            emb = get_embedding(text, ollama_url=ollama_url, model=model)
            results.append(emb)

        done = min(i + len(batch), total)
        if on_progress:
            on_progress(done, total)

    return results


def embedding_to_blob(arr: np.ndarray) -> bytes:
    """Serialize a float32 numpy array to bytes for SQLite storage."""
    return arr.astype("<f4").tobytes()


def blob_to_embedding(blob: bytes) -> np.ndarray:
    """Deserialize bytes from SQLite back to a float32 numpy array."""
    return np.frombuffer(blob, dtype="<f4").copy()


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two vectors, safe against zero-norm."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


def check_ollama(
    ollama_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
) -> tuple[bool, str]:
    """Check that Ollama is running and the embedding model is available.

    Returns:
        (ok, message) tuple.
    """
    try:
        resp = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if resp.status_code != 200:
            return False, f"Ollama returned status {resp.status_code}"
        models = [m["name"] for m in resp.json().get("models", [])]
        if model not in models and f"{model}:latest" not in models:
            return False, f"Model '{model}' not found. Run: ollama pull {model}"
        return True, f"Ollama ready with {model}"
    except Exception as exc:
        return False, f"Cannot reach Ollama at {ollama_url}: {exc}"
