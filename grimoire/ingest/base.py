"""Base ingestor class.

All ingestors should subclass BaseIngestor and implement the ingest() method.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)


class BaseIngestor(ABC):
    """Abstract base class for data ingestors.

    Subclasses must implement ``ingest()`` which yields document dicts
    compatible with ``Grimoire.add_document()``.
    """

    source_name: str = "unknown"

    def __init__(self, **kwargs: Any):
        self.options = kwargs

    @abstractmethod
    def ingest(self, path: str | Path) -> Iterator[dict[str, Any]]:
        """Yield document dicts from the given path.

        Each dict should contain at minimum:
            - source: str
            - content: str

        Optional fields:
            - title: str
            - path: str
            - metadata: dict
            - severity: str
            - categories: list[str]

        Args:
            path: File or directory path to ingest.

        Yields:
            Document dicts ready for Grimoire.add_document().
        """
        ...

    def ingest_to_grimoire(self, grimoire, path: str | Path) -> int:
        """Convenience: ingest documents directly into a Grimoire instance.

        Args:
            grimoire: A Grimoire instance.
            path: File or directory path to ingest.

        Returns:
            Number of documents successfully ingested.
        """
        count = 0
        for doc in self.ingest(path):
            doc_id = grimoire.add_document(**doc)
            if doc_id is not None:
                count += 1
        return count
