"""CSV/structured data ingestor.

Reads CSV files and maps columns to Grimoire document fields.
Supports configurable column mapping.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any, Iterator, Optional

from .base import BaseIngestor

logger = logging.getLogger(__name__)

# Default column mapping: CSV column name -> document field
DEFAULT_MAPPING = {
    "title": "title",
    "name": "title",
    "description": "content",
    "content": "content",
    "summary": "content",
    "severity": "severity",
    "risk": "severity",
    "category": "categories",
    "categories": "categories",
    "tags": "categories",
    "source": "source",
    "path": "path",
    "url": "path",
    "id": None,  # stored in metadata
    "cve_id": None,
    "cwe": None,
    "mitigation": None,
    "fix": None,
    "references": None,
}


class CSVIngestor(BaseIngestor):
    """Ingest structured data from CSV files."""

    source_name = "csv"

    def __init__(
        self,
        *,
        source_label: Optional[str] = None,
        column_map: Optional[dict[str, str]] = None,
        content_columns: Optional[list[str]] = None,
        delimiter: str = ",",
        **kwargs,
    ):
        """Initialize CSV ingestor.

        Args:
            source_label: Source identifier for ingested documents.
            column_map: Custom mapping of CSV columns to document fields.
            content_columns: List of columns to concatenate as content.
                If provided, overrides the default content column detection.
            delimiter: CSV delimiter character.
        """
        super().__init__(**kwargs)
        self.source_label = source_label or "csv"
        self.column_map = column_map or {}
        self.content_columns = content_columns
        self.delimiter = delimiter

    def ingest(self, path: str | Path) -> Iterator[dict[str, Any]]:
        """Yield documents from a CSV file.

        Args:
            path: Path to a CSV file.

        Yields:
            Document dicts from each row.
        """
        path = Path(path)
        if not path.exists():
            logger.error("CSV file not found: %s", path)
            return

        try:
            with open(path, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f, delimiter=self.delimiter)
                if not reader.fieldnames:
                    logger.error("No headers found in %s", path)
                    return

                for row_num, row in enumerate(reader, start=2):
                    doc = self._parse_row(row, row_num, path)
                    if doc:
                        yield doc

        except Exception as exc:
            logger.error("Failed to read CSV %s: %s", path, exc)

    def _resolve_field(self, col_name: str) -> Optional[str]:
        """Resolve a CSV column name to a document field name."""
        col_lower = col_name.lower().strip()
        # Check custom mapping first
        if col_lower in self.column_map:
            return self.column_map[col_lower]
        # Check default mapping
        return DEFAULT_MAPPING.get(col_lower)

    def _parse_row(self, row: dict, row_num: int, file_path: Path) -> dict[str, Any] | None:
        """Parse a single CSV row into a document dict."""
        doc: dict[str, Any] = {
            "source": self.source_label,
        }
        metadata: dict[str, Any] = {"csv_file": str(file_path.name), "row": row_num}

        # Build content from specified columns or auto-detect
        if self.content_columns:
            content_parts = []
            for col in self.content_columns:
                val = row.get(col, "").strip()
                if val:
                    content_parts.append(f"{col}: {val}")
            content = "\n".join(content_parts)
        else:
            content = ""

        for col_name, value in row.items():
            if not value or not value.strip():
                continue
            value = value.strip()

            field = self._resolve_field(col_name)

            if field == "title":
                doc.setdefault("title", value)
            elif field == "content" and not self.content_columns:
                # Append to content
                if content:
                    content += "\n\n"
                content += value
            elif field == "severity":
                doc["severity"] = value.lower()
            elif field == "categories":
                # Parse comma-separated categories
                if "," in value:
                    doc["categories"] = [c.strip() for c in value.split(",") if c.strip()]
                elif value.startswith("["):
                    try:
                        doc["categories"] = json.loads(value)
                    except json.JSONDecodeError:
                        doc["categories"] = [value]
                else:
                    doc["categories"] = [value]
            elif field == "source":
                doc["source"] = value
            elif field == "path":
                doc["path"] = value
            else:
                # Store everything else in metadata
                metadata[col_name] = value

        if not content or len(content.strip()) < 10:
            return None

        doc["content"] = content
        doc["metadata"] = metadata
        return doc
