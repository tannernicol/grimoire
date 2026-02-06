"""Generic Markdown file ingestor.

Recursively reads ``.md`` files from a directory, extracting the title
from the first heading and treating the full text as content.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Iterator, Optional

from .base import BaseIngestor

logger = logging.getLogger(__name__)


def _extract_title(text: str) -> Optional[str]:
    """Extract the first markdown heading as the title."""
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("#"):
            return re.sub(r"^#+\s*", "", line).strip()
    return None


def _extract_severity(text: str) -> Optional[str]:
    """Try to detect severity from common markdown patterns."""
    text_lower = text.lower()
    patterns = [
        (r"\bseverity:\s*(critical|high|medium|low)\b", 1),
        (r"\brisk:\s*(critical|high|medium|low)\b", 1),
        (r"\b(critical|high|medium|low)\s+severity\b", 1),
        (r"\b(critical|high|medium|low)\s+risk\b", 1),
    ]
    for pattern, group in patterns:
        match = re.search(pattern, text_lower)
        if match:
            return match.group(group)
    return None


def _extract_categories(text: str) -> list[str]:
    """Try to extract category/tag information from the text."""
    categories = []
    # Look for tags/categories in front matter style
    for pattern in [r"tags?:\s*\[([^\]]+)\]", r"categories?:\s*\[([^\]]+)\]"]:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            raw = match.group(1)
            categories.extend(
                t.strip().strip("\"'") for t in raw.split(",") if t.strip()
            )
    return categories


class MarkdownIngestor(BaseIngestor):
    """Ingest Markdown files from a directory tree."""

    source_name = "markdown"

    def __init__(
        self,
        *,
        source_label: Optional[str] = None,
        glob_pattern: str = "**/*.md",
        max_file_size: int = 500_000,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.source_label = source_label or "markdown"
        self.glob_pattern = glob_pattern
        self.max_file_size = max_file_size

    def ingest(self, path: str | Path) -> Iterator[dict[str, Any]]:
        """Yield documents from Markdown files.

        Args:
            path: Directory to scan for .md files, or a single .md file.

        Yields:
            Document dicts from each Markdown file.
        """
        path = Path(path)

        if path.is_file():
            doc = self._parse_file(path, path.parent)
            if doc:
                yield doc
            return

        if not path.is_dir():
            logger.error("Path does not exist: %s", path)
            return

        for md_file in sorted(path.glob(self.glob_pattern)):
            if md_file.stat().st_size > self.max_file_size:
                logger.debug("Skipping large file: %s", md_file)
                continue
            doc = self._parse_file(md_file, path)
            if doc:
                yield doc

    def _parse_file(self, file_path: Path, base_dir: Path) -> dict[str, Any] | None:
        """Parse a single Markdown file into a document dict."""
        try:
            content = file_path.read_text(errors="ignore")
        except Exception as exc:
            logger.warning("Failed to read %s: %s", file_path, exc)
            return None

        if len(content.strip()) < 20:
            return None

        title = _extract_title(content) or file_path.stem
        severity = _extract_severity(content)
        categories = _extract_categories(content)

        try:
            rel_path = str(file_path.relative_to(base_dir))
        except ValueError:
            rel_path = str(file_path)

        return {
            "source": self.source_label,
            "title": title,
            "path": rel_path,
            "content": content,
            "severity": severity,
            "categories": categories or None,
            "metadata": {
                "file": rel_path,
                "size": file_path.stat().st_size,
            },
        }
