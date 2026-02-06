"""CVE/NVD JSON ingestor.

Reads CVE data from NVD JSON feed format (both 1.1 and 2.0 schemas)
or a simple JSON array of CVE objects.

Expected input formats:

1. NVD API 2.0 response::

    {"vulnerabilities": [{"cve": {"id": "CVE-...", ...}}, ...]}

2. NVD 1.1 feed::

    {"CVE_Items": [{"cve": {"CVE_data_meta": {"ID": "CVE-..."}}, ...}, ...]}

3. Simple array::

    [{"id": "CVE-...", "description": "...", ...}, ...]
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterator

from .base import BaseIngestor

logger = logging.getLogger(__name__)


class CVEIngestor(BaseIngestor):
    """Ingest CVE/NVD vulnerability data."""

    source_name = "cve"

    def ingest(self, path: str | Path) -> Iterator[dict[str, Any]]:
        """Yield documents from a CVE JSON file.

        Args:
            path: Path to a JSON file containing CVE data.

        Yields:
            Document dicts with CVE information.
        """
        path = Path(path)
        if not path.exists():
            logger.error("CVE file not found: %s", path)
            return

        try:
            data = json.loads(path.read_text())
        except Exception as exc:
            logger.error("Failed to parse CVE JSON %s: %s", path, exc)
            return

        if isinstance(data, dict):
            # NVD 2.0 format
            if "vulnerabilities" in data:
                for entry in data["vulnerabilities"]:
                    doc = self._parse_nvd20(entry)
                    if doc:
                        yield doc
            # NVD 1.1 format
            elif "CVE_Items" in data:
                for entry in data["CVE_Items"]:
                    doc = self._parse_nvd11(entry)
                    if doc:
                        yield doc
            else:
                logger.warning("Unrecognized CVE JSON structure in %s", path)
        elif isinstance(data, list):
            # Simple array format
            for entry in data:
                doc = self._parse_simple(entry)
                if doc:
                    yield doc

    def _parse_nvd20(self, entry: dict) -> dict[str, Any] | None:
        """Parse an NVD 2.0 vulnerability entry."""
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        if not desc_text:
            return None

        # Extract CVSS severity
        severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                severity = cvss.get("baseSeverity", "").lower()
                if severity:
                    break

        # Extract CWE categories
        categories = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val and cwe_val != "NVD-CWE-noinfo":
                    categories.append(cwe_val)

        # Extract references
        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

        content = f"{cve_id}\n\n{desc_text}"
        if refs:
            content += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in refs[:10])

        return {
            "source": "cve",
            "title": cve_id,
            "path": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "content": content,
            "severity": severity or None,
            "categories": categories or None,
            "metadata": {
                "cve_id": cve_id,
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
                "references": refs[:10],
            },
        }

    def _parse_nvd11(self, entry: dict) -> dict[str, Any] | None:
        """Parse an NVD 1.1 CVE item."""
        cve = entry.get("cve", {})
        meta = cve.get("CVE_data_meta", {})
        cve_id = meta.get("ID", "")

        desc_data = cve.get("description", {}).get("description_data", [])
        desc_text = ""
        for d in desc_data:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and desc_data:
            desc_text = desc_data[0].get("value", "")

        if not desc_text:
            return None

        # Severity from impact
        severity = None
        impact = entry.get("impact", {})
        if "baseMetricV3" in impact:
            severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "").lower()
        elif "baseMetricV2" in impact:
            severity = impact["baseMetricV2"].get("severity", "").lower()

        # CWE categories
        categories = []
        for prob in cve.get("problemtype", {}).get("problemtype_data", []):
            for desc in prob.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val and cwe_val != "NVD-CWE-noinfo":
                    categories.append(cwe_val)

        content = f"{cve_id}\n\n{desc_text}"

        return {
            "source": "cve",
            "title": cve_id,
            "path": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "content": content,
            "severity": severity or None,
            "categories": categories or None,
            "metadata": {"cve_id": cve_id},
        }

    def _parse_simple(self, entry: dict) -> dict[str, Any] | None:
        """Parse a simple CVE object with id/title/description fields."""
        cve_id = entry.get("id") or entry.get("cve_id") or entry.get("title", "")
        desc = entry.get("description") or entry.get("content") or entry.get("summary", "")

        if not desc:
            return None

        content = f"{cve_id}\n\n{desc}" if cve_id else desc

        # Accept severity under various key names
        severity = (
            entry.get("severity")
            or entry.get("baseSeverity")
            or entry.get("cvss_severity")
        )
        if isinstance(severity, str):
            severity = severity.lower()

        categories = entry.get("categories") or entry.get("cwes") or entry.get("cwe")
        if isinstance(categories, str):
            categories = [categories]

        mitigations = entry.get("mitigations") or entry.get("mitigation") or entry.get("fix")
        if mitigations:
            if isinstance(mitigations, list):
                content += "\n\nMitigations:\n" + "\n".join(f"- {m}" for m in mitigations)
            else:
                content += f"\n\nMitigation: {mitigations}"

        return {
            "source": "cve",
            "title": cve_id or None,
            "content": content,
            "severity": severity,
            "categories": categories if isinstance(categories, list) else None,
            "metadata": {k: v for k, v in entry.items() if k not in ("description", "content", "summary")},
        }
