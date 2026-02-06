#!/usr/bin/env python3
"""Fetch and ingest reputable security data sources into Grimoire.

Downloads from public APIs and ingests directly — no manual file downloads needed.

Supported sources:
    nvd     -- Recent CVEs from NIST NVD API 2.0
    cwe     -- CWE catalog from MITRE (XML → parsed)
    owasp   -- OWASP Top 10 (bundled sample data)
    all     -- All of the above

Usage:
    python scripts/fetch_sources.py nvd              # Last 30 days of CVEs
    python scripts/fetch_sources.py nvd --days 90    # Last 90 days
    python scripts/fetch_sources.py cwe              # Full CWE catalog
    python scripts/fetch_sources.py all              # Everything
    python scripts/fetch_sources.py all --embeddings # + generate embeddings
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from grimoire.core import Grimoire
from grimoire.ingest.cve import CVEIngestor

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_CSV_URL = "https://cwe.mitre.org/data/csv/research-concepts.csv"


def fetch_nvd(
    days: int = 30,
    severity: str | None = None,
    max_results: int = 2000,
) -> list[dict]:
    """Fetch recent CVEs from the NVD API 2.0.

    Args:
        days: How many days back to fetch.
        severity: Optional CVSS severity filter (LOW, MEDIUM, HIGH, CRITICAL).
        max_results: Maximum number of CVEs to fetch.

    Returns:
        List of NVD 2.0 vulnerability entries.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": min(max_results, 2000),
    }
    if severity:
        params["cvssV3Severity"] = severity.upper()

    all_vulns = []
    start_index = 0

    while start_index < max_results:
        params["startIndex"] = start_index
        print(f"  Fetching NVD page (offset {start_index})...")

        try:
            resp = requests.get(NVD_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("NVD API error: %s", exc)
            print(f"  Error: {exc}")
            break

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        all_vulns.extend(vulns)
        total = data.get("totalResults", 0)
        start_index += len(vulns)

        if start_index >= total:
            break

        # NVD rate limit: 5 requests per 30 seconds without API key
        time.sleep(6)

    return all_vulns


def fetch_cwe() -> list[dict]:
    """Fetch the CWE catalog and return as document dicts.

    Uses the CWE research concepts CSV for a lightweight download.

    Returns:
        List of document dicts ready for Grimoire ingestion.
    """
    print("  Downloading CWE catalog...")
    try:
        resp = requests.get(CWE_CSV_URL, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("CWE download error: %s", exc)
        print(f"  Error: {exc}")
        return []

    lines = resp.text.strip().split("\n")
    if len(lines) < 2:
        return []

    # Parse CSV (first line is header)
    header = lines[0].split(",")
    docs = []

    for line in lines[1:]:
        # Simple CSV parse (CWE CSV doesn't have complex quoting)
        parts = line.split(",", len(header) - 1)
        if len(parts) < 3:
            continue

        cwe_id = parts[0].strip().strip('"')
        name = parts[1].strip().strip('"')
        description = parts[2].strip().strip('"') if len(parts) > 2 else ""

        if not cwe_id or not name:
            continue

        cwe_label = f"CWE-{cwe_id}" if not cwe_id.startswith("CWE") else cwe_id

        docs.append({
            "source": "cwe",
            "title": f"{cwe_label}: {name}",
            "path": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
            "content": f"{cwe_label}: {name}\n\n{description}",
            "severity": None,
            "categories": ["cwe"],
            "metadata": {"cwe_id": cwe_label},
        })

    return docs


def ingest_nvd(g: Grimoire, days: int = 30, severity: str | None = None) -> int:
    """Fetch and ingest NVD CVEs."""
    print(f"[+] Fetching CVEs from NVD (last {days} days)...")
    vulns = fetch_nvd(days=days, severity=severity)
    if not vulns:
        print("  No CVEs found.")
        return 0

    print(f"  Found {len(vulns)} CVEs. Ingesting...")

    # Convert to NVD 2.0 format for CVEIngestor
    ingestor = CVEIngestor()
    count = 0
    for entry in vulns:
        doc = ingestor._parse_nvd20(entry)
        if doc:
            doc_id = g.add_document(**doc)
            if doc_id is not None:
                count += 1

    print(f"  Ingested {count} CVEs.")
    return count


def ingest_cwe(g: Grimoire) -> int:
    """Fetch and ingest CWE catalog."""
    print("[+] Fetching CWE catalog from MITRE...")
    docs = fetch_cwe()
    if not docs:
        print("  No CWE entries found.")
        return 0

    print(f"  Found {len(docs)} CWE entries. Ingesting...")
    count = g.add_documents(docs)
    print(f"  Ingested {count} CWE entries.")
    return count


def ingest_owasp(g: Grimoire) -> int:
    """Ingest bundled OWASP Top 10 sample data."""
    sample_path = Path(__file__).resolve().parents[1] / "examples" / "sample_data" / "owasp_top10.json"
    if not sample_path.exists():
        print("  OWASP sample data not found.")
        return 0

    print("[+] Ingesting OWASP Top 10 sample data...")
    ingestor = CVEIngestor()
    count = ingestor.ingest_to_grimoire(g, sample_path)
    print(f"  Ingested {count} entries.")
    return count


def main():
    parser = argparse.ArgumentParser(
        description="Fetch and ingest security data into Grimoire"
    )
    parser.add_argument(
        "sources",
        nargs="+",
        choices=["nvd", "cwe", "owasp", "all"],
        help="Data sources to fetch",
    )
    parser.add_argument(
        "--db", default="grimoire.db", help="Database path (default: grimoire.db)"
    )
    parser.add_argument(
        "--days", type=int, default=30, help="Days of CVE history to fetch (default: 30)"
    )
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter NVD CVEs by CVSS severity",
    )
    parser.add_argument(
        "--embeddings",
        action="store_true",
        help="Generate embeddings after ingest (requires Ollama)",
    )
    args = parser.parse_args()

    sources = set(args.sources)
    if "all" in sources:
        sources = {"nvd", "cwe", "owasp"}

    g = Grimoire(db_path=args.db)
    total = 0

    if "owasp" in sources:
        total += ingest_owasp(g)

    if "cwe" in sources:
        total += ingest_cwe(g)

    if "nvd" in sources:
        total += ingest_nvd(g, days=args.days, severity=args.severity)

    if args.embeddings and total > 0:
        print("[+] Generating embeddings...")

        def progress(done, total_docs):
            pct = done / total_docs * 100 if total_docs else 0
            print(f"    [{pct:.0f}%] {done}/{total_docs}", end="\r")

        result = g.generate_embeddings(on_progress=progress)
        print()
        print(f"  Generated: {result['generated']}, Failed: {result['failed']}")

    status = g.index_status()
    print(f"\n[+] Final index: {status['document_count']} documents, "
          f"{status['embedding_count']} embeddings ({status['embedding_coverage']} coverage)")
    print(f"    Sources: {status['sources']}")

    g.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
