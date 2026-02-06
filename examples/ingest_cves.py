#!/usr/bin/env python3
"""Example: Ingest OWASP Top 10 sample data into Grimoire.

Usage:
    python examples/ingest_cves.py
    python examples/ingest_cves.py --db my_kb.db
    python examples/ingest_cves.py --generate-embeddings
"""

import argparse
import sys
from pathlib import Path

# Allow running from the repo root without installing
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from grimoire.core import Grimoire
from grimoire.ingest.cve import CVEIngestor


def main():
    parser = argparse.ArgumentParser(description="Ingest OWASP Top 10 sample data")
    parser.add_argument(
        "--db", default="grimoire.db", help="Database path (default: grimoire.db)"
    )
    parser.add_argument(
        "--data",
        default=str(Path(__file__).parent / "sample_data" / "owasp_top10.json"),
        help="Path to CVE/vulnerability JSON data",
    )
    parser.add_argument(
        "--generate-embeddings",
        action="store_true",
        help="Generate embeddings after ingest (requires Ollama)",
    )
    args = parser.parse_args()

    print(f"[+] Opening Grimoire database: {args.db}")
    g = Grimoire(db_path=args.db)

    print(f"[+] Ingesting data from: {args.data}")
    ingestor = CVEIngestor()
    count = ingestor.ingest_to_grimoire(g, args.data)
    print(f"[+] Ingested {count} documents")

    status = g.index_status()
    print(f"[+] Index status:")
    print(f"    Documents: {status['document_count']}")
    print(f"    Sources: {status['sources']}")

    if args.generate_embeddings:
        print("[+] Generating embeddings (requires Ollama with nomic-embed-text)...")

        def progress(done, total):
            pct = done / total * 100
            print(f"    [{pct:.0f}%] {done}/{total}", end="\r")

        result = g.generate_embeddings(on_progress=progress)
        print()
        print(f"[+] Embeddings: {result['generated']} generated, {result['failed']} failed")

    print("[+] Done! Run `python examples/search_demo.py` to search.")
    g.close()


if __name__ == "__main__":
    main()
