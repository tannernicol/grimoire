#!/usr/bin/env python3
"""Example: Search the Grimoire knowledge base.

Usage:
    python examples/search_demo.py "SQL injection"
    python examples/search_demo.py "authentication bypass" --mode keyword
    python examples/search_demo.py "SSRF" --severity high
"""

import argparse
import sys
from pathlib import Path

# Allow running from the repo root without installing
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from grimoire.core import Grimoire


def main():
    parser = argparse.ArgumentParser(description="Search Grimoire knowledge base")
    parser.add_argument("query", nargs="?", help="Search query")
    parser.add_argument(
        "--db", default="grimoire.db", help="Database path (default: grimoire.db)"
    )
    parser.add_argument(
        "--mode",
        choices=["keyword", "semantic", "hybrid"],
        default="keyword",
        help="Search mode (default: keyword; use hybrid/semantic if embeddings exist)",
    )
    parser.add_argument("-k", "--limit", type=int, default=5, help="Max results")
    parser.add_argument("-s", "--severity", help="Filter by severity")
    parser.add_argument("--source", help="Filter by source")
    parser.add_argument("--status", action="store_true", help="Show index status")
    parser.add_argument("--health", action="store_true", help="Run health check")
    args = parser.parse_args()

    g = Grimoire(db_path=args.db)

    if args.status:
        import json
        status = g.index_status()
        print(json.dumps(status, indent=2))
        g.close()
        return

    if args.health:
        import json
        health = g.health_check()
        print(json.dumps(health, indent=2))
        g.close()
        return

    if not args.query:
        print("Usage: search_demo.py <query>")
        print("       search_demo.py --status")
        print("       search_demo.py --health")
        print()
        print("Example: search_demo.py 'SQL injection'")
        g.close()
        return

    print(f"\n=== Search: '{args.query}' (mode={args.mode}, limit={args.limit}) ===\n")

    results = g.search(
        args.query,
        mode=args.mode,
        limit=args.limit,
        severity=args.severity,
        source=args.source,
    )

    if not results:
        print("No results found.")
    else:
        for i, r in enumerate(results, 1):
            severity_str = f" [{r.severity.upper()}]" if r.severity else ""
            cats_str = f" ({', '.join(r.categories)})" if r.categories else ""
            print(f"{i}. [{r.score:.3f}]{severity_str} {r.title}{cats_str}")
            print(f"   Source: {r.source}")
            # Show a brief snippet
            snippet_lines = r.snippet.split("\n")
            for line in snippet_lines[:3]:
                print(f"   {line.strip()}")
            print()

    g.close()


if __name__ == "__main__":
    main()
