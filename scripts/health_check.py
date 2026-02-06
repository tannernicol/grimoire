#!/usr/bin/env python3
"""Database integrity check for Grimoire.

Verifies SQLite integrity, FTS sync, orphaned embeddings, and
optionally rebuilds the FTS index if issues are found.

Usage:
    python scripts/health_check.py
    python scripts/health_check.py --db /path/to/grimoire.db
    python scripts/health_check.py --rebuild-fts
    python scripts/health_check.py --json
"""

import argparse
import json
import sys
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from grimoire.core import Grimoire


def main():
    parser = argparse.ArgumentParser(description="Grimoire database health check")
    parser.add_argument(
        "--db", default="grimoire.db", help="Database path (default: grimoire.db)"
    )
    parser.add_argument(
        "--rebuild-fts",
        action="store_true",
        help="Rebuild FTS index if issues are found",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        result = {"status": "error", "message": f"Database not found: {db_path}"}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Error: {result['message']}")
        return 1

    g = Grimoire(db_path=args.db)
    health = g.health_check()

    if args.rebuild_fts and health.get("issues"):
        fts_issues = [i for i in health["issues"] if "FTS" in i]
        if fts_issues:
            print("[*] Rebuilding FTS index...")
            if g.rebuild_fts():
                health["fts_rebuilt"] = True
                # Re-check after rebuild
                health = g.health_check()
                health["fts_rebuilt"] = True
            else:
                health["fts_rebuild_failed"] = True

    if args.json:
        print(json.dumps(health, indent=2))
    else:
        status_icon = "OK" if health["status"] == "healthy" else "DEGRADED"
        print(f"Status: {status_icon}")
        print(f"Database: {health.get('database', args.db)}")
        print(f"Documents: {health.get('document_count', 0)}")
        print(f"Embeddings: {health.get('embedding_count', 0)}")
        print(f"Coverage: {health.get('embedding_coverage', '0%')}")

        if health.get("sources"):
            print(f"Sources: {health['sources']}")

        if health.get("issues"):
            print(f"\nIssues ({len(health['issues'])}):")
            for issue in health["issues"]:
                print(f"  - {issue}")
        else:
            print("\nNo issues found.")

        if health.get("fts_rebuilt"):
            print("\nFTS index was rebuilt successfully.")

    g.close()
    return 0 if health["status"] == "healthy" else 1


if __name__ == "__main__":
    sys.exit(main())
