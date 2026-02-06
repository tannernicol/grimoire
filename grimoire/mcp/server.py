"""MCP server exposing Grimoire search tools to LLMs.

Tools:
    grimoire_search  -- Search the knowledge base (keyword/semantic/hybrid)
    grimoire_index_status -- Show index stats
    grimoire_quality -- Run quality check on search results

Usage:
    python -m grimoire.mcp.server --db /path/to/grimoire.db
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from ..core import Grimoire

logger = logging.getLogger(__name__)

server = Server("grimoire-mcp")
_grimoire: Grimoire | None = None


def _get_grimoire() -> Grimoire:
    global _grimoire
    if _grimoire is None:
        db_path = os.environ.get("GRIMOIRE_DB", "grimoire.db")
        config_path = os.environ.get("GRIMOIRE_CONFIG")
        _grimoire = Grimoire(
            db_path=db_path,
            config_path=config_path,
        )
    return _grimoire


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="grimoire_search",
            description="Search the Grimoire security knowledge base. Supports keyword (FTS5), semantic (embedding), and hybrid search modes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (natural language or keywords)",
                    },
                    "mode": {
                        "type": "string",
                        "description": "Search mode: keyword, semantic, or hybrid (default)",
                        "enum": ["keyword", "semantic", "hybrid"],
                        "default": "hybrid",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results (default 10)",
                        "default": 10,
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: critical, high, medium, low",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "source": {
                        "type": "string",
                        "description": "Filter by data source (e.g., 'cve', 'advisory', 'markdown')",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="grimoire_index_status",
            description="Show Grimoire index statistics: document count, embedding coverage, data sources, last update times.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="grimoire_quality",
            description="Run a quality and health check on the Grimoire knowledge base. Reports integrity issues, FTS sync status, and embedding coverage.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Optional: test search query to evaluate result quality",
                    },
                },
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        g = _get_grimoire()

        if name == "grimoire_search":
            query = arguments.get("query", "")
            mode = arguments.get("mode", "hybrid")
            limit = arguments.get("limit", 10)
            severity = arguments.get("severity")
            source = arguments.get("source")

            results = g.search(
                query,
                mode=mode,
                limit=limit,
                severity=severity,
                source=source,
            )

            formatted = []
            for r in results:
                entry = {
                    "score": round(r.score, 3),
                    "title": r.title,
                    "snippet": r.snippet[:500],
                    "source": r.source,
                }
                if r.severity:
                    entry["severity"] = r.severity
                if r.categories:
                    entry["categories"] = r.categories
                if r.metadata:
                    entry["metadata"] = r.metadata
                formatted.append(entry)

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"query": query, "mode": mode, "results": formatted},
                        indent=2,
                    ),
                )
            ]

        elif name == "grimoire_index_status":
            status = g.index_status()
            return [TextContent(type="text", text=json.dumps(status, indent=2))]

        elif name == "grimoire_quality":
            health = g.health_check()

            # Optionally run a test query
            query = arguments.get("query")
            if query:
                results = g.search(query, limit=5)
                health["test_query"] = {
                    "query": query,
                    "result_count": len(results),
                    "top_score": round(results[0].score, 3) if results else 0,
                    "results": [
                        {"title": r.title, "score": round(r.score, 3)}
                        for r in results
                    ],
                }

            return [TextContent(type="text", text=json.dumps(health, indent=2))]

    except Exception as exc:
        return [TextContent(type="text", text=f"Error: {exc}")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _run_server():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main():
    parser = argparse.ArgumentParser(description="Grimoire MCP Server")
    parser.add_argument("--db", help="Path to grimoire database", default=None)
    parser.add_argument("--config", help="Path to config YAML", default=None)
    args = parser.parse_args()

    if args.db:
        os.environ["GRIMOIRE_DB"] = args.db
    if args.config:
        os.environ["GRIMOIRE_CONFIG"] = args.config

    asyncio.run(_run_server())


if __name__ == "__main__":
    main()
