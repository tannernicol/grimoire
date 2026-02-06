# Grimoire

**Your LLM re-reads the same reference docs every conversation. Grimoire indexes them once.**

[![CI](https://github.com/tannernicol/grimoire/actions/workflows/ci.yml/badge.svg)](https://github.com/tannernicol/grimoire/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Grimoire is a hybrid search engine for security reference material — NIST frameworks, CWE catalogs, CVE feeds, audit findings, internal standards — backed by SQLite FTS5 and semantic embeddings. It exposes everything over [MCP](https://modelcontextprotocol.io/) so your LLM agent gets instant retrieval instead of a 50-page context dump.

Keyword search for exact matches. Semantic search for "what's related." Both in one query.

```
                          +------------------+
                          |   Data Sources   |
                          |  CVE  MD  CSV .. |
                          +--------+---------+
                                   |
                              ingest()
                                   |
                          +--------v---------+
                          |     SQLite DB    |
                          |  +------------+  |
                          |  | documents  |  |
                          |  +------------+  |
                          |  | docs_fts5  |  |  <-- FTS5 keyword index
                          |  +------------+  |
                          |  | embeddings |  |  <-- semantic vectors
                          |  +------------+  |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |   Search Engine  |
                          |                  |
                          |  keyword (BM25)  |
                          |  semantic (cos)  |
                          |  hybrid (both)   |
                          +--------+---------+
                                   |
                     +-------------+-------------+
                     |                           |
              +------v------+           +--------v--------+
              | Python API  |           |   MCP Server    |
              |             |           |                 |
              | Grimoire()  |           | grimoire_search |
              | .search()   |           | grimoire_status |
              | .add_doc()  |           | grimoire_quality|
              +-------------+           +-----------------+
```

## Quick Start

```bash
git clone https://github.com/tannernicol/grimoire.git
cd grimoire
pip install -e .

# Ingest sample data (OWASP Top 10)
python examples/ingest_cves.py

# Search
python examples/search_demo.py "SQL injection"
python examples/search_demo.py "access control" --severity critical
```

### Enable Semantic Search

Requires [Ollama](https://ollama.com) with `nomic-embed-text`:

```bash
ollama pull nomic-embed-text
python examples/ingest_cves.py --generate-embeddings
python examples/search_demo.py "authentication bypass" --mode hybrid
```

## Why Not Just Use RAG?

Most RAG setups do one thing: chunk documents, embed them, vector search. That works until you need an exact CVE number, a specific NIST control ID, or a CWE by name. Vector search alone misses exact matches.

Grimoire runs both:
- **FTS5** (BM25) for keyword precision — finds "CWE-89" when you search "CWE-89"
- **Semantic embeddings** (cosine similarity) for conceptual recall — finds SQL injection variants when you search "database manipulation"
- **Hybrid mode** combines both with configurable weighting (default 40/60 keyword/semantic)

Everything lives in a single SQLite file. No Postgres, no Pinecone, no cloud anything.

## Python API

```python
from grimoire.core import Grimoire

g = Grimoire("security_kb.db")

# Add documents
g.add_document(
    source="advisory",
    title="CVE-2024-1234",
    content="Buffer overflow in example library allows RCE via crafted input...",
    severity="critical",
    categories=["buffer-overflow", "RCE"],
)

# Search
results = g.search("buffer overflow", mode="hybrid", limit=10)
for r in results:
    print(f"[{r.score:.3f}] {r.title} ({r.severity})")

# Check index health
status = g.index_status()
health = g.health_check()
```

## Ingest Anything

Built-in ingestors for common security data formats:

```python
# CVE/NVD feeds (API 2.0, 1.1, or JSON array)
from grimoire.ingest.cve import CVEIngestor
CVEIngestor().ingest_to_grimoire(g, "cve_data.json")

# Markdown files (recursively scan directories)
from grimoire.ingest.markdown import MarkdownIngestor
MarkdownIngestor(source_label="audit-findings").ingest_to_grimoire(g, "findings/")

# CSV with column mapping
from grimoire.ingest.csv import CSVIngestor
CSVIngestor(
    source_label="vuln-db",
    column_map={"vuln_name": "title", "details": "content"},
).ingest_to_grimoire(g, "vulns.csv")
```

Add your own by subclassing `BaseIngestor`:

```python
from grimoire.ingest.base import BaseIngestor

class MyIngestor(BaseIngestor):
    source_name = "my-source"

    def ingest(self, path):
        for item in read_my_data(path):
            yield {
                "source": self.source_name,
                "title": item["name"],
                "content": item["description"],
                "severity": item.get("severity"),
                "categories": item.get("tags"),
            }
```

## MCP Integration

Grimoire ships an MCP server so LLM agents can search your knowledge base mid-conversation.

```bash
# Start the server
grimoire-mcp --db security_kb.db
```

Add to Claude Code or Claude Desktop:

```json
{
  "mcpServers": {
    "grimoire": {
      "command": "grimoire-mcp",
      "args": ["--db", "/path/to/security_kb.db"]
    }
  }
}
```

| Tool | What it does |
|------|-------------|
| `grimoire_search` | Keyword, semantic, or hybrid search with severity/source filters |
| `grimoire_index_status` | Document count, embedding coverage, sources, last update |
| `grimoire_quality` | Health check; optionally test a query for result quality |

## Configuration

```yaml
database:
  path: grimoire.db

ollama:
  url: http://localhost:11434
  model: nomic-embed-text

search:
  default_mode: hybrid
  semantic_weight: 0.6      # 60% semantic, 40% keyword
  default_limit: 20
  min_similarity: 0.3

quality:
  min_cases: 5
  gate_on_missing_eval: false
```

## Search Algorithm

1. **FTS5 keyword** — BM25 on title, content, and categories
2. **Semantic** — cosine similarity between query and document embeddings (via Ollama `nomic-embed-text`)
3. **Score fusion** — `hybrid = (0.4 * normalized_bm25) + (0.6 * cosine_sim)`
4. **Dedup** — merge by document ID, sum scores
5. **Filter** — min score, severity, source, max results

## Requirements

- Python 3.10+
- SQLite with FTS5 (included in Python's `sqlite3`)
- [Ollama](https://ollama.com) + `nomic-embed-text` (only needed for semantic/hybrid search — keyword works without it)

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
