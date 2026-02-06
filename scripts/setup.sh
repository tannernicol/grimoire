#!/usr/bin/env bash
set -euo pipefail

# Grimoire setup script
# Installs the package, pulls the embedding model, and ingests sample data.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[+] Installing grimoire..."
cd "$REPO_DIR"
pip install -e . 2>&1 | tail -1

echo "[+] Checking Ollama..."
if command -v ollama &>/dev/null; then
    if curl -s http://localhost:11434/api/tags &>/dev/null; then
        echo "[+] Ollama is running"
        echo "[+] Pulling nomic-embed-text model..."
        ollama pull nomic-embed-text 2>&1 | tail -1
    else
        echo "[!] Ollama is installed but not running. Start it with: ollama serve"
        echo "    Semantic search will be unavailable until Ollama is running."
    fi
else
    echo "[!] Ollama not found. Install from https://ollama.com"
    echo "    Keyword search works without it. Semantic/hybrid search requires Ollama."
fi

echo "[+] Ingesting sample data..."
python "$REPO_DIR/examples/ingest_cves.py" --db "$REPO_DIR/grimoire.db"

echo ""
echo "[+] Setup complete!"
echo ""
echo "Try searching:"
echo "  python examples/search_demo.py 'SQL injection'"
echo "  python examples/search_demo.py 'access control' --severity critical"
echo "  python examples/search_demo.py --status"
echo ""
echo "To use with MCP:"
echo "  python -m grimoire.mcp.server --db grimoire.db"
