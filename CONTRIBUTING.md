# Contributing

Thanks for your interest in Grimoire.

## Getting Started

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Pull Requests

1. Fork the repo and create a branch for one logical change.
2. Include tests for new ingest or search behavior.
3. Run `pytest` before opening a PR.
4. Never include secrets, internal hostnames, or private data.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
