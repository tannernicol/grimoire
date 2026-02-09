# Contributing

Thanks for contributing to Grimoire.

## Workflow

1. Fork the repository and create a branch for one logical change.
2. Add or update tests and docs alongside code changes.
3. Run local validation before opening a pull request.
4. Open a PR with clear problem statement and validation notes.

## Local Validation

```bash
pip install -e ".[dev]"
pytest
pre-commit run --all-files
python scripts/redact.py --self-check
```

## Pull Request Expectations

- Keep PRs focused and easy to review.
- Include reproducible examples for new ingest/search behavior.
- Avoid breaking CLI and MCP contracts without docs updates.
- Never include secrets, internal hostnames, private IPs, or customer data.

## Starter Tasks

- See docs/good-first-issues.md for contributor-friendly tasks with acceptance criteria.
- Follow docs/release-policy.md when preparing release-impacting changes.
