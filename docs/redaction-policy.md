# Redaction Policy

Sanitize all content before publishing examples, reports, screenshots, and docs.

## Always Redact

- Emails and usernames
- Private IP addresses
- Internal domains and hostnames
- API keys, tokens, and secrets
- Customer or proprietary incident details

## Use These Replacements

- Email: `user@example.com`
- Domain: `example.com` or `example.internal`
- IP: `10.0.0.0`
- Secrets: `REDACTED`

## Verification

Run:

```bash
python scripts/redact.py --self-check
```
