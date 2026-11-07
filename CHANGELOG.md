# Changelog

## 1.1.0

- Detects GitLab, npm, PyPI and SendGrid tokens, Anthropic/OpenAI-style keys, Slack and Discord webhooks, JWTs
  and credentials inside URLs
- Blocks `*.tfvars`, `*.keystore` and `.git-credentials`
- `githookguard.allow` (repeatable) exempts fixture paths from file checks
- Installable with pip (`githook-guard` command), CI on Linux and macOS

## 1.0.0

Initial release.
