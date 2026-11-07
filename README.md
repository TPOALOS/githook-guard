# githook-guard

One-command **pre-commit protection** against leaking secrets. It installs a git hook
that checks your staged changes before every commit and blocks the commit when
something looks wrong. One file, standard library only (requires the `git` command).

## Install

```bash
cd your-repo
python3 /path/to/githook_guard.py install
# or: pip install git+https://github.com/TPOALOS/githook-guard && githook-guard install
```

This copies the tool into `.git/hooks/` and creates a `pre-commit` hook, so it keeps
working even if you move or delete the original file. Remove it any time with
`python3 githook_guard.py uninstall`. An existing foreign `pre-commit` hook is never
overwritten unless you pass `--force` (it is backed up as `pre-commit.backup`).

## What it blocks

| Check | Details |
|-------|---------|
| Sensitive files | `.env` (not `.env.example`), `id_rsa`/`id_ed25519`..., `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx`, `*.tfvars`, `.netrc`, `.pgpass`, `.git-credentials`, `.htpasswd`, `credentials.json`, `terraform.tfstate` |
| Secrets in content | AWS access key IDs, GitHub/GitLab/Slack/Stripe/Google/npm/PyPI/SendGrid tokens, Anthropic/OpenAI-style keys, Slack/Discord webhooks, JWTs, credentials inside URLs, private key headers, `password/token/api_key = "..."` assignments |
| Large files | over 5 MB by default |
| Personal e-mail identity | warns when `user.email` is a personal address (gmail, icloud, outlook, ...) |

Example when blocked:

```
githook-guard: commit blocked:
  - src/config.py:12: possible secret (aws-access-key-id)
  - .env: sensitive file type must not be committed
Fix the issues, mark a false positive with `githook-guard:ignore`, or bypass once with `git commit --no-verify`.
```

Matched secret values are never printed.

## Settings

Stored with plain `git config` (per repository):

```bash
git config githookguard.maxsizemb 10        # size limit in MB (default 5)
git config githookguard.identity block      # warn (default) | block | off
git config --add githookguard.allow 'tests/fixtures/*'   # exempt paths (glob or file name), repeatable
```

Add `githook-guard:ignore` in a comment on a line to skip a known false positive.

## Limits

It is a safety net, not a full scanner: pattern based, so it can miss secrets and can
raise false positives. It only checks what is staged, and anyone can bypass a local hook
with `--no-verify`. Rotate any credential that was ever committed.

## Tests

Tests create throwaway repositories and run real `git commit` commands:

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
