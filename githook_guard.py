#!/usr/bin/env python3
"""githook-guard - one-command pre-commit protection against leaking secrets.

    python3 githook_guard.py install      # in your repository
    python3 githook_guard.py uninstall

Before every commit it checks the staged changes for secrets, private key and
.env files, oversized files and a personal e-mail identity, and blocks the
commit if something is wrong. Standard library only (needs the git command).
Bypass once with `git commit --no-verify`.
"""
import argparse
import fnmatch
import os
import re
import shutil
import stat
import subprocess
import sys

__version__ = "1.1.0"
MARKER = "# githook-guard managed hook"
HOOK_TOOL = "githook_guard.py"
IGNORE_MARK = "githook-guard:ignore"
DEFAULT_MAX_MB = 5.0

FORBIDDEN_NAMES = re.compile(
    r"(?i)(^|/)(\.env(\.(?!example$|sample$|template$|dist$)[^/]+)?|id_(rsa|dsa|ecdsa|ed25519)|"
    r"[^/]+\.(pem|key|p12|pfx|jks|kdbx|ovpn)|\.htpasswd|credentials\.json|terraform\.tfstate(\.backup)?|"
    r"\.netrc|\.pgpass|\.git-credentials|[^/]+\.(tfvars|keystore)|secrets?\.(ya?ml|json|toml))$")
SECRET_PATTERNS = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("webhook-url", re.compile(
        r"https://(?:hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}|"
        r"(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{50,})")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("url-credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@'\"/]{6,})@[^\s'\"]+")),
    ("hardcoded-secret", re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
]
PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxxx|<.*>|\$\{|dummy|^(?:pass(?:word)?|secret|\*+)$")
CHECKED_VALUE = ("hardcoded-secret", "url-credentials")
PERSONAL_DOMAINS = {"gmail.com", "googlemail.com", "icloud.com", "me.com", "outlook.com", "hotmail.com",
                    "live.com", "yahoo.com", "proton.me", "protonmail.com", "pm.me", "hey.com", "aol.com"}


def git(args, cwd, **kw):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, **kw)


def repo_root(cwd):
    r = git(["rev-parse", "--show-toplevel"], cwd, text=True)
    if r.returncode != 0:
        raise RuntimeError("not inside a git repository")
    return r.stdout.strip()


def config_value(cwd, key, default):
    r = git(["config", "--get", key], cwd, text=True)
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else default


def allowed_paths(cwd):
    """Glob patterns from `git config githookguard.allow` (repeatable) that are exempt from file checks."""
    r = git(["config", "--get-all", "githookguard.allow"], cwd, text=True)
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()] if r.returncode == 0 else []


def is_allowed(path, patterns):
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p) for p in patterns)


def staged_files(cwd):
    r = git(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], cwd)
    return [n for n in r.stdout.decode(errors="replace").split("\0") if n]


def scan_text(text):
    hits = []
    for no, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARK in line:
            continue
        for name, rx in SECRET_PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            if name in CHECKED_VALUE and PLACEHOLDER.search(m.group(1)):
                continue
            hits.append((no, name))
    return hits


def check_identity(cwd, mode):
    """Return a message when the configured commit e-mail looks personal."""
    if mode == "off":
        return None
    email = config_value(cwd, "user.email", "").lower()
    domain = email.rsplit("@", 1)[-1]
    if email and "noreply" not in email and domain in PERSONAL_DOMAINS:
        return "commit e-mail %s is a personal address and will be public in the history" % email
    return None


def check(cwd=None, out=sys.stderr):
    """Inspect staged changes. Returns exit code (0 = allow, 1 = block)."""
    cwd = repo_root(cwd or os.getcwd())
    max_mb = float(config_value(cwd, "githookguard.maxsizemb", DEFAULT_MAX_MB))
    id_mode = config_value(cwd, "githookguard.identity", "warn")
    problems, warnings = [], []
    allow = allowed_paths(cwd)
    for path in staged_files(cwd):
        if is_allowed(path, allow):
            continue
        if FORBIDDEN_NAMES.search(path):
            problems.append("%s: sensitive file type must not be committed" % path)
            continue
        size = git(["cat-file", "-s", ":" + path], cwd, text=True)
        if size.returncode == 0 and size.stdout.strip().isdigit():
            n = int(size.stdout.strip())
            if n > max_mb * 1024 * 1024:
                problems.append("%s: %.1f MB exceeds the %.1f MB limit" % (path, n / 1048576, max_mb))
                continue
        blob = git(["show", ":" + path], cwd)
        if blob.returncode != 0 or b"\x00" in blob.stdout[:4096]:
            continue
        for no, rule in scan_text(blob.stdout.decode("utf-8", errors="replace")):
            problems.append("%s:%d: possible secret (%s)" % (path, no, rule))
    msg = check_identity(cwd, id_mode)
    if msg:
        (problems if id_mode == "block" else warnings).append(msg)
    for w in warnings:
        print("githook-guard: warning: %s" % w, file=out)
    if problems:
        print("githook-guard: commit blocked:", file=out)
        for p in problems:
            print("  - %s" % p, file=out)
        print("Fix the issues, mark a false positive with `%s`, or bypass once with "
              "`git commit --no-verify`." % IGNORE_MARK, file=out)
        return 1
    return 0


def hooks_dir(cwd):
    r = git(["rev-parse", "--git-path", "hooks"], cwd, text=True)
    path = r.stdout.strip()
    return path if os.path.isabs(path) else os.path.join(cwd, path)


HOOK_SCRIPT = """#!/bin/sh
%s
PY=$(command -v python3 || command -v python)
exec "$PY" "$(dirname "$0")/%s" check
""" % (MARKER, HOOK_TOOL)


def install(cwd=None, force=False):
    cwd = repo_root(cwd or os.getcwd())
    hdir = hooks_dir(cwd)
    os.makedirs(hdir, exist_ok=True)
    hook = os.path.join(hdir, "pre-commit")
    if os.path.exists(hook):
        with open(hook, errors="replace") as fh:
            ours = MARKER in fh.read()
        if not ours:
            if not force:
                raise RuntimeError("a different pre-commit hook already exists; use --force to back it up and replace it")
            shutil.copy2(hook, hook + ".backup")
    shutil.copy2(os.path.abspath(__file__), os.path.join(hdir, HOOK_TOOL))
    with open(hook, "w") as fh:
        fh.write(HOOK_SCRIPT)
    os.chmod(hook, os.stat(hook).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook


def uninstall(cwd=None):
    cwd = repo_root(cwd or os.getcwd())
    hdir = hooks_dir(cwd)
    hook = os.path.join(hdir, "pre-commit")
    removed = False
    if os.path.exists(hook):
        with open(hook, errors="replace") as fh:
            if MARKER in fh.read():
                os.remove(hook)
                removed = True
    tool = os.path.join(hdir, HOOK_TOOL)
    if removed and os.path.exists(tool):
        os.remove(tool)
    return removed


def main(argv=None):
    ap = argparse.ArgumentParser(description="Pre-commit protection against leaking secrets.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("install", help="install the pre-commit hook in the current repository")
    p.add_argument("--force", action="store_true", help="replace an existing foreign hook (backed up)")
    sub.add_parser("uninstall", help="remove the hook installed by githook-guard")
    sub.add_parser("check", help="check staged changes now (this is what the hook runs)")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "install":
            print("githook-guard: installed %s" % install(force=args.force))
            return 0
        if args.cmd == "uninstall":
            print("githook-guard: %s" % ("hook removed" if uninstall() else "no githook-guard hook found"))
            return 0
        return check()
    except RuntimeError as exc:
        print("githook-guard: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
