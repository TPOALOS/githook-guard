import io
import os
import shutil
import subprocess
import tempfile
import unittest

import githook_guard as gg

HAVE_GIT = shutil.which("git") is not None
ENV = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def run(args, cwd, **kw):
    return subprocess.run(args, cwd=cwd, env=ENV, capture_output=True, text=True, **kw)


def make_repo(email="123+me@users.noreply.github.com"):
    d = tempfile.mkdtemp()
    run(["git", "init", "-q", "-b", "main"], d)
    run(["git", "config", "user.name", "me"], d)
    run(["git", "config", "user.email", email], d)
    return d


def stage(repo, name, text="x\n", binary=False):
    p = os.path.join(repo, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb" if binary else "w") as fh:
        fh.write(text)
    run(["git", "add", "-f", name], repo)


def do_check(repo):
    buf = io.StringIO()
    code = gg.check(repo, out=buf)
    return code, buf.getvalue()


class PatternTests(unittest.TestCase):
    def test_forbidden_names(self):
        for bad in (".env", "app/.env.production", "id_rsa", "keys/server.pem", "a/b.key", "terraform.tfstate", ".netrc"):
            self.assertTrue(gg.FORBIDDEN_NAMES.search(bad), bad)
        for ok in (".env.example", ".env.sample", "id_rsa.pub", "environment.py", "monkey.txt", "README.md"):
            self.assertFalse(gg.FORBIDDEN_NAMES.search(ok), ok)

    def test_scan_text(self):
        self.assertEqual(gg.scan_text("k = %s" % AWS), [(1, "aws-access-key-id")])
        self.assertEqual(gg.scan_text("k = %s  # githook-guard:ignore" % AWS), [])
        self.assertEqual(gg.scan_text('password = "your_password_here"'), [])
        self.assertEqual(gg.scan_text('password = "hunter2hunter2"')[0][1], "hardcoded-secret")  # githook-guard:ignore secretscan:ignore


def tok(*parts):
    return "".join(parts)


NEW = {
    "gitlab-token": tok("glpat-", "abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
    "npm-token": tok("npm_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),  # secretscan:ignore
    "sendgrid-key": tok("SG.", "a" * 22, ".", "b" * 43),
    "anthropic-key": tok("sk-ant-", "api03-abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
    "openai-key": tok("sk-", "proj-", "abcdEFGH1234ijklMNOP5678qrstUVWX"),  # secretscan:ignore
    "webhook-url": tok("https://hooks.slack", ".com/services/T01ABCDEF/B02GHIJKL/", "x" * 24),
    "jwt": tok("eyJ", "hbGciOiJIUzI1NiJ9", ".eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".", "abcdEFGH1234ijkl"),
    "url-credentials": tok("postgres://", "admin:", "S3cr3tPassw0rd", "@db.internal:5432/app"),
}


class NewPatternTests(unittest.TestCase):
    def test_new_detectors(self):
        for rule, value in NEW.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, [r for _, r in gg.scan_text("x = %s" % value)])

    def test_placeholders_and_plain_urls_ok(self):
        for text in ("https://example.com/x", "postgres://user:password@localhost/db",
                     "postgres://user:${PASS}@localhost/db", "sk-short"):
            self.assertEqual(gg.scan_text(text), [], text)

    def test_new_forbidden_names(self):
        for bad in ("infra/prod.tfvars", ".git-credentials", "android/release.keystore"):
            self.assertTrue(gg.FORBIDDEN_NAMES.search(bad), bad)
        for ok in ("infra/prod.tfvars.example", "keystore.md", "tfvars.py"):
            self.assertFalse(gg.FORBIDDEN_NAMES.search(ok), ok)


@unittest.skipUnless(HAVE_GIT, "git not installed")
class AllowListTests(unittest.TestCase):
    def setUp(self):
        self.repo = make_repo()

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_allow_glob_exempts_fixtures(self):
        stage(self.repo, "tests/fixtures/leaky.txt", "k = %s\n" % AWS)
        self.assertEqual(do_check(self.repo)[0], 1)
        run(["git", "config", "--add", "githookguard.allow", "tests/fixtures/*"], self.repo)
        self.assertEqual(do_check(self.repo)[0], 0)

    def test_allow_by_basename_and_forbidden_name(self):
        stage(self.repo, "deploy/prod.tfvars", "region = 1\n")
        self.assertEqual(do_check(self.repo)[0], 1)
        run(["git", "config", "--add", "githookguard.allow", "prod.tfvars"], self.repo)
        self.assertEqual(do_check(self.repo)[0], 0)

    def test_allow_does_not_exempt_other_files(self):
        run(["git", "config", "--add", "githookguard.allow", "tests/*"], self.repo)
        stage(self.repo, "src/a.py", "k = %s\n" % AWS)
        self.assertEqual(do_check(self.repo)[0], 1)


@unittest.skipUnless(HAVE_GIT, "git not installed")
class CheckTests(unittest.TestCase):
    def setUp(self):
        self.repo = make_repo()

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_clean_commit_allowed(self):
        stage(self.repo, "a.txt", "hello\n")
        self.assertEqual(do_check(self.repo)[0], 0)

    def test_secret_blocked_with_location(self):
        stage(self.repo, "src/a.py", "x = 1\nkey = '%s'\n" % AWS)
        code, text = do_check(self.repo)
        self.assertEqual(code, 1)
        self.assertIn("src/a.py:2", text)
        self.assertNotIn(AWS, text)

    def test_env_file_blocked_but_example_allowed(self):
        stage(self.repo, ".env", "A=1\n")
        self.assertEqual(do_check(self.repo)[0], 1)
        run(["git", "reset", "-q"], self.repo)
        os.remove(os.path.join(self.repo, ".env"))
        stage(self.repo, ".env.example", "A=\n")
        self.assertEqual(do_check(self.repo)[0], 0)

    def test_large_file_blocked_and_limit_configurable(self):
        stage(self.repo, "big.bin", b"a" * (2 * 1024 * 1024 + 10), binary=True)
        self.assertEqual(do_check(self.repo)[0], 0)
        run(["git", "config", "githookguard.maxsizemb", "1"], self.repo)
        self.assertEqual(do_check(self.repo)[0], 1)

    def test_identity_modes(self):
        run(["git", "config", "user.email", "jane@gmail.com"], self.repo)
        stage(self.repo, "a.txt")
        code, text = do_check(self.repo)
        self.assertEqual(code, 0)
        self.assertIn("warning", text)
        run(["git", "config", "githookguard.identity", "block"], self.repo)
        self.assertEqual(do_check(self.repo)[0], 1)
        run(["git", "config", "githookguard.identity", "off"], self.repo)
        self.assertEqual(do_check(self.repo)[0], 0)

    def test_binary_content_not_scanned(self):
        stage(self.repo, "b.dat", b"\x00" + AWS.encode(), binary=True)
        self.assertEqual(do_check(self.repo)[0], 0)


@unittest.skipUnless(HAVE_GIT and shutil.which("python3"), "git or python3 missing")
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.repo = make_repo()

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_install_uninstall(self):
        hook = gg.install(self.repo)
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(hook), gg.HOOK_TOOL)))
        self.assertTrue(gg.uninstall(self.repo))
        self.assertFalse(os.path.exists(hook))
        self.assertFalse(gg.uninstall(self.repo))

    def test_foreign_hook_protected(self):
        hdir = gg.hooks_dir(self.repo)
        os.makedirs(hdir, exist_ok=True)
        foreign = os.path.join(hdir, "pre-commit")
        with open(foreign, "w") as fh:
            fh.write("#!/bin/sh\necho mine\n")
        with self.assertRaises(RuntimeError):
            gg.install(self.repo)
        gg.install(self.repo, force=True)
        self.assertTrue(os.path.exists(foreign + ".backup"))

    def test_real_commit_is_blocked_then_allowed(self):
        gg.install(self.repo)
        stage(self.repo, "leak.py", "k = '%s'\n" % AWS)
        r = run(["git", "commit", "-q", "-m", "x"], self.repo)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("commit blocked", r.stderr)
        run(["git", "reset", "-q"], self.repo)
        stage(self.repo, "ok.py", "k = 1\n")
        r = run(["git", "commit", "-q", "-m", "ok"], self.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        stage(self.repo, "leak2.py", "k = '%s'\n" % AWS)
        r = run(["git", "commit", "-q", "--no-verify", "-m", "bypass"], self.repo)
        self.assertEqual(r.returncode, 0)


class CliTests(unittest.TestCase):
    def test_outside_repo(self):
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                env_backup = os.environ.get("GIT_CEILING_DIRECTORIES")
                os.environ["GIT_CEILING_DIRECTORIES"] = os.path.dirname(d)
                self.assertEqual(gg.main(["check"]), 2)
            finally:
                os.chdir(old)
                if env_backup is None:
                    os.environ.pop("GIT_CEILING_DIRECTORIES", None)
                else:
                    os.environ["GIT_CEILING_DIRECTORIES"] = env_backup


if __name__ == "__main__":
    unittest.main()
