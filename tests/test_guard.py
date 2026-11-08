"""Tests for the rules and the runner. Needs `semgrep` and `git` on PATH.

    python -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import run_scan  # noqa: E402

RULES = ROOT / "rules"
FIXTURES = ROOT / "tests" / "fixtures"
SEMGREP = os.environ.get("GUARD_SEMGREP", "semgrep")


def scan(path: Path) -> list[run_scan.Finding]:
    p = subprocess.run(
        [SEMGREP, "scan", "--config", str(RULES), "--json", "--quiet", "--metrics=off",
         "--disable-version-check", "--no-git-ignore", str(path)],
        capture_output=True, text=True,
    )
    assert p.returncode in (0, 1), p.stderr
    doc = json.loads(p.stdout)
    assert not doc["errors"], doc["errors"]
    return run_scan.parse_semgrep_json(doc)


class RuleTests(unittest.TestCase):
    def test_inline_annotated_tests_pass(self):
        p = subprocess.run([SEMGREP, "--test", "--metrics=off", "--disable-version-check", str(RULES)],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_fixtures(self):
        expected = {
            "pwn_scalar_trigger.yml": {"gha-pwn-request-checkout"},
            "pwn_list_trigger.yml": {"gha-pwn-request-checkout"},
            "pwn_quoted_on_key.yml": {"gha-pwn-request-checkout"},
            "injection_composite_action.yml": {"gha-script-injection-run"},
            "safe_pull_request_trigger.yml": set(),  # head checkout under plain `pull_request` is fine
            "safe_list_no_prt.yml": set(),
        }
        for name, want in expected.items():
            with self.subTest(name):
                got = {f.rule_id for f in scan(FIXTURES / name)}
                self.assertEqual(got, want)

    def test_duplicated_untrusted_context_regex_is_in_sync(self):
        text = (RULES / "gha-script-injection.yaml").read_text(encoding="utf-8")
        regexes = [l.strip() for l in text.splitlines() if l.strip().startswith("(?is).*?\\$\\{\\{")]
        self.assertEqual(len(regexes), 2)
        self.assertEqual(regexes[0], regexes[1])


class HelperTests(unittest.TestCase):
    def test_parse_diff_ranges(self):
        diff = (
            "diff --git a/.github/workflows/a.yml b/.github/workflows/a.yml\n"
            "--- a/.github/workflows/a.yml\n+++ b/.github/workflows/a.yml\n"
            "@@ -3,0 +4,2 @@ x\n+a\n+b\n"
            "@@ -10 +12 @@\n-c\n+d\n"
            "@@ -20,3 +21,0 @@\n-del\n-del\n-del\n"
            "--- a/gone.yml\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
        )
        self.assertEqual(
            run_scan.parse_diff_ranges(diff),
            {".github/workflows/a.yml": [(4, 5), (12, 12)]},
        )

    def test_overlap_uses_whole_finding_range(self):
        f = run_scan.Finding("a.yml", 10, 14, "r", "ERROR", "m")
        self.assertTrue(run_scan.overlaps(f, [(13, 13)]))  # change inside a multi-line run: block
        self.assertFalse(run_scan.overlaps(f, [(1, 9), (15, 20)]))

    def test_annotation_escaping(self):
        f = run_scan.Finding("dir,x:y/a.yml", 3, 3, "rule", "ERROR", "line1\nline2 100%")
        a = run_scan.annotation(f)
        self.assertNotIn("\n", a)
        self.assertIn("file=dir%2Cx%3Ay/a.yml", a)
        self.assertTrue(a.endswith("::line1%0Aline2 100%25"))

    def test_is_target(self):
        for p in (".github/workflows/ci.yml", ".github/actions/foo/action.yaml", "action.yml", "tools/x/action.yml"):
            self.assertTrue(run_scan.is_target(p), p)
        for p in ("docker-compose.yml", ".github/dependabot.yml", "src/workflows/ci.yml"):
            self.assertFalse(run_scan.is_target(p), p)

    def test_leading_dot_is_preserved(self):
        doc = {"results": [{"path": "./.github/workflows/a.yml", "check_id": "rules.my-rule",
                            "start": {"line": 1}, "end": {"line": 1},
                            "extra": {"severity": "ERROR", "message": "m"}}]}
        (f,) = run_scan.parse_semgrep_json(doc)
        self.assertEqual((f.path, f.rule_id), (".github/workflows/a.yml", "my-rule"))


VULN = 'echo "${{ github.event.pull_request.title }}"'


def sh(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


class EndToEnd(unittest.TestCase):
    """Old vulnerabilities must not block a PR; newly introduced ones must."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        sh("git", "init", "-q", "-b", "main", cwd=self.tmp)
        sh("git", "config", "user.email", "t@example.com", cwd=self.tmp)
        sh("git", "config", "user.name", "t", cwd=self.tmp)
        wf = self.tmp / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "old.yml").write_text(self._wf(VULN), encoding="utf-8")  # pre-existing problem
        (wf / "ok.yml").write_text(self._wf("echo hi"), encoding="utf-8")
        sh("git", "add", "-A", cwd=self.tmp)
        sh("git", "commit", "-qm", "base", cwd=self.tmp)
        self.base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.tmp, text=True).strip()
        sh("git", "checkout", "-qb", "pr", cwd=self.tmp)

    @staticmethod
    def _wf(cmd):
        return f"on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {cmd}\n"

    def run_guard(self, **extra):
        sh("git", "add", "-A", cwd=self.tmp)
        sh("git", "commit", "-qm", "pr", "--allow-empty", cwd=self.tmp)
        summary = self.tmp / "summary.md"
        env = {**os.environ, "GUARD_RULES_DIR": str(RULES), "GITHUB_WORKSPACE": str(self.tmp),
               "GUARD_BASE_SHA": self.base, "GITHUB_STEP_SUMMARY": str(summary), **extra}
        p = subprocess.run([sys.executable, str(ROOT / "scripts" / "run_scan.py")],
                           env=env, capture_output=True, text=True)
        return p, summary

    def test_pr_touching_unrelated_file_passes_despite_old_vuln(self):
        (self.tmp / "README.md").write_text("hi", encoding="utf-8")
        p, _ = self.run_guard()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("No issues found", p.stdout)

    def test_new_vuln_in_new_line_fails_and_annotates(self):
        (self.tmp / ".github/workflows/ok.yml").write_text(self._wf(VULN), encoding="utf-8")
        p, summary = self.run_guard()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("::error file=.github/workflows/ok.yml,line=6", p.stdout)
        self.assertIn("gha-script-injection-run", summary.read_text(encoding="utf-8"))

    def test_scope_all_reports_old_vuln(self):
        p, _ = self.run_guard(GUARD_SCOPE="all")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("old.yml", p.stdout)

    def test_fail_on_never(self):
        (self.tmp / ".github/workflows/ok.yml").write_text(self._wf(VULN), encoding="utf-8")
        p, _ = self.run_guard(GUARD_FAIL_ON="never")
        self.assertEqual(p.returncode, 0)
        self.assertIn("::error", p.stdout)  # still annotated


if __name__ == "__main__":
    unittest.main()
