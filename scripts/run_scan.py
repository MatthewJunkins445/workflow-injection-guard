#!/usr/bin/env python3
"""Run the Workflow Injection Guard rules against a PR and report findings.

Reads configuration from environment variables (never from argv/expressions, so the
action itself cannot be script-injected through its own inputs):

  GUARD_RULES_DIR   directory with the Semgrep rules          (required)
  GUARD_SCOPE       changed-lines | changed-files | all       (default changed-lines)
  GUARD_FAIL_ON     error | warning | never                   (default error)
  GUARD_BASE_SHA    base commit of the PR (needed for the two "changed-*" scopes)
  GUARD_HEAD_SHA    head commit of the PR                     (default HEAD)
  GUARD_SARIF_OUT   optional path; Semgrep SARIF is written here
  GUARD_SEMGREP     semgrep executable                        (default "semgrep")
  GITHUB_WORKSPACE  repo checkout to scan                     (default cwd)
  GITHUB_STEP_SUMMARY  set by Actions; a Markdown report is appended to it

Exit codes: 0 = clean (or fail-on=never), 1 = findings at/above fail-on, 2 = tool error.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Files that can contain `run:` / `script:` steps.
TARGET_GLOBS = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "*/action.yml",
    "*/action.yaml",
    "action.yml",
    "action.yaml",
    ".github/actions/*/action.yml",
    ".github/actions/*/action.yaml",
)

SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2}
FAIL_THRESHOLD = {"error": 2, "warning": 1, "never": 99}


@dataclass(frozen=True)
class Finding:
    path: str
    start_line: int
    end_line: int
    rule_id: str
    severity: str
    message: str


def is_target(path: str) -> bool:
    path = path.replace("\\", "/")
    return any(fnmatch.fnmatch(path, g) for g in TARGET_GLOBS)


# ---------------------------------------------------------------- diff handling
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_diff_ranges(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    """Parse `git diff -U0` output into {path: [(first_line, last_line), ...]} (new side)."""
    ranges: dict[str, list[tuple[int, int]]] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            name = line[4:]
            current = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            if current is not None:
                ranges.setdefault(current, [])
        elif line.startswith("@@") and current is not None:
            m = _HUNK.match(line)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count == 0:  # pure deletion: nothing on the new side
                continue
            ranges[current].append((start, start + count - 1))
    return ranges


def overlaps(finding: Finding, ranges: list[tuple[int, int]]) -> bool:
    return any(finding.start_line <= hi and lo <= finding.end_line for lo, hi in ranges)


# ------------------------------------------------------ GitHub workflow commands
def escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value: str) -> str:
    return escape_data(value).replace(":", "%3A").replace(",", "%2C")


def annotation(f: Finding) -> str:
    level = {"ERROR": "error", "WARNING": "warning"}.get(f.severity, "notice")
    title = escape_property(f"Workflow Injection Guard: {f.rule_id}")
    return (
        f"::{level} file={escape_property(f.path)},line={f.start_line},"
        f"endLine={f.end_line},title={title}::{escape_data(f.message)}"
    )


def render_summary(findings: list[Finding], scanned: int, scope: str) -> str:
    if not findings:
        return (
            "## Workflow Injection Guard\n\n"
            f"No issues found ({scanned} workflow/action file(s) scanned, scope: `{scope}`).\n"
        )
    lines = [
        "## Workflow Injection Guard",
        "",
        f"**{len(findings)} issue(s)** in {scanned} scanned file(s) (scope: `{scope}`).",
        "",
        "| Severity | Rule | Location |",
        "|---|---|---|",
    ]
    for f in sorted(findings, key=lambda x: (-SEVERITY_RANK.get(x.severity, 0), x.path, x.start_line)):
        lines.append(f"| {f.severity} | `{f.rule_id}` | `{f.path}:{f.start_line}` |")
    lines += ["", "<details><summary>How to fix</summary>", ""]
    for rid in sorted({f.rule_id for f in findings}):
        msg = next(f.message for f in findings if f.rule_id == rid)
        lines.append(f"- **`{rid}`** - {msg}")
    lines += ["", "</details>", ""]
    return "\n".join(lines)


# -------------------------------------------------------------------- semgrep
def short_rule_id(check_id: str) -> str:
    # Semgrep prefixes ids with the config path, e.g. "rules.gha-script-injection-run".
    return check_id.rsplit(".", 1)[-1]


def parse_semgrep_json(doc: dict) -> list[Finding]:
    out = []
    for r in doc.get("results", []):
        out.append(
            Finding(
                path=r["path"].replace("\\", "/").removeprefix("./"),
                start_line=r["start"]["line"],
                end_line=r["end"]["line"],
                rule_id=short_rule_id(r["check_id"]),
                severity=r["extra"]["severity"].upper(),
                message=" ".join(r["extra"]["message"].split()),
            )
        )
    return out


def git(*args: str, cwd: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def diff_against_base(base: str, head: str, root: str) -> str:
    """`git diff -U0` of the PR's changes, tolerant of shallow checkouts."""
    probe = subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=root, capture_output=True)
    if probe.returncode != 0:  # actions/checkout defaults to depth 1: fetch just the base commit
        git("fetch", "--no-tags", "--depth=1", "origin", base, cwd=root)
    try:
        # Three-dot = changes on the PR branch since it diverged from base.
        return git("diff", "-U0", "--no-color", f"{base}...{head}", cwd=root)
    except subprocess.CalledProcessError:
        # No merge base available (shallow). When head is GitHub's synthetic merge commit,
        # a plain base..head diff is exactly the PR's changes.
        return git("diff", "-U0", "--no-color", base, head, cwd=root)


def list_all_targets(root: str) -> list[str]:
    files = git("ls-files", cwd=root).splitlines()
    return [f for f in files if is_target(f)]


def main() -> int:
    env = os.environ
    rules = env.get("GUARD_RULES_DIR")
    if not rules:
        print("GUARD_RULES_DIR is required", file=sys.stderr)
        return 2
    root = env.get("GITHUB_WORKSPACE") or os.getcwd()
    scope = env.get("GUARD_SCOPE", "changed-lines")
    fail_on = env.get("GUARD_FAIL_ON", "error").lower()
    base, head = env.get("GUARD_BASE_SHA", ""), env.get("GUARD_HEAD_SHA", "HEAD")
    if scope not in {"changed-lines", "changed-files", "all"} or fail_on not in FAIL_THRESHOLD:
        print(f"invalid scope={scope!r} or fail-on={fail_on!r}", file=sys.stderr)
        return 2

    ranges: dict[str, list[tuple[int, int]]] = {}
    if scope == "all" or not base:
        if scope != "all":
            print("::notice::No base SHA available (not a pull_request run?); scanning all files.")
            scope = "all"
        targets = list_all_targets(root)
    else:
        try:
            ranges = parse_diff_ranges(diff_against_base(base, head, root))
        except subprocess.CalledProcessError as e:
            print(f"git diff failed (try `fetch-depth: 0` on actions/checkout): {e.stderr}", file=sys.stderr)
            return 2
        targets = [p for p in ranges if is_target(p) and (Path(root) / p).is_file()]

    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if not targets:
        text = render_summary([], 0, scope)
        print(text)
        if summary_path:
            Path(summary_path).open("a", encoding="utf-8").write(text)
        return 0

    cmd = [
        env.get("GUARD_SEMGREP", "semgrep"), "scan",
        "--config", rules, "--json", "--quiet", "--metrics=off", "--disable-version-check",
        "--no-git-ignore",
    ]
    if env.get("GUARD_SARIF_OUT"):
        cmd += ["--sarif-output", env["GUARD_SARIF_OUT"]]
    proc = subprocess.run([*cmd, "--", *targets], cwd=root, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        print(f"semgrep failed ({proc.returncode}):\n{proc.stderr}", file=sys.stderr)
        return 2
    doc = json.loads(proc.stdout)
    if doc.get("errors"):
        for e in doc["errors"]:
            print(f"::warning::semgrep: {escape_data(str(e.get('message', e))[:300])}")

    findings = parse_semgrep_json(doc)
    if scope == "changed-lines":
        findings = [f for f in findings if overlaps(f, ranges.get(f.path, []))]

    for f in findings:
        print(annotation(f))
    text = render_summary(findings, len(targets), scope)
    print(text)
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as fh:
            fh.write(text)

    threshold = FAIL_THRESHOLD[fail_on]
    return 1 if any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
