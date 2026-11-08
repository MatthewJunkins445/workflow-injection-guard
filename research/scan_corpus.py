#!/usr/bin/env python3
"""Scan the corpus built by fetch_corpus.py and attach triage context to each finding.

Run with semgrep's own interpreter so ruamel.yaml is available:
    ~/.local/share/uv/tools/semgrep/bin/python -I scan_corpus.py --corpus ~/corpus --rules ../rules --out results.json

Triage tiers (who can reach the vulnerable step, and with what privileges):
  A  workflow can be triggered by an OUTSIDE party and runs with repo privileges
     (pull_request_target, issue_comment, issues, discussion*, pull_request_review*,
      workflow_run, ...)  -> candidate real vulnerability; needs manual verification
  B  only `pull_request`: fork PRs get a read-only token and no secrets, and the attacker
     can already edit the workflow itself -> low impact (only same-repo branch names matter)
  C  only triggers an outsider cannot cause (push, schedule, workflow_dispatch, ...)
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from ruamel.yaml import YAML

OUTSIDER_PRIVILEGED = {
    "pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment",
    "pull_request_review", "pull_request_review_comment", "workflow_run", "fork", "watch",
    "pull_request_comment", "label", "status",
}


def triggers_of(doc) -> set[str]:
    if not hasattr(doc, "get"):
        return set()
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if hasattr(on, "keys"):
        return {str(k) for k in on.keys()}
    return set()


def tier(rule_id: str, trig: set[str]) -> str:
    if trig & OUTSIDER_PRIVILEGED:
        return "A"
    if "pull_request" in trig:
        # `pwn-request` rule only fires on pull_request_target/workflow_run, so B == injection only
        return "B"
    return "C"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--rules", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()

    manifest = {r["full_name"].replace("/", "__"): r for r in json.loads((a.corpus / "manifest.json").read_text())["repos"] if r["ok"]}
    files = sorted(
        str(p) for d in a.corpus.iterdir() if d.is_dir()
        for pat in (".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.y*ml", "action.y*ml")
        for p in d.glob(pat)
    )
    print(f"{len(manifest)} repos, {len(files)} workflow/action files", flush=True)

    findings = []
    yaml = YAML(typ="safe")
    scanned_total = 0
    for i in range(0, len(files), 400):  # chunk to keep argv small
        chunk = files[i:i + 400]
        p = subprocess.run(
            ["semgrep", "scan", "--config", str(a.rules), "--json", "--quiet", "--metrics=off",
             "--disable-version-check", "--no-git-ignore", "--", *chunk],
            capture_output=True, text=True)
        if p.returncode not in (0, 1):
            print("semgrep error", p.stderr[:500], file=sys.stderr)
            return 2
        doc = json.loads(p.stdout)
        scanned_total += len(doc.get("paths", {}).get("scanned", []))
        for e in doc.get("errors", []):
            print("  parse/scan error:", e.get("path"), str(e.get("message"))[:100])
        for r in doc["results"]:
            path = Path(r["path"])
            rel = path.relative_to(a.corpus)
            repo_dir = rel.parts[0]
            repo = manifest[repo_dir]
            try:
                trig = triggers_of(yaml.load(path.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                trig = set()
            rule_id = r["check_id"].rsplit(".", 1)[-1]
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            lo, hi = r["start"]["line"], r["end"]["line"]
            text = "\n".join(lines)
            findings.append({
                # Hints for the human doing triage; NOT used to suppress findings.
                "uses_secrets": bool(re.search(r"secrets\.(?!GITHUB_TOKEN)", text)),
                "has_author_or_fork_guard": bool(re.search(
                    r"author_association|head\.repo\.full_name\s*==\s*github\.repository|repository_owner|github\.actor\s*==", text)),
                "repo": repo["full_name"], "stars": repo["stars"], "sha": repo["sha"],
                "file": str(Path(*rel.parts[1:])), "line": lo, "end_line": hi,
                "rule": rule_id, "triggers": sorted(trig), "tier": tier(rule_id, trig),
                "snippet": "\n".join(lines[lo - 1:min(hi, lo + 14)]),
            })
    findings.sort(key=lambda f: (f["tier"], -f["stars"], f["file"], f["line"]))
    a.out.write_text(json.dumps({"repos": len(manifest), "files": len(files),
                                 "files_scanned": scanned_total, "findings": findings}, indent=1))
    from collections import Counter
    print("files semgrep actually scanned:", scanned_total)
    print("by tier:", dict(Counter(f["tier"] for f in findings)))
    print("by rule:", dict(Counter(f["rule"] for f in findings)))
    print("repos with >=1 finding:", len({f["repo"] for f in findings}),
          "| with tier A:", len({f["repo"] for f in findings if f["tier"] == "A"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
