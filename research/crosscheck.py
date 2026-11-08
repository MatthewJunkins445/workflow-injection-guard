#!/usr/bin/env python3
"""Recall check: independently find `run:`/`script:` steps containing untrusted contexts by
parsing YAML (not via Semgrep) and diff against results.json.

    ~/.local/share/uv/tools/semgrep/bin/python -I crosscheck.py --corpus ~/corpus --results results.json
"""
import argparse
import json
import re
from pathlib import Path

from ruamel.yaml import YAML

def _rule_regex() -> re.Pattern:
    """Reuse the rule's own untrusted-context regex, so this check isolates what it is meant
    to test: Semgrep's YAML structure matching vs. an independent parse of the same files."""
    rules = YAML(typ="safe").load((Path(__file__).parent.parent / "rules" / "gha-script-injection.yaml").read_text())
    rx = rules["rules"][0]["patterns"][-1]["metavariable-regex"]["regex"].strip()
    assert rx.startswith("(?is).*?")
    return re.compile(rx[len("(?is).*?"):], re.I | re.S)


CTX = _rule_regex()
# Looser variant to catch bracket notation / odd spellings the rule intentionally does not cover.
LOOSE = re.compile(r"\$\{\{(?:(?!\}\}).)*?(?:github\[|\bgithub\.event\.[a-z_.\[\]*0-9]*?(?:title|body|message|head_ref|\bref\b|label|name|email)\b)", re.S)


def steps_of(doc):
    if not hasattr(doc, "get"):
        return
    for job in (doc.get("jobs") or {}).values():
        if hasattr(job, "get"):
            yield from (job.get("steps") or [])
    runs = doc.get("runs")
    if hasattr(runs, "get"):
        yield from (runs.get("steps") or [])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--results", required=True, type=Path)
    a = ap.parse_args()
    got = {(f["repo"].replace("/", "__"), f["file"]) for f in json.loads(a.results.read_text())["findings"]
           if f["rule"].startswith("gha-script-injection")}
    yaml = YAML(typ="safe")
    strict, loose_only = set(), []
    for d in a.corpus.iterdir():
        if not d.is_dir():
            continue
        for p in list(d.glob(".github/workflows/*.y*ml")) + list(d.glob(".github/actions/*/action.y*ml")) + list(d.glob("action.y*ml")):
            try:
                doc = yaml.load(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            for s in steps_of(doc):
                if not hasattr(s, "get"):
                    continue
                texts = []
                if isinstance(s.get("run"), str):
                    texts.append(("run", s["run"]))
                if str(s.get("uses", "")).startswith("actions/github-script") and isinstance(s.get("with"), dict):
                    if isinstance(s["with"].get("script"), str):
                        texts.append(("script", s["with"]["script"]))
                for kind, t in texts:
                    key = (d.name, str(p.relative_to(d)))
                    if CTX.search(t):
                        strict.add(key)
                    elif LOOSE.search(t):
                        loose_only.append((key, kind, " ".join(t.split())[:140]))
    print(f"independent parser flagged {len(strict)} files; semgrep rules flagged {len(got)}")
    print("missed by semgrep (false negatives):", sorted(strict - got))
    print("flagged by semgrep only:", sorted(got - strict))
    print(f"\nloose-only candidates (outside rule scope, not necessarily vulns): {len(loose_only)}")
    for k, kind, t in loose_only[:25]:
        print(" ", k[0], k[1], kind, "|", t)


if __name__ == "__main__":
    main()
