#!/usr/bin/env python3
"""Build a corpus of workflow files from the most-starred public GitHub repos.

Static analysis only: we never execute anything from these repos. Each repo is
sparse-cloned (depth 1, only .github/ and root action.yml) into its OWN directory and the
exact commit is recorded in manifest.json so results are reproducible.

    python3 -I fetch_corpus.py --out ~/corpus --n 300
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

API = "https://api.github.com/search/repositories?q=stars:%3E5000+archived:false+fork:false&sort=stars&order=desc&per_page=100&page={page}"


def top_repos(n: int) -> list[dict]:
    repos: list[dict] = []
    for page in range(1, (n + 99) // 100 + 1):
        req = urllib.request.Request(API.format(page=page), headers={
            "Accept": "application/vnd.github+json", "User-Agent": "workflow-injection-guard-research"})
        with urllib.request.urlopen(req, timeout=30) as r:
            repos += json.load(r)["items"]
        time.sleep(7)  # unauthenticated search: 10 req/min
    return [{"full_name": r["full_name"], "stars": r["stargazers_count"],
             "language": r["language"], "default_branch": r["default_branch"]} for r in repos[:n]]


def clone(repo: dict, out: Path) -> dict:
    dest = out / repo["full_name"].replace("/", "__")
    if dest.exists():
        rev = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True)
        return {**repo, "sha": rev.stdout.strip(), "ok": rev.returncode == 0}
    url = f"https://github.com/{repo['full_name']}.git"
    safe = ["-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null"]
    steps = [
        ["git", *safe, "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--sparse", url, str(dest)],
        ["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone", "/.github/", "/action.yml", "/action.yaml"],
    ]
    for cmd in steps:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            return {**repo, "ok": False, "error": p.stderr.strip()[:200]}
    sha = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    return {**repo, "sha": sha, "ok": True}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--n", type=int, default=300)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    repos = top_repos(a.n)
    print(f"selected {len(repos)} repos (min stars: {repos[-1]['stars']})", flush=True)
    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(lambda r: clone(r, a.out), repos))
    (a.out / "manifest.json").write_text(json.dumps(
        {"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "repos": results}, indent=1))
    bad = [r for r in results if not r["ok"]]
    print(f"cloned {len(results) - len(bad)}, failed {len(bad)}")
    for r in bad[:10]:
        print("  FAILED", r["full_name"], r.get("error"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
