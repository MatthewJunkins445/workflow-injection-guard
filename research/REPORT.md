# Measuring GitHub Actions workflow injection in the 300 most-starred repos

*Snapshot: 2026-11-08. Rules: `workflow-injection-guard` (this repo), Semgrep 1.184.0.*

## Summary

| | |
|---|---|
| Repos analysed | 300 most-starred non-archived, non-fork public repos (all with >= 68.8k stars) |
| Repos with at least one workflow | 250 |
| Workflow + composite-action files scanned | 4,158 (3,773 are `.github/workflows/*`) |
| Raw findings | 10 in v1 of the rules; **8 after fixing a false-positive class found during triage** |
| Judged plausibly exploitable | **1** (needs a maintainer action to trigger; not dynamically tested) |
| Mitigated by design | 2 (one repo, two checkouts) |
| Syntactically real, not exploitable (guarded or no secrets) | 5 |
| False positives (rule bug, fixed) | 2 |

**The headline result is that these bugs are rare in this population.** I expected more. Of 238
workflows using `pull_request_target` (in 100 repos), only 3 checkouts of PR code were flagged, and
only one of those combined the checkout with secrets and no mitigation. Highly-starred projects
are well-resourced, widely copied, and increasingly already scanned by tools such as zizmor and
CodeQL, so this sample says little about the long tail of smaller repositories.

## Method

1. **Corpus** (`research/fetch_corpus.py`): top 300 repos by stars via the GitHub search API;
   shallow, sparse clone of `.github/` and root `action.yml` only, one directory per repo, commit
   SHA recorded. Nothing from these repos was executed - static analysis only.
2. **Detection** (`research/scan_corpus.py`): the three Semgrep rules.
3. **Tiering**, by who can cause the workflow to run and with what privileges:
   - **A** - triggerable by an outside party with repo privileges (`pull_request_target`,
     `issue_comment`, `issues`, `workflow_run`, ...). Candidate vulnerabilities.
   - **B** - only `pull_request`. Fork PRs get a read-only token and no secrets, and the attacker
     can already edit the workflow in their own PR, so injection adds almost nothing.
   - **C** - only triggers an outsider cannot cause.
4. **Manual triage** of every finding: read the whole workflow, looked for guards (`if:` on
   author/fork), permissions, and secrets in scope.
5. **Recall check** (`research/crosscheck.py`): re-derived the injection findings with a YAML
   parser walking every `steps[].run` / github-script `script`, independently of Semgrep's
   matcher. Same 5 files flagged both ways, 0 missed. (It shares the rule's context regex, so it
   validates Semgrep's structural matching, not the completeness of the context list.)

## Findings (repos anonymised - see `DISCLOSURE.md`)

| ID | Rule | Trigger | Verdict | Reasoning |
|---|---|---|---|---|
| 1 | pwn-request | `pull_request_target` | **Plausible, medium** | Checks out PR head SHA, then runs the project's build tooling with deployment secrets in the workflow env. Gated: fires only on `review_requested`, so a maintainer must act first. Static assessment only. |
| 2, 3 | pwn-request | `pull_request_target` | Mitigated by design | Job has `contents: read`, no secrets, first checkout is README-only; the comments in the file show the authors understood the risk. |
| 4 | script-injection | `pull_request` | Not exploitable | `if:` restricts to same-repo branches; branch names are set by people who can already edit the workflow. |
| 5 | script-injection | `pull_request` | Not exploitable | `if:` restricts to `OWNER/MEMBER/COLLABORATOR` authors. Defence-in-depth gap only. |
| 6 | script-injection | `pull_request: closed` | Not exploitable | Only runs when the PR author is the repository owner. |
| 7, 8 | script-injection | `pull_request` | Not exploitable | Fork PRs get no secrets; same-repo branch names are writer-controlled. |
| - | script-injection (v1) | `pull_request_target` + others | **False positive** | `${{ !contains(toJson(github.event.pull_request.body), '#x') }}` evaluates to a boolean. |
| - | script-injection (v1) | n/a | **False positive** | `${{ !startsWith(github.event.head_commit.message, 'x') && 'build' || '' }}` yields a constant. |

## What I learned about the detection problem

- **Syntax gets you recall, not precision.** Within its defined scope the rule missed nothing
  (cross-check), but 7 of 10 v1 findings were not exploitable and 2 were outright wrong. A PR bot
  with that ratio gets muted.
- **Two false-positive classes, one fixed.** Boolean-valued expressions (`contains`,
  `startsWith`, `endsWith`, `==`) are now excluded - the rule fix has regression tests. Also
  discovered: GitHub expression and context names are case-insensitive, so the rule now matches
  `GitHub.Head_Ref`.
- **Guards are not modelled.** Findings 4-6 are all defused by an `if:` on author or fork status.
  The corpus scanner computes `has_author_or_fork_guard` / `uses_secrets` hints, but the rule
  does not use them: encoding "job-level `if` restricts the author" in Semgrep patterns is the
  next improvement, and the right place for taint/dataflow tooling (CodeQL).
- **`pwn-request` is MEDIUM confidence for a reason.** It flags the checkout, not the execution.
  Finding 2/3 shows an expert maintainer doing this deliberately and safely.

## Limitations

- Top-300-by-stars is a biased, hardened sample. A 1k-10k star sample would likely give a higher
  hit rate; I did not run one.
- Default branch at one instant. Only `.github/` and root `action.yml` were fetched, so
  reusable workflows referenced from elsewhere were not followed.
- Two files failed to parse in Semgrep (2 of 4,158).
- One plausible vulnerability, assessed statically. I did not (and should not) test it against
  the live repository.
- Only one bug class, and only explicit `${{ }}` interpolation; `$GITHUB_ENV` and step-output
  taint, and bracket-notation contexts, are out of scope.

## Reproduce

```bash
python3 research/fetch_corpus.py --out ~/corpus --n 300
semgrep-python research/scan_corpus.py --corpus ~/corpus --rules rules --out research/results.json
semgrep-python research/crosscheck.py  --corpus ~/corpus --results research/results.json
```
