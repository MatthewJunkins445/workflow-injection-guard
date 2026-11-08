# Workflow Injection Guard

A GitHub Action that reviews **only what a pull request changes** in `.github/workflows/*` and
`action.yml` files, and flags one bug class: **untrusted input reaching code execution in
GitHub Actions**. Rules are custom [Semgrep](https://semgrep.dev) rules.

| Rule | What it catches |
|---|---|
| `gha-script-injection-run` | `${{ github.event.pull_request.title }}` (and ~20 other attacker-controlled contexts) interpolated into a `run:` script |
| `gha-script-injection-github-script` | The same, interpolated into the JS source of `actions/github-script` |
| `gha-pwn-request-checkout` | `pull_request_target` / `workflow_run` workflows that check out the PR's own code ("pwn requests") |

## Usage

```yaml
# .github/workflows/workflow-guard.yml
name: Workflow guard
on:
  pull_request:
    paths: [".github/workflows/**", "**/action.yml", "**/action.yaml"]
permissions:
  contents: read
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: <you>/workflow-injection-guard@<sha>
```

Inputs: `scope` (`changed-lines` default / `changed-files` / `all`), `fail-on`
(`error` default / `warning` / `never`), `sarif-file`, `semgrep-version`.

Findings show up as inline annotations on the PR diff and in the job summary. It uses the plain
`pull_request` trigger, so it works on fork PRs (read-only token, no secrets) - it needs no
write permissions and no secrets.

**`changed-lines` is the default on purpose**: a team adopting this on an existing repo should
not have a PR blocked by a ten-year-old workflow it did not touch.

## Design notes

- **Diff-aware.** `git diff -U0` gives the changed line ranges; a finding is reported only if its
  matched range (a whole multi-line `run: |` block counts) overlaps a changed line.
- **The action cannot be injected through its own inputs.** Every input is passed via `env:`,
  never expanded inside a script body, and third-party actions are pinned by commit SHA.
- **Rules are tested**: Semgrep `ruleid:`/`ok:` annotations, fixture files for trigger-syntax
  variants (`on: x`, `on: [x]`, `on: {x: ...}`, `"on":`), and end-to-end tests that build a
  throwaway git repo to prove old issues do not block a PR but new ones do.

```bash
python -m unittest discover -s tests -v     # needs semgrep + git on PATH
```

## Known limitations (false negatives)

- Only explicit `${{ }}` expressions are tracked. Taint through `$GITHUB_ENV`, step outputs
  (`${{ steps.x.outputs.y }}`) or artifacts is not followed.
- Bracket-notation contexts (`github['event']['pull_request']['title']`) are not matched.
- `gha-pwn-request-checkout` flags the *checkout*; it does not prove later steps execute the
  checked-out code (hence confidence MEDIUM).
- Reusable workflows called with untrusted `with:` inputs are not analysed across files.

## Research

`research/REPORT.md` measures these bugs across the 300 most-starred public repos (4,158 files):
8 findings, 1 plausibly exploitable, and a write-up of what the detection problem taught me
(including two false-positive classes found by triage and fixed). Disclosure policy:
`research/DISCLOSURE.md`.

## Related tools

[zizmor](https://github.com/woodruffw/zizmor) and CodeQL's built-in Actions queries cover this
space far more broadly. This project's purpose is a small, readable, well-tested, diff-aware
implementation of one bug class, plus the measurement study in `research/`.
