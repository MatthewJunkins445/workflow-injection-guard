# Disclosure policy for this research

- Findings in `REPORT.md` are anonymised. Repositories are named only after the maintainers have
  been told privately and have had a reasonable time (default 90 days) to fix, or after they say
  the behaviour is intended.
- Report privately through the project's `SECURITY.md` / GitHub private vulnerability reporting.
  Never through a public issue or PR.
- Only one finding (ID 1) is plausibly a vulnerability; its draft lives in `research/private/`
  (git-ignored). Nothing has been sent. The other findings are not exploitable as deployed, so
  naming those projects as "vulnerable" would be inaccurate.
- Do not test a suspected issue against a live repository you do not own. A static read of the
  workflow is enough for a report.
- `results.json` names every flagged repo, so it is git-ignored.
