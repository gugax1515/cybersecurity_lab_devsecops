# After the repair (CI evidence)

- Run: https://github.com/gugax1515/cybersecurity_lab_devsecops/actions/runs/44229777540
- Application: baseline plus the F03 and F06 repairs (see `../../patching/`)
- Result: all four jobs completed successfully: functional tests (`test`), static analysis (`sast`), `security-regression` and the Docker build and smoke test (`build`).
- Compare with the run before the repair: `../before-patch-ci.md` (28 of 33 security tests failed, `build` skipped).

## Contents

| Path | Content |
|---|---|
| `static-analysis-reports/` and `.zip` | Bandit and Semgrep reports of this run (artifact `static-analysis-reports`) |
| `docker-build-records/` | The two Docker build records of the `build` job (`.dockerbuild` archives and their extracted contents) |

## Static analysis: before vs after the repair

Baseline reports: `../../content/part1/static-analysis-reports/`.

| Tool | Before | After |
|---|---|---|
| Bandit 1.9.4 | B105 (line 8), B106 x4 (lines 37, 38, 40, 42), B201 High and B104 Medium (line 159) | The same 7 findings with the same severities: B105 (line 11), B106 x4 (lines 40, 41, 43, 45), B201 and B104 (line 270) |
| Semgrep | `debug-enabled` and `avoid_app_run_with_bad_host` (line 159) | The same 2 rules (line 270) |

- The findings are identical; only the line numbers moved, because code was added (120 lines of code scanned before, 199 after).
- Tool versions: Bandit 1.9.4 and Python 3.10.22 are unchanged. Semgrep went from 1.183.0 to 1.186.0 between the two runs (also `click-option-group`, `markdown-it-py` and a new `structlog` in the environment), with no effect on the result.
- As expected, the authorization and validation repairs did not change the scanner output: these rules only report configuration issues (debug mode, bind address, hard-coded key and passwords), which were not part of the selected repairs.
