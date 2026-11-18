# F06 review (Section 12) and manual changes

Reviewed: `llm-response.md`, `llm-patch.diff` (original, not edited).

## Applying the model's diff

The diff was written against the original baseline. The F03 repair was already in the repository, so it did not apply:

- `git apply --check` fails; with `patch -p1`, hunk 1 (imports) and hunk 3 (`/files` and `handle_error`) fail, hunk 2 (helpers) applies.
- Cause: the F03 patch already added `import werkzeug.exceptions` and replaced `handle_error`, and the F06 diff changes the same lines.

## Changes to the model's patch (file: `manual-merge.diff`, applies on top of the F03 commit)

The merge and the `login_required` correction were done with the help of a coding assistant (Claude Code) and checked by running the tests.

1. **Merge:** added `import functools`, the `login_required` and `resolve_material` helpers and the `/files` change. The model's second version of `handle_error` was not applied, because the F03 handler already does the same (HTTP errors keep their status, other errors return a generic 500 and are logged).
2. **Correction to `login_required`:** the model checked only `"user" in flask.session`. The F03 code resolves the user on the server (`current_user()`). With the model's version, a session for a user that does not exist passed the check: `/grades/1001` returned 401 but `/files?path=srs-summary.txt` returned 200. `login_required` now calls `current_user()`, so both endpoints behave the same (401 in both cases).

## Section 12 questions

- **Root cause or only the example?** Root cause. The path is resolved first (`resolve(strict=True)` collapses `..`, honours absolute paths and follows symlinks) and only then checked with `is_relative_to`, which compares path components and not a text prefix. This covers all five attacks of the finding, the sibling directory `materials_evil`, symbolic-link directories and symlink loops.
- **Does an authentication check leave object authorization missing?** Authentication and containment are both implemented. R6 allows every authenticated user to read every file in the materials directory, so no per-file or per-course rule is required.
- **Are all relevant paths protected?** `/files` is the only endpoint that turns user input into a file path. The profile and grade reads are covered by F03. `POST /grades/update` is still unprotected (F04, not selected).
- **Can authorized users still act?** Yes: `public.txt`, `sub/nested.txt`, `sub/../public.txt` and a symbolic link to another file inside the directory still work (tests).
- **Denial responses and state changes?** 401 for anonymous requests; 404 with the same body for a missing file and for a path outside the directory, without internal paths. R7 mentions 403 for authenticated but unauthorized requests; the tests accept 400, 403 or 404, and the identical 404 was kept as a deliberate choice to avoid an existence oracle. Reads change no stored data.
- **Unrelated change, broad handler or insecure fallback?** The model also rewrote the global error handler, which duplicated the F03 change (not applied twice). No insecure fallback.

## Limitations stated by the model

Time-of-check to time-of-use race if an attacker can write inside `materials/`; every logged-in user reads every material; symlinks that stay inside the directory are allowed; only tested on Linux and Python 3.13 (CI uses 3.10, and `is_relative_to` needs 3.9).

## Verification of the merged result (local, before pushing)

- Repo tests plus `tests_security`: 39 passed.
- With the model's 15 extra tests: 54 passed.
