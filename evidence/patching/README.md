# Patching evidence (Part IV)

Records of the repair conversations (Section 11) and the review of the proposed changes (Section 12).
Repair assistance, not discovery. Model: Claude Opus 5.5, medium effort (see `../discovery/model.md`).

## Layout

| Path | Content |
|---|---|
| `F03/prompt.md` | Exact repair prompt sent for F03 (authorization on `GET /grades/<student_id>`) |
| `F03/llm-response.md` | The model's complete first answer (explanation, assumptions, limitations) |
| `F03/llm-patch.diff` | The unified diff proposed by the model (original attachment `f03_grades_authz.patch`) |
| `F03/llm-additional-tests.py` | Extra regression tests proposed by the model (original attachment `test_grades_read_authorization_extra.py`) |
| `F03/manual-decorators-draft.txt` | Our own earlier hand-written decorator attempt, kept only as a reference for the review; it was not sent to the model |
| `F06/prompt.md` | Repair prompt for F06 (path traversal in `GET /files`) |
| `F06/first-attempt-andre/` | First F06 attempt by a team member (prompt, CI output, model diff, partial review notes), kept for the record |

## Rules for this folder

- Files named `llm-*` are the original model output and must not be edited.
- Our review notes and any manual changes go in separate files (for example `F03/review.md`), so the original suggestion stays separate from the final implementation.
