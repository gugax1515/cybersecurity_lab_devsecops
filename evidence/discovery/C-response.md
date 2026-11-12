# Static security review: baseline_secure_coding_api.py

Line numbers are approximate, counted from the source as pasted. "Fact" means directly visible in the code. "Requirement-derived" means it follows from R1-R7. "Assumption" is stated where the policy is unspecified. Severity ratings are my provisional judgment.

## Findings table

| ID | Title | Location | Reqs | Severity | Confidence |
|---|---|---|---|---|---|
| F01 | No authentication on protected endpoints | `get_profile`, `get_grades`, `update_grade`, `download_file` (~115-148) | R1, R7 | Critical | High |
| F02 | Profile access lacks object/role authorization | `get_profile` (~117-120) | R2, R3, R4 | High | High |
| F03 | Grade read returns all records for any identifier | `get_grades` (~124-126) | R2, R3, R4 | High | High |
| F04 | Grade update lacks authorization | `update_grade` (~128-142) | R3, R4, R7 | Critical | High |
| F05 | Grade update lacks input validation | `update_grade` (~130-140) | R5, R7 | High | High |
| F06 | Path traversal / arbitrary file read | `download_file` (~146-148) | R6, R1 | Critical | High |
| F07 | Catch-all handler leaks exception details and turns client errors into 500 | `handle_error` (~150-155) | R7 | Medium | High |
| F08 | Debug mode enabled on all interfaces | `app.run(...)` (~159) | R7 (and general) | High | Medium |
| F09 | Hardcoded, guessable `SECRET_KEY` | ~8 | R1-R4 (conditional) | High | High |
| F10 | Unsafe parsing of `student_id` path parameter | `get_profile` ~117, `get_grades` ~124 | R5, R7 | Medium | High |
| F11 | Plaintext hardcoded credentials, non-constant-time compare | ~36-43, ~88 | R1 (inferred) | Medium | Medium |
| F12 | Session and cookie hardening gaps (CSRF, flags, logout, stale role) | `login`, `logout`, config | R1 (inferred) | Low | Low-Medium |
| F13 | Non-atomic check-then-append on shared grade store | `update_grade`, `find_grade` (~136-140) | R4, R5 (integrity) | Low | Medium |

## Cross-cutting assumptions

- `@app.get`/`@app.post` imply Flask 2.0 or later. `get_json()` behavior on a wrong content type or invalid body differs by version (older returns `None`, newer raises 415/400).
- Authentication is the signed Flask session cookie only. `session["role"]`, `["student_id"]` and `["courses"]` are what an authorization layer would consume.
- Check order assumed: authentication (401), authorization (403), validation (400), existence (404). Where authorization would depend on existence, I assume non-permitted callers get 403 rather than 404, to avoid an existence oracle. The exercise doesn't state this.
- A professor requesting grades for a student with no records in their courses is treated as "no permitted records", so 403 under R4.
- Numeric grades are assumed to include non-integer numbers, since R5 says only "numeric". If integers only are intended, the validation rule changes.

## Supporting explanations

**F01: No authentication on protected endpoints**
- Location: `get_profile`, `get_grades`, `update_grade`, `download_file`.
- Fact: none of these handlers reads `flask.session` or checks that a user is logged in. Only `/me` does.
- Input and flow: any unauthenticated HTTP request reaches the handler and executes fully. There is no before-request hook or decorator.
- Root cause: no authentication control is applied, so login has no enforcement effect.
- Preconditions and impact: network access to port 5001. The server binds to 0.0.0.0, so the whole reachable network is exposed. Impact is anonymous read of profiles, grades and files, and anonymous grade modification.
- Test: send each protected request with no cookie. Expect 401 with no data and no state change; the current code should return 200.
- Confidence: high (code fact plus R1).

**F02: Profile access lacks authorization**
- Location: `get_profile`, `STUDENT_PROFILES.get(int(student_id))`.
- Fact: the profile is returned for any integer identifier that exists. Role and ownership are never consulted.
- Requirement-derived: students may read only their own profile. Professors may not read profiles. Admins may.
- Flow: the attacker controls `student_id` in the URL path, and the lookup returns the matching record directly.
- Root cause: a missing object-level and role-level check.
- Impact: disclosure of names, emails and programs to anyone. Once F01 is fixed, any logged-in student or professor would still read all profiles.
- Test: as alice, request `/students/1002/profile` (expect 403). As prof_srs, request `/students/1001/profile` (expect 403). As alice, request her own profile (expect 200). As admin1, request any profile (expect 200).
- Confidence: high. Assumption: the 403-versus-404 ordering above.

**F03: Grade read returns all records for any identifier**
- Location: `get_grades`.
- Fact: it filters by the supplied `student_id` only, never by requester.
- Requirement-derived: students see only their own grades. Professors see only rows for their courses. Admins see all. A request with no permitted rows returns 403, not an empty or partial disclosure.
- Flow: `student_id` in the path goes through `int()` and then to the list comprehension over `GRADES`.
- Root cause: missing object-level authorization and missing per-record filtering by course for professors.
- Impact: for example, any user could read bob's SRS grade, or alice's SSD grade as a professor of SRS only.
- Test: as alice request `/grades/1002` (403). As prof_srs request `/grades/1001` and confirm only the SRS row appears, not SSD. As prof_srs request a student with only SSD rows (403). As admin1 request all (200).
- Confidence: high. Assumption: the "no permitted rows gives 403" interpretation.

**F04: Grade update lacks authorization**
- Location: `update_grade`.
- Fact: there is no check of role, session, or course membership before mutation.
- Requirement-derived: professors may update only grades for assigned courses. Admins may update any. Students may not update. Denied requests must leave data unchanged.
- Flow: attacker-controlled JSON `student_id`, `course_id` and `grade` go to `find_grade`, which either overwrites `row["grade"]` or appends a new row.
- Root cause: no authorization control, and state is mutated unconditionally.
- Impact: anyone, including anonymous callers, can change or fabricate grades. This is the most serious integrity issue.
- Test: for each of anonymous (401), alice (403), prof_srs updating SSD (403), and prof_srs updating SRS (200), POST an update and compare `GRADES` through an admin read before and after.
- Confidence: high.

**F05: Grade update lacks input validation**
- Location: `update_grade`, ~130-140.
- Facts:
  - `get_json()` is used without checking its result. A missing or invalid body, or a non-object (list, string), raises `TypeError`, `KeyError` or an HTTP exception, which becomes a 500 via F07.
  - `student_id`, `course_id` and `grade` are used as supplied, with no type, range or existence checks.
  - An unmatched pair triggers `GRADES.append(...)`.
- Requirement-derived: the student ID must be a positive integer for an existing student. The course must be SRS or SSD. The grade must be numeric, 0 to 20, and not boolean.
- Flow: attacker-controlled JSON values are stored directly in the shared list. Examples:
  - `"grade": "abc"`, `true`, `99`, `-5`, `NaN` (Python's JSON parser accepts `NaN`/`Infinity` by default) are all stored.
  - `"course_id": "XYZ"` creates a record for an unknown course.
  - `"student_id": 9999`, or a string, boolean or list, creates an orphan record.
  - Because `True == 1` in Python, `true` can match or create records keyed as integer 1.
- Root cause: no schema validation, and update logic that creates records rather than only modifying existing ones.
- Impact: corrupted data that later feeds `get_grades`, and possible downstream serialization problems from `NaN`. This also bypasses the "existing student" and "known course" constraints.
- Test: after authorization is in place, send each malformed case as an authorized professor and as an admin. Expect 400 and an unchanged `GRADES`. Boundary values: 0 and 20 accepted; -1, 21, `true`, `false`, `"15"`, `null`, `NaN` rejected.
- Confidence: high. Assumption: how floats should be treated.

**F06: Path traversal and arbitrary file read in `/files`**
- Location: `download_file`.
- Fact: `target = MATERIALS_DIR / raw_path` is passed directly to `flask.send_file`. There is no containment check (`resolve()` plus parent comparison) and no use of `send_from_directory`/`safe_join`.
- Flow: the attacker controls the `path` query parameter.
  - `pathlib` discards the left operand when the right operand is absolute, so `?path=/etc/passwd` resolves to `/etc/passwd`.
  - `../` sequences (`?path=../baseline_secure_coding_api.py`) climb out of `materials/`.
  - A path that resolves inside the directory but is a symlink to elsewhere (if one is present) would also escape, since nothing is resolved.
- Root cause: path concatenation without canonicalization or a containment check.
- Preconditions and impact: no authentication is needed (F01). Impact is arbitrary file read as the server user, including the application source (and thus the key in F09) and environment or system files.
- Test: request `?path=/etc/hostname`, `?path=../baseline_secure_coding_api.py`, `?path=%2e%2e%2fbaseline_secure_coding_api.py`, `?path=srs-summary.txt` (should succeed when authenticated), `?path=` (directory; should be a clean client error), and a path containing a NUL byte. Also test a symlink placed inside `materials/` pointing outside, and a sibling directory with the same name prefix such as `materials_evil/`, as regression cases for any future containment check.
- Confidence: high for absolute-path and `..` cases (code fact). Medium for symlink and platform-specific cases (Windows drive or backslash behavior), which are inferred.

**F07: Catch-all error handler leaks details and misclassifies errors**
- Location: `handle_error`.
- Facts: every `Exception` returns `str(exc)` and the class name with status 500. In Flask, a handler registered on `Exception` also receives `HTTPException`s, so 404, 405 and similar are likely converted to 500. This is version-dependent (inferred, Flask 1.1 and later).
- Flow: any failure, such as `ValueError` from `int()`, `KeyError` from missing JSON keys, or `FileNotFoundError` from `send_file`, reaches this handler. `FileNotFoundError` messages normally include the absolute filesystem path.
- Root cause: raw exception text is returned and there is no mapping to 4xx.
- Impact: internal path disclosure, an oracle for file existence in F06, and violation of R7's requirement for client errors on invalid requests.
- Test: request `/students/abc/profile`, `/files?path=nope.txt`, POST `/grades/update` with an empty body, and an unknown route. Inspect status codes and bodies for paths, exception class names, or messages.
- Confidence: high for the body leak. Medium for the HTTP-exception behavior, since it depends on the Flask version.

**F08: Debug mode on 0.0.0.0**
- Location: `app.run(debug=True, host="0.0.0.0", port=5001)`.
- Fact: the Werkzeug debugger and reloader are enabled and the server listens on all interfaces.
- Inferred: because `handle_error` catches most exceptions, the traceback page is probably not the main exposure. The interactive `/console` endpoint is typically still served and PIN-protected, and an arbitrary file read (F06) may expose inputs used to derive that PIN. The chain is plausible but depends on Werkzeug version and host configuration.
- Impact if exploitable: remote code execution as the server user. Without that chain, it is still a hardening failure.
- Test: confirm whether `GET /console` serves the debugger page (do not attempt the PIN) and whether any traceback page appears for unhandled errors. Check whether the setting is controlled by environment configuration.
- Confidence: medium. Assumption: the exercise runs the file as shown with `python file.py`.

**F09: Hardcoded, guessable `SECRET_KEY`**
- Location: `app.config["SECRET_KEY"] = "dev-secret-key"`.
- Fact: the signing key is a constant in source and trivially guessable.
- Flow: an attacker who knows or guesses the key can forge a session cookie with arbitrary `user`, `role`, `student_id` and `courses`.
- Root cause: a static, weak, source-embedded secret.
- Preconditions and impact: this matters once endpoints actually trust the session. Today it is masked by F01, but fixing F01 alone would leave full impersonation, including admin and professor roles, available to anyone.
- Test: sign a cookie with this key containing role `admin` and use it against a protected endpoint. Confirm that a differently keyed cookie is rejected.
- Confidence: high that the key is weak. The exploit's reachability depends on enforcement being added.

**F10: Unsafe parsing of `student_id`**
- Location: `int(student_id)` in `get_profile` and `get_grades`.
- Facts: the route parameter is a plain string. `int()` raises `ValueError` on non-numeric input, giving a 500 via F07. It also accepts zero and negative values, surrounding whitespace, underscores (`"1_001"`), a leading plus sign, and non-ASCII decimal digits (for example full-width digits).
- Requirement-derived: identifiers must be positive integers (R5).
- Flow: attacker-controlled path text is normalized by `int()` before any comparison.
- Impact: R5 violations and 500s now. Later, if an authorization check compares against a differently canonicalized form of the identifier, the lax parsing could cause mismatches.
- Test: request `/grades/abc`, `/grades/-1`, `/grades/0`, `/grades/1001%20`, `/grades/1_001`, `/grades/١٠٠١`, `/grades/1e3`, and an extremely long digit string. Expect 400 for every one of them, with no distinct data returned.
- Confidence: high on the code behavior. The Unicode and underscore cases depend on Python semantics, which I am fairly sure of.

**F11: Plaintext hardcoded credentials and comparison**
- Location: `USERS` (~36-43) and `login` (~88).
- Facts: passwords are stored in cleartext in source and compared with `!=`. The same error text is returned for unknown users and wrong passwords, which is good. However, `user is None or ...` short-circuits, which may leave a small timing difference. There is no rate limiting or lockout.
- Inferred: the exercise context says this is a teaching dataset, so the credentials may be intentional. The requirements do not specify a password-storage policy.
- Impact: credential disclosure through source or file read (F06), brute force with no throttling, and a possible username timing oracle.
- Test: measure response time for known versus unknown usernames, and try repeated failed logins to see whether throttling exists.
- Confidence: medium. Severity may be lower if you treat this as demo data.

**F12: Session and cookie hardening gaps**
- Location: `login`, `logout`, application configuration.
- Facts: no `SESSION_COOKIE_SECURE` or `SAMESITE` settings. Flask's default `HttpOnly` applies. Sessions are client-side signed cookies. `logout` only clears the cookie in that client, and there is no server-side invalidation. Role and courses are copied into the session at login and never revalidated.
- Inferred: a stolen or old cookie stays valid until its signature expires or the key changes. The state-changing JSON endpoint is partly protected against classic form CSRF because `get_json()` normally requires a JSON content type (version-dependent). Login and logout are form-based and could be forged cross-site, though impact is low.
- Impact: low in isolation. It matters if these endpoints later sit behind real authorization.
- Test: inspect `Set-Cookie` attributes; replay a pre-logout cookie after logout; send a cross-origin form POST to `/logout` and `/login`; submit `/grades/update` with `text/plain` and form content types.
- Confidence: low to medium. These are hardening items, not requirement violations.

**F13: Non-atomic check-then-append on shared grade store**
- Location: `update_grade`, `find_grade`.
- Fact: lookup and append or update are separate operations on a shared module-level list, with no locking. Flask's development server is threaded by default.
- Inferred: two concurrent requests for the same new `(student, course)` pair could both see no row and both append, leaving duplicate rows. `find_grade` then updates only the first match, so reads may expose stale values.
- Impact: data inconsistency, not direct disclosure. Likely a low-impact finding in a teaching setup.
- Test: fire many simultaneous identical updates for a pair with no existing row, then count matching rows in `GRADES` through an admin read.
- Confidence: medium. The race window is small and may be hard to hit.

## Things reviewed that did not produce a finding

I looked for open redirects, SQL or template injection, and user enumeration through login errors. `login` redirects to a fixed path and uses no templates or SQL, and the login error message is uniform. This is not proof of safety. The review is limited to the shown source, and I did not consider deployment, reverse-proxy, or dependency issues.