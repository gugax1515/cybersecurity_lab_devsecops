# Static security review: `baseline_secure_coding_api.py`

Line numbers are counted from the pasted source and may be off by a line or two. Severity ratings are my own estimates, not CVSS scores.

## Assumptions

- **Policy:** The code states no access-control policy, so the policy below is inferred from the application description.
  - Students read only their own profile and grades.
  - Professors read and write grades only for their assigned courses.
  - Admins can do anything.
  - Teaching materials are readable by authenticated users, possibly scoped per course.
- **Deployment:** I assume Flask 2.x or later (`@app.get`, dict return values) and a POSIX host. The review concerns the code as written, not a hardened deployment behind a proxy.

## Findings table

| ID | Title | Location | Est. severity | Confidence |
|---|---|---|---|---|
| SC-01 | Path traversal / arbitrary file read in `/files` | `download_file`, L144-148 | Critical | High |
| SC-02 | No authentication on any data endpoint | L115-148 | Critical | High |
| SC-03 | Missing authorization on grade updates | `update_grade`, L128-142 | Critical | High |
| SC-04 | Object-level authorization missing on profile and grade reads (IDOR/BOLA) | `get_profile`, `get_grades`, L115-126 | High | High |
| SC-05 | Hardcoded, guessable session signing key | L8 | High (latent) | High (fact), Medium (impact) |
| SC-06 | Debug mode on all interfaces | L159 | High (if deployed as written) | Medium |
| SC-07 | Catch-all error handler leaks exception details | `handle_error`, L150-155 | Medium | High |
| SC-08 | Plaintext, hardcoded credentials and non-constant-time comparison | L36-43, L88 | Medium (Low if demo-only) | High |
| SC-09 | No brute-force or rate limiting on login | `login`, L82-96 | Medium | High |
| SC-10 | Weak session lifecycle: CSRF, cookie flags, logout, stale claims | L91-100, L8 | Medium | Medium |
| SC-11 | Missing input validation and integrity checks on grade writes | L130-140 | Medium | High |

## Supporting explanations

**SC-01: Path traversal in `/files`** (code fact)
- **Input and flow:** The query parameter `path` (L146) goes into `MATERIALS_DIR / raw_path` (L147) and then straight into `flask.send_file` (L148).
- **Missing control and root cause:** There is no normalization, containment check, or allow-list.
  - `pathlib` joining does not confine the result. `..` segments are not resolved, and an absolute `raw_path` such as `/etc/passwd` replaces the base entirely.
  - `send_file` serves whatever path it receives. `send_from_directory` is the confining variant, and it is not used here.
- **Preconditions and impact:**
  - The only precondition is network access, because SC-02 means no login is needed.
  - Impact is arbitrary file read as the app's OS user. This includes the application source (secret key and credentials), environment and config files, and other users' data.
  - It also gives an existence oracle: file-not-found and permission errors are distinguishable through SC-07.
  - It combines with SC-05 and SC-06.
- **Proposed test:**
  - Request `/files?path=../baseline_secure_coding_api.py`, `/files?path=/etc/hostname`, and `/files?path=srs-summary.txt` as a control.
  - Also try an empty path, which yields a directory error, and a path containing `%00`.
  - Any 200 response whose content comes from outside `materials/` confirms the finding. Rejection of every out-of-tree path rejects it.
- **Uncertainty:** The Windows drive-letter and UNC behavior differs, but the finding holds on both platforms. High confidence.

**SC-02: No authentication** (code fact)
- **Input and flow:** Requests to `/students/<id>/profile`, `/grades/<id>`, `/grades/update`, and `/files` reach their handlers with no check of `flask.session`.
  - Only `/me` inspects the session, and only to report on it.
  - There is no `before_request` hook or decorator anywhere in the file.
- **Missing control and root cause:** There is no authentication gate. Login creates a session that nothing consumes.
- **Impact:** All data and write operations are exposed to anonymous clients.
- **Proposed test:** Call each endpoint with no cookie. A 200 on any of them confirms the finding. A 401 or 403 rejects it.
- **Confidence:** High.

**SC-03: Missing authorization on grade updates** (the code fact is that there is no check; the required rule is inferred)
- **Input and flow:** The JSON body fields `student_id`, `course_id`, and `grade` (L132-134) are written directly to `GRADES` (L136-140).
- **Missing control and root cause:** Nothing checks the caller's role or whether `course_id` is among the caller's assigned courses. The session already carries `role` and `courses` (L92-94), but they are never consulted.
- **Preconditions and impact:** No credentials are needed (SC-02). Anyone can create or alter any grade for any student or course, which is a direct integrity compromise of academic records.
- **Proposed test:** Send `POST /grades/update` with no session, then as `alice` (student), then as `prof_srs` for course `SSD`. Any success other than a professor updating their own course confirms the finding.
- **Assumption:** The policy that only a professor assigned to the course, or an admin, may write is inferred from the description. Confidence is high, because under any plausible policy an anonymous write is a violation.

**SC-04: IDOR/BOLA on reads** (code fact; the ownership rule is inferred)
- **Input and flow:** The path parameter `student_id` is passed through `int()` and used as the lookup key (L117, L124). It is never compared with `session["student_id"]`.
- **Missing control and root cause:** There is no ownership or role check. Even after authentication is added, any student could enumerate IDs and read other students' data.
- **Additional observations:**
  - `int()` also accepts forms like `" 1001 "`, `"1_001"`, and non-ASCII digits, so one object can have several aliases. This matters for any check that compares raw strings.
  - Profiles return 404 for unknown IDs, while grades return `[]`. That difference is an enumeration oracle.
  - A non-numeric ID causes `ValueError` and a 500 with detail (SC-07).
- **Impact:** Disclosure of PII (name, email) and grades.
- **Proposed test:** Log in as `alice` and request `/students/1002/profile` and `/grades/1002`. Success confirms the finding. 403 or 404 rejects it. Then repeat with a professor for students outside their course.
- **Assumption:** The rule that students see only their own records and professors only their courses' records is inferred. Confidence is high.

**SC-05: Hardcoded secret key** (code fact)
- **Input and flow:** `SECRET_KEY = "dev-secret-key"` (L8) signs the client-side session cookie, which holds `user`, `role`, `student_id`, and `courses`.
- **Missing control and root cause:** The key is a guessable constant in source and is not loaded from the environment.
- **Preconditions and impact:** Anyone who knows or guesses the key can forge a session with any role or identity.
  - Today this is latent, because no endpoint reads the session for authorization.
  - It becomes critical as soon as authorization is added without changing the key.
  - The key is also exposed through SC-01, which can read the source.
- **Proposed test:** Offline, with a Flask/itsdangerous session serializer and the key above, sign a cookie with `role=admin` and submit it to `/me`. If `/me` echoes the forged claims, the key is valid and the finding is confirmed.
- **Confidence:** High for the fact, medium for the impact until the session is relied on.

**SC-06: Debug mode on 0.0.0.0** (code fact for the setting; impact depends on how it is run)
- **Input and flow:** `app.run(debug=True, host="0.0.0.0", ...)` (L159) exposes the Werkzeug debugger and reloader to the network.
- **Missing control and root cause:** Debug mode is hardcoded on and the bind address is hardcoded wide open.
- **Preconditions and impact:**
  - This applies only if the file is run directly as `__main__`.
  - The interactive debugger can execute arbitrary code, and its `/console` endpoint is PIN-protected.
  - Because `handle_error` catches `Exception`, most errors will not show the interactive traceback page, so exposure is mainly `/console`.
  - The PIN is derived from host values that SC-01 may be able to read, so chaining the two is plausible but unverified.
- **Proposed test:**
  - Start the app and request `/console` from another host. If the page loads, the debugger is exposed.
  - Separately, confirm whether file-read (SC-01) reaches the files the PIN depends on.
- **Confidence:** Medium.

**SC-07: Verbose catch-all error handler** (code fact)
- **Input and flow:** Every exception becomes a 500 containing `str(exc)` and the exception class name (L150-155). Examples include `KeyError('student_id')`, `ValueError` from `int()`, `FileNotFoundError` with an absolute path, and `IsADirectoryError`.
- **Missing control and root cause:** Raw exception text is returned to clients.
- **Impact:**
  - It leaks internals such as filesystem paths and the data model.
  - It serves as an oracle for SC-01.
  - `HTTPException`s (404, 405, 415, and so on) are also converted to 500, which breaks correct status semantics and any logic or monitoring that relies on them.
- **Proposed test:** Send malformed JSON, `/students/abc/profile`, and `/files?path=nonexistent`. Check whether the response bodies reveal paths or internals.
- **Confidence:** High.

**SC-08: Credentials handling** (code fact)
- **Input and flow:**
  - `USERS` holds plaintext passwords (L36-43).
  - Login compares them with `!=` (L88). Non-constant-time comparison and the early return for unknown users create a small timing difference.
- **Impact:** Anyone with source or memory access, such as through SC-01, obtains all credentials. Passwords are trivially weak, though that is likely intentional for a teaching dataset.
- **Proposed test:** Review the source, and measure response timing for valid and invalid usernames across many samples. Timing exploitability over a network is uncertain.
- **Assumption:** These are demo credentials. Confidence is high that the pattern is unsafe, and low on timing exploitability.

**SC-09: No brute-force protection** (code fact)
- **Input and flow:** `/login` (L82-96) has no lockout, throttling, or CAPTCHA, and the credentials are weak.
- **Impact:** Online password guessing and credential stuffing.
- **Proposed test:** Send repeated failed logins. If there is no 429 or lockout after many attempts, the finding is confirmed.
- **Confidence:** High for the missing control. Impact depends on password strength and any upstream rate limits.

**SC-10: Session lifecycle** (mostly inferred requirements)
- **CSRF** (not a fact until sessions are used for authorization):
  - Cookie-based sessions with state-changing POSTs and no CSRF token.
  - `get_json()` with a required JSON content type partly mitigates simple form CSRF.
  - Cookie `SameSite` and `Secure` attributes are not configured, and the cookie is `HttpOnly` by Flask default.
- **Logout:**
  - `session.clear()` (L100) only clears the cookie in the client.
  - Flask's cookie sessions are stateless, so a copied cookie stays valid until it expires.
  - There is no server-side revocation.
- **Stale claims:** `role` and `courses` are cached in the cookie at login (L92-94). Revoked privileges persist until the cookie expires.
- **Proposed test:**
  - Capture a cookie, log out, and replay it against `/me`.
  - Inspect `Set-Cookie` flags.
  - Attempt a cross-origin POST with a victim's cookie once authorization exists.
- **Confidence:** Medium.

**SC-11: Input validation and integrity on grade writes** (code fact)
- **Input and flow:**
  - `get_json()` is called with no validation (L130-134).
  - A missing or non-JSON body gives `None`, causing `TypeError` and a 500.
  - Missing keys cause `KeyError` (L132-134).
  - `student_id` as a string such as `"1001"` fails to match the integer rows, so a duplicate record is appended.
  - `grade` accepts any JSON type, including strings, negatives, huge numbers, and objects.
  - `student_id` and `course_id` need not refer to real students or courses.
  - The find-then-append sequence has no locking, so concurrent requests can create duplicate rows.
  - There is no audit trail for grade changes.
- **Impact:** Corrupted or inconsistent grade data, possible downstream parse errors, and an inability to attribute changes.
- **Proposed test:** Send the payloads above (`"1001"`, `-5`, `1e308`, `"abc"`, a missing key, and no body) and inspect `GRADES` through `GET /grades/<id>`. Run parallel updates to test for duplicates.
- **Confidence:** High for the missing validation. The race depends on the server's threading model.

## Other observations (lower confidence or hygiene)

- `GET /` lists every endpoint, which is minor information disclosure.
- There is no `MAX_CONTENT_LENGTH` and no request rate limiting, which gives some resource-exhaustion exposure.
- There are no security headers, no TLS awareness (the `Secure` cookie flag depends on it), and no logging of security events.
- The materials directory has no per-course scoping, and file types are not restricted. Both depend on a policy not stated in the code.

## Caveats

- This is a static review of one file. I did not execute anything, so every "confirmed" claim above is conditional on the proposed test.
- The absence of other findings here is not evidence of safety. Reverse proxies, WSGI settings, the Flask version, the OS, and anything outside this file were not reviewed.
- The strongest chain is SC-02 with SC-01, which gives an unauthenticated attacker the source, the secret key, and the credentials. SC-05 then allows session forgery and SC-03 allows grade tampering.