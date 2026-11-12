# Static security review: `baseline_secure_coding_api.py`

Line numbers are approximate, based on the file as provided. I did not run or test anything. A "code fact" is something directly visible in the source. An "inferred requirement" is a policy I am assuming, and I label it as such.

## Assumed policy (not stated in the source)

- Students may read only their own profile and grades.
- Professors may read and write grades only for courses listed in their `courses`.
- Admins may do both for any student or course.
- Only files inside `materials/` are meant to be served.
- Passwords and the secret key should be treated as real secrets.

If the app is purely a throwaway teaching baseline, several severities below drop. The missing access controls and the path traversal stay serious either way.

## Findings table

| ID | Title | Location | Severity (inferred) | Confidence |
|---|---|---|---|---|
| SC-01 | Path traversal / arbitrary file read | `download_file`, ~L144–148 | Critical | High |
| SC-02 | No authentication or authorization on grade updates | `update_grade`, ~L128–142 | Critical | High (facts), policy assumed |
| SC-03 | No authentication; broken object-level authorization on profile and grades reads | `get_profile`, `get_grades`, ~L115–126 | High | High (facts), policy assumed |
| SC-04 | Werkzeug debug mode bound to all interfaces | `app.run(...)`, ~L159 | High (conditional) | Medium |
| SC-05 | Hardcoded, weak `SECRET_KEY` (forgeable sessions) | ~L8 | High (latent) | High (fact), impact conditional |
| SC-06 | Verbose exception disclosure; client errors reported as 500 | `handle_error`, ~L150–155 | Medium | High / Medium |
| SC-07 | Insufficient input validation and non-atomic update | `update_grade`, ~L130–140 | Medium | High / Medium |
| SC-08 | Plaintext, hardcoded credentials; non-constant-time compare | ~L30, 36–43, 88 | Medium (context-dependent) | High |
| SC-09 | No brute-force protection on login | `login`, ~L82–96 | Medium | Medium |
| SC-10 | Weak session management (no revocation, cookie flags, no TLS, no CSRF tokens) | ~L8, 91–101 | Low–Medium | Medium |
| SC-11 | Unbounded resource consumption | `update_grade`, `download_file`, app config | Low–Medium | Medium |

## Supporting explanations

### SC-01 Path traversal / arbitrary file read
- **Location:** `download_file()`, `GET /files`.
- **Input and flow:** the query parameter `path` becomes `raw_path`, then `MATERIALS_DIR / raw_path`, then `flask.send_file(target)`.
- **Missing control and root cause:** there is no canonicalization or containment check against `MATERIALS_DIR`, and no authentication.
  - Code fact: `pathlib` does not collapse `..`, and an absolute right-hand operand replaces the left-hand side entirely.
  - Code fact: `send_file` performs no containment check of its own, unlike a safe-join helper.
- **Preconditions:** network reach to port 5001, and the target file is readable by the process.
- **Impact:** disclosure of any file the process can read. That includes this source file, and so the secret key and credentials (SC-05, SC-08), plus OS and application files. It also feeds SC-04 and SC-06.
- **Fact vs. inference:** no check exists between reading the parameter and calling `send_file`. That only `materials/` should be reachable is an inferred requirement.
- **Test:**
  1. `?path=srs-summary.txt` as a baseline; it should return 200.
  2. `?path=../baseline_secure_coding_api.py`.
  3. An absolute path to a known readable file.
  4. URL-encoded `..` variants, an empty path (directory case), and a symlink inside `materials/` pointing outside it.
  5. Confirmed if out-of-directory content is returned. Rejected if every variant gets 4xx and no content.
- **Confidence:** high.

### SC-02 No authentication or authorization on `POST /grades/update`
- **Input and flow:** JSON fields `student_id`, `course_id`, `grade` go to `find_grade` and then either append to or mutate the global `GRADES`.
- **Missing control:** there is no authentication check, no role check, and no check that a professor teaches the course. The function never touches `flask.session`.
- **Code fact:** `login` stores `role` and `courses` in the session (~L91–94), but nothing enforces them. This suggests the intended policy is unimplemented, which is an inference.
- **Preconditions:** network access and a `Content-Type: application/json` request. No credentials are needed.
- **Impact:** anyone can create or change any grade, which is an integrity failure of academic records. There is also no audit trail of who changed what (the missing logging is a code fact; needing it is an inferred requirement).
- **Test:**
  1. Send an unauthenticated update, then `GET /grades/1001` to see whether it took effect.
  2. Repeat as `alice` (student), as `prof_srs` for `SRS`, and as `prof_srs` for `SSD`.
  3. Expected under the assumed policy: 401, 403, 200, 403. Observed 200 everywhere confirms the claim.
- **Confidence:** high for the facts, since the missing check is directly visible. The policy is assumed.

### SC-03 Missing authentication and BOLA on reads
- **Locations:** `GET /students/<student_id>/profile` and `GET /grades/<student_id>`.
- **Input and flow:** the path parameter goes through `int()`, then a lookup, then the full record is returned.
- **Missing control:** no session check and no ownership or role comparison against `session["student_id"]`.
- **Impact:** anonymous or cross-user reads of names, emails, programs, and grades. The sequential IDs (1001, 1002) make enumeration easy. The profile endpoint also leaks existence through 404 vs. 200.
- **Side note:** `int()` accepts several spellings of one ID (whitespace, underscores, leading zeros, non-ASCII digits). Any later ID-based filtering must operate on the parsed value, not the raw string.
- **Test:**
  1. Request `/grades/1001` and `/students/1001/profile` unauthenticated.
  2. Request them logged in as `bob`.
  3. Request IDs 1001–1010 and compare status codes.
  4. Expected under the assumed policy: 401 unauthenticated and 403 for another student's data.
- **Confidence:** high for the facts, policy assumed.

### SC-04 Debug mode on all interfaces
- **Location:** `app.run(debug=True, host="0.0.0.0", port=5001)`.
- **Flow:** when run as `__main__`, the Werkzeug development server starts with the interactive debugger and reloader, reachable from the network.
- **Missing control:** debug should be off outside local development, binding should be loopback, and a production WSGI server should be used.
- **Nuance:** the catch-all `errorhandler(Exception)` likely intercepts exceptions before the traceback page appears. However, the debugger's `/console` endpoint is normally still served and is protected only by a PIN. Behavior varies by Flask and Werkzeug version.
- **Impact:** if the PIN is bypassed or leaked, arbitrary code execution. SC-01 could expose host data relevant to that.
- **Preconditions:** the app is launched via `python file.py` and is network-reachable. None of this applies if it is deployed behind a WSGI server with debug off.
- **Test:** from another host, request `/console` and check the `Server` header. Confirm `app.debug` at runtime in a lab instance.
- **Confidence:** medium. The flag is a code fact, but exploitability depends on versions and deployment.

### SC-05 Hardcoded weak secret key
- **Location:** `app.config["SECRET_KEY"] = "dev-secret-key"`.
- **Flow:** Flask sessions are client-side signed cookies. Anyone who knows the key can forge a cookie with arbitrary `user`, `role`, `student_id`, and `courses`. The key is in the source and readable through SC-01.
- **Impact:** currently limited, because only `/me` reads the session. It becomes critical once any authorization is built on the session, which is the natural remedy for SC-02 and SC-03.
- **Test:** in a lab, craft a cookie signed with this key setting `role=admin`, then call `/me`. If `/me` reflects it, the claim is confirmed.
- **Confidence:** high that the key is hardcoded and guessable. The impact is conditional on future use.

### SC-06 Verbose exception disclosure and misclassified errors
- **Location:** `handle_error`, which returns `str(exc)` and the exception class name with status 500 for every exception.
- **Input and flow:** any failing request. Examples: `/students/abc/profile` (`ValueError`), missing JSON keys (`KeyError`), a bad body, a nonexistent file, unknown routes.
- **Impact:** leaks internal names and likely absolute filesystem paths (for example from a file-not-found error). It also acts as an oracle that sharpens SC-01.
- **Likely inference:** in Flask 2.x and later, a handler registered for `Exception` probably also receives `HTTPException`. That would turn 404, 405, and 415 into 500s and distort monitoring and client behavior. I have not verified your version.
- **Test:** request `/students/abc/profile`, `/files?path=nope`, `POST /grades/update` with an empty body and with `text/plain`, and `/nonexistent`. Inspect the bodies and status codes.
- **Confidence:** high for the disclosure, medium for the HTTP-status behavior.

### SC-07 Insufficient validation and non-atomic update
- **Facts in `update_grade`:**
  - `data` may be `None`, which raises a `TypeError`.
  - `grade` accepts any JSON value (string, negative, huge, NaN, object).
  - `student_id` and `course_id` are not checked against `STUDENT_PROFILES` or known courses, so orphan rows can be created.
  - `"1001"` (string) does not equal `1001` (int) in `find_grade`, so duplicate or hidden rows can appear. `get_grades` only matches integer IDs.
  - The check-then-append on a shared list has no locking.
- **Inferred requirement:** a valid grade range (probably 0–20 given the seed data, which is an assumption), and existing students and courses.
- **Impact:** data corruption, hidden or duplicate records, and 500 errors that leak detail (SC-06).
- **Test:** POST `grade` as `"abc"`, `-5`, `99`, and `null`. POST `student_id` as `"1001"` and `9999`. Send concurrent identical requests for a new key and count the rows.
- **Confidence:** high for the missing validation, medium for the race (depends on threading).

### SC-08 Plaintext and hardcoded credentials
- **Facts:** passwords are stored in plaintext in source (`alicepw`, `adminpw`, and so on) and compared with `!=`, which is not constant-time.
- **Impact:** disclosure of the source, for example through SC-01, discloses every credential, including `admin1`. Guessable defaults allow takeover if used outside a demo. The timing difference is likely impractical to exploit.
- **Test:** log in with the listed credentials. Review the source for hashing. Timing measurement is optional and low-confidence.
- **Confidence:** high for the facts, impact depends on whether this is demo-only.

### SC-09 No brute-force protection on `/login`
- **Facts:** there is no attempt counter, delay, lockout, or throttling. Login messages are uniform, so username enumeration is not demonstrated.
- **Impact:** unlimited guessing, amplified by weak credentials.
- **Uncertainty:** a reverse proxy or other layer outside this file might throttle.
- **Test:** in a lab, send a few hundred failed logins in a short window and watch for 429, delays, or lockout.
- **Confidence:** medium.

### SC-10 Weak session management
- **Facts:**
  - Sessions are stateless signed cookies. `logout` only clears the client's copy, so a captured cookie stays valid until its server-checked lifetime ends. As far as I know that default is 31 days, but I have not verified it.
  - No `SESSION_COOKIE_SECURE` or `SESSION_COOKIE_SAMESITE` configuration. HttpOnly is Flask's default.
  - The app serves plain HTTP, so any TLS must be provided elsewhere.
  - `POST /login` and `POST /logout` have no CSRF tokens. Impact is low (login CSRF and forced logout), and SameSite defaults in modern browsers reduce it.
- **Test:** log in, save the cookie, log out, replay the old cookie against `/me`. Inspect `Set-Cookie` attributes. Capture traffic on a lab network.
- **Confidence:** medium. Impact depends on deployment (TLS proxy, browser behavior).

### SC-11 Unbounded resource consumption
- **Facts:** `MAX_CONTENT_LENGTH` is not set. The unauthenticated `GRADES` list grows with each new key. `send_file` serves whatever size the target is.
- **Impact:** memory growth and denial of service of an in-memory store.
- **Test:** in an isolated lab, post many distinct keys and one oversized body, and observe memory and response behavior.
- **Confidence:** medium; low severity.

## Considered, with no finding from this source

- **SQL injection:** no database is used.
- **XSS and SSTI:** responses are JSON and there are no templates.
- **Command injection and unsafe deserialization:** none present.
- **Open redirect:** the login redirect target is a constant.
- **Login enumeration:** error messages are uniform.

These are not proofs of safety. This review cannot assess dependency versions, deployment and TLS configuration, reverse-proxy behavior, or any code outside this file.

## Chains worth testing

- SC-01 → SC-05: read the source, take the key, forge a session.
- SC-01 + SC-06: use the error messages as an oracle to map the filesystem.
- SC-04 + SC-01: debug exposure combined with host-information disclosure.