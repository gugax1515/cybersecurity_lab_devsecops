I'll reproduce the baseline locally, write the patch, and run the F03 suite plus some extra regression tests against it.

Baseline reproduces (21 failed, 2 passed). Now the patch.

Now some extra regression tests for the cases the suite doesn't cover.

I've attached the patch as `f03_grades_authz.patch` and the new tests as `test_grades_read_authorization_extra.py`. I ran it locally on Python 3.10, Flask 3.1 and pytest 9.1. Before the patch the F03 file gave the same result as your CI run: 21 failed, 2 passed. After the patch all 23 F03 tests pass, and so do the 17 new tests (40 in total). The supplied `test_grade_authorization.py` wasn't in the attachment, so I couldn't run it. The patch doesn't touch `/grades/update`, so that test should be unaffected.

**What the patch does**

Every protected read now goes through the same steps, in this order:

1. **Login check (R1).** `current_user()` takes the username from the session and looks the user up in `USERS` on the server. Role, `student_id` and `courses` come from that server-side record, never from the cookie. So a forged `role` in the session gets nothing, an unknown user gets 401, and a change to a professor's courses applies on their next request.
2. **ID check (R5).** `parse_student_id()` only accepts plain ASCII positive integers: it must fully match `[1-9][0-9]*`. Anything else gets a 400 before `int()` runs. This fixes the root cause of the alias bypass: `int()` accepted `01002`, `+1002`, `1_002`, `" 1002"`, `1002\n` and Unicode digits as Bob's ID. Now the value that gets checked and the value that gets used are the same.
3. **Per-row permission check (R2–R4).** `can_read_grade(user, row)` runs on every grade row:
   - admins can read every row;
   - students can read only rows with their own ID;
   - professors can read only rows for their assigned courses.

   If no rows are left, the answer is 403. A forbidden student and a nonexistent one get exactly the same response, so the endpoint no longer reveals whether a student exists. The response shape is unchanged: a JSON list of `{student_id, course_id, grade}`.
4. **Error handler (R7).** The catch-all handler used to return `str(exc)` and the exception type with a 500. It also turned Werkzeug's own 404 and 405 errors into 500s; `GET /grades/` showed this. Now framework errors keep their real status code with a generic message, and anything else returns `{"error": "internal server error"}` and is logged on the server only.

**Other endpoints with the same problem**

- **`GET /students/<id>/profile`** — same root cause (no session check, bare `int()`), now fixed in the patch. Students can read their own profile, admins can read any, professors get 403 (R3). Admins still get 404 for an unknown ID. Everyone else gets 403 before the lookup, so they can't use it to test whether a student exists.
- **`POST /grades/update`** — still open, and I left it out to keep the diff reviewable. It needs the login check, a write rule (admin, or a professor for the course in the request), and the R5 body checks: JSON object, existing student, `course_id` in {SRS, SSD}, a number from 0 to 20 that isn't a bool, and no changes on rejection. It also currently inserts new rows, which lets a caller create grades for students that don't exist. Please look at it next; the helpers in the patch are built to be reused there.
- **`GET /files`** — needs the login check (R1). It also has a separate path traversal bug: `MATERIALS_DIR / raw_path` with no containment check. The fix is `flask.send_from_directory` or a check that the resolved path stays inside the folder.

**Assumptions and limitations**

- **Empty results.** I read R4 literally: any request with no readable rows gets 403. That includes an admin asking for an unknown student and a student with no grades yet asking for their own, which used to return `200 []`. If you'd rather keep `200 []` for admins and a student's own record, only the empty-result check needs to change.
- **Hard-coded secret key.** `SECRET_KEY` is still `"dev-secret-key"` in the source. Anyone who knows it can sign their own session cookie as `admin1`. Checking the user on the server stops a forged role, but not a forged username. The key should come from the environment.
- **Logout and old cookies.** Sessions are cookie-based and stateless, so logout only clears the browser's copy. A copied cookie stays valid until it expires. Fixing that needs server-side sessions or a session version stored per user.
- **Other baseline problems I left alone:** plaintext passwords, `debug=True` on `0.0.0.0`, and no CSRF protection on `/login` and `/logout`.
- **Unknown roles get no access.** Any role other than admin, student or professor is denied.

**Additional regression tests (all in the attached file)**

- **More fake ID spellings:** Arabic-Indic digits, a trailing newline, a leading tab, `1002.0`, `0x3EA`, `1e3`, an encoded `+`, and an empty ID.
- **Forged sessions:** a session claiming the admin role, and a session for a user that doesn't exist.
- **Live permissions:** changing a professor's courses applies without logging in again.
- **No existence leak:** asking for Bob and asking for a nonexistent student give byte-identical 403 responses.
- **Response shape** is preserved.
- **Profile endpoint:** login required, students see only their own, professors are denied, admins get 200/404/400 as expected.

When you fix `/grades/update`, it's also worth adding:

- an unauthenticated or unauthorized update leaves `GRADES` unchanged;
- `grade: true`, `-1`, `21`, `"15"` and a missing field are all rejected;
- an unknown course or student is rejected;
- `/files?path=../baseline_secure_coding_api.py` doesn't return the source.