I'll reproduce the baseline locally, write the patch, and run the supplied tests against it.

The baseline reproduces as described: 7 failed, 2 passed. Now the patch.

All 9 tests pass. Next I'll check the extra regression tests I plan to suggest, so I only recommend ones that actually work.

I've fixed the `/files` endpoint. With the patch, all 9 tests in `test_file_access.py` pass (the original code gave 7 failed, 2 passed). I ran them locally on Python 3.13, not 3.10 like your CI. The patch uses nothing newer than 3.9, so it should behave the same there, but I didn't run it on 3.10.

## Unified diff

```diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -1,8 +1,10 @@
 import dataclasses
+import functools
 import pathlib
 import typing
 
 import flask
+import werkzeug.exceptions
 
 app = flask.Flask(__name__)
 app.config["SECRET_KEY"] = "dev-secret-key"
@@ -53,6 +55,37 @@
     {"student_id": 1001, "course_id": "SSD", "grade": 16},
 ]
 
+def login_required(view):
+    """Reject requests without an authenticated session (R1)."""
+
+    @functools.wraps(view)
+    def wrapper(*args, **kwargs):
+        if "user" not in flask.session:
+            return {"error": "authentication required"}, 401
+        return view(*args, **kwargs)
+
+    return wrapper
+
+
+def resolve_material(raw_path):
+    """Map a client-supplied relative path to a regular file inside
+    MATERIALS_DIR, or return None.
+
+    The path is fully resolved first (".." collapsed, symlinks followed,
+    absolute operands honoured), and only then checked for containment,
+    so every escape route is judged on the real final location.
+    """
+    base = MATERIALS_DIR.resolve()
+    try:
+        target = (base / raw_path).resolve(strict=True)
+    except (OSError, RuntimeError, ValueError):
+        # Missing file, symlink loop, embedded NUL byte, etc.
+        return None
+    if not target.is_relative_to(base) or not target.is_file():
+        return None
+    return target
+
+
 def find_grade(student_id, course_id):
     for row in GRADES:
         if row["student_id"] == student_id and row["course_id"] == course_id:
@@ -142,17 +175,22 @@
     return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
 
 @app.get("/files")
+@login_required
 def download_file():
     raw_path = flask.request.args.get("path", "")
-    target = MATERIALS_DIR / raw_path
+    target = resolve_material(raw_path)
+    if target is None:
+        # Same response for "outside the directory" and "does not exist",
+        # so the endpoint cannot be used to probe the filesystem.
+        return {"error": "file not found"}, 404
     return flask.send_file(target)
 
 @app.errorhandler(Exception)
 def handle_error(exc):
-    if isinstance(exc, werkzeug.exceptions.HTTPException):
-    return {
-        "error": str(exc),
-        "type": exc.__class__.__name__,
-    }, 500
+    if isinstance(exc, werkzeug.exceptions.HTTPException):
+        return {"error": exc.name}, exc.code
+    app.logger.exception("Unhandled exception")
+    return {"error": "internal server error"}, 500
```

(The attached `f06-path-traversal.patch` is the exact file produced by `diff -u`. Use that one when applying.)

## What each change does

**Path containment (R6).** The code first finds the real final location of the requested path, then checks that it is inside the materials folder. `resolve(strict=True)` does three things before the check runs: it collapses `..`, applies an absolute path (which replaces the base folder), and follows every symlink. `is_relative_to(base)` then compares whole path components, not text prefixes, so `materials_evil/` is not counted as inside `materials/`. All five attacks in the finding end up outside the base and are refused. A file must also be a regular file, so asking for a folder (`""`, `sub`, `..`) is refused too.

I chose this over `flask.send_from_directory` / `werkzeug.safe_join` because `safe_join` blocks `..` and absolute paths but still follows symlinks inside the folder. It would fail `test_symlink_escape_is_denied`.

**Authentication (R1).** A small `login_required` decorator returns `401 {"error": "authentication required"}` before any filesystem access, so unauthenticated users get no file content.

**Error handling (R7).** The endpoint returns the same `404 {"error": "file not found"}` whether the file is missing or outside the folder. This means it can't be used to check which files exist elsewhere on the server. I also changed the global error handler, since it's the root of the leak: it sent `str(exc)` to clients (including absolute paths) and turned every HTTP error, even a plain 404 for an unknown route, into a 500. It now keeps the status code of HTTP errors, logs unexpected exceptions on the server, and returns a generic 500.

What still works: `public.txt`, `sub/nested.txt`, `sub/../public.txt`, and symlinks that point to another file inside the folder.

## Other endpoints that need the same control

The containment check only matters for `/files`, because it's the only place user input becomes a filesystem path. The missing authentication, however, also affects other endpoints that R1 lists as protected:

- `GET /students/<student_id>/profile`
- `GET /grades/<student_id>`
- `POST /grades/update`

The `login_required` decorator can go on all three as it is. I left them out of this patch to keep it focused on F06. Logging in alone also doesn't decide who may see or change what (the 403 cases in R7). Those endpoints still need ownership and role checks, and they also crash with a 500 on bad input (`int("abc")`, missing JSON keys). These are separate findings.

## Remaining assumptions and limitations

- **Race between check and read.** A local attacker who can write inside `materials/` could swap a file for a symlink after the check and before `send_file` opens it. Fully closing this needs opening the file with `O_NOFOLLOW`/`openat` and sending the open file handle. That's overkill unless the folder is writable by untrusted users.
- **Same policy for every user.** Any logged-in user can download every file in `materials/`. If materials should depend on course or role, that's a separate authorisation control.
- **Symlinks pointing inside are allowed.** I assumed this is intended. If you'd rather refuse every symlink, reject paths where any component `is_symlink()`.
- **Platform.** I tested only on Linux. On Windows, backslashes, drive letters and UNC paths are also absolute or relative paths. `resolve()` plus `is_relative_to()` still covers them, but that's untested.
- **Other hardening still needed.** The hard-coded `SECRET_KEY` and `debug=True` should also be fixed before any real deployment.

## Suggested regression tests

These are in the attached `test_file_access_extra.py`. All 15 pass with the patch, and 13 fail on the unmodified code. The 2 that pass there are the two "still allowed" cases in the last group.

- **Odd paths are refused:** `..`, `sub/..`, empty path, `sub` (a folder), `..%2fsecret.txt`, a NUL byte, `sub/../../materials_evil/secret.txt` and `./../secret.txt`.
- **Symlink escapes are refused:** a symlinked folder leading outside (`evil_dir/secret.txt`), and a symlink loop, which must give 404, not a 500.
- **Legitimate access still works:** a symlink to another file inside the folder, and `sub/../public.txt`.
- **Login is enforced:** a traversal attempt without a session gets 401 with no secret in the body, and logging out removes access.
- **Errors keep their status:** an unknown route returns 404, not 500.

Once you add `login_required` to the profile and grades endpoints, it's worth adding a parametrised test that every protected route returns 401 without a session.