--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ MATERIALS_DIR definition (unchanged) @@
 BASE_DIR = pathlib.Path(__file__).resolve().parent
 MATERIALS_DIR = BASE_DIR / "materials"
 MATERIALS_DIR.mkdir(exist_ok=True)
 
+
+def _resolve_material(raw_path: str):
+    """Map a user-supplied relative path to a file strictly inside MATERIALS_DIR.
+
+    Returns a resolved pathlib.Path, or None if the request is not acceptable.
+    The root is resolved per call (not at import time) so it always reflects
+    the current MATERIALS_DIR.
+    """
+    if not raw_path or "\x00" in raw_path:
+        return None
+    root = MATERIALS_DIR.resolve()
+    try:
+        # resolve() collapses "..", discards the base for absolute operands
+        # and follows symlinks, so the containment check below is applied
+        # to the real on-disk location of the file.
+        target = (root / raw_path).resolve()
+    except (OSError, ValueError, RuntimeError):
+        return None
+    if not target.is_relative_to(root):      # Python >= 3.9
+        return None
+    if not target.is_file():
+        return None
+    return target
+
+
 @app.get("/files")
 def download_file():
-    raw_path = flask.request.args.get("path", "")
-    target = MATERIALS_DIR / raw_path
-    return flask.send_file(target)
+    # R1: authentication first, before touching the filesystem.
+    if not flask.session.get("user"):        # same key /login sets
+        return flask.jsonify({"error": "authentication required"}), 401
+
+    raw_path = flask.request.args.get("path", "")
+    if not raw_path or "\x00" in raw_path:
+        return flask.jsonify({"error": "invalid path"}), 400
+
+    # R6: containment. Escapes and missing files get the same generic 404,
+    # so the response doesn't reveal what exists outside the directory.
+    target = _resolve_material(raw_path)
+    if target is None:
+        return flask.jsonify({"error": "file not found"}), 404
+
+    try:
+        return flask.send_file(target)
+    except OSError:                          # file vanished between check and send
+        return flask.jsonify({"error": "file not found"}), 404