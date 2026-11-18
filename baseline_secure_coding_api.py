import dataclasses
import functools
import pathlib
import re
import typing

import flask
import werkzeug.exceptions

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

def login_required(view):
    """Reject requests without an authenticated session (R1)."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return {"error": "authentication required"}, 401
        return view(*args, **kwargs)

    return wrapper


def resolve_material(raw_path):
    """Map a client-supplied relative path to a regular file inside
    MATERIALS_DIR, or return None.

    The path is fully resolved first (".." collapsed, symlinks followed,
    absolute operands honoured), and only then checked for containment,
    so every escape route is judged on the real final location.
    """
    base = MATERIALS_DIR.resolve()
    try:
        target = (base / raw_path).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        # Missing file, symlink loop, embedded NUL byte, etc.
        return None
    if not target.is_relative_to(base) or not target.is_file():
        return None
    return target


def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


# -----------------------------------------------------------------------------
# Access control helpers
# -----------------------------------------------------------------------------

_STUDENT_ID_RE = re.compile(r"[1-9][0-9]*")  # ASCII only, no sign/space/_/0-prefix


def parse_student_id(raw):
    """Return a positive int for a canonical decimal identifier, else None."""
    if not isinstance(raw, str) or not _STUDENT_ID_RE.fullmatch(raw):
        return None
    return int(raw)


def current_user():
    """Resolve the session to a server-side User; never trust role from the cookie."""
    username = flask.session.get("user")
    if not isinstance(username, str):
        return None
    return USERS.get(username)


def can_read_grade(user, row):
    if user.role == "admin":
        return True
    if user.role == "student":
        return user.student_id is not None and row["student_id"] == user.student_id
    if user.role == "professor":
        return row["course_id"] in (user.courses or [])
    return False


def can_read_profile(user, student_id):
    if user.role == "admin":
        return True
    if user.role == "student":
        return user.student_id is not None and student_id == user.student_id
    return False  # professors and unknown roles: no profile access (R3)


def _unauthenticated():
    return {"error": "authentication required"}, 401


def _forbidden():
    return {"error": "forbidden"}, 403


def _bad_student_id():
    return {"error": "invalid student id"}, 400


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    user = current_user()
    if user is None:
        return _unauthenticated()
    sid = parse_student_id(student_id)
    if sid is None:
        return _bad_student_id()
    if not can_read_profile(user, sid):
        return _forbidden()
    profile = STUDENT_PROFILES.get(sid)
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

@app.get("/grades/<student_id>")
def get_grades(student_id):
    user = current_user()
    if user is None:
        return _unauthenticated()
    sid = parse_student_id(student_id)
    if sid is None:
        return _bad_student_id()
    rows = [
        row for row in GRADES
        if row["student_id"] == sid and can_read_grade(user, row)
    ]
    if not rows:
        # Same answer for "not allowed" and "does not exist": no existence oracle.
        return _forbidden()
    return flask.jsonify(rows)

@app.post("/grades/update")
def update_grade():
    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

@app.get("/files")
@login_required
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = resolve_material(raw_path)
    if target is None:
        # Same response for "outside the directory" and "does not exist",
        # so the endpoint cannot be used to probe the filesystem.
        return {"error": "file not found"}, 404
    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, werkzeug.exceptions.HTTPException):
        # Keep framework client errors (404, 405, 400...) as-is, generic body.
        return {"error": exc.name}, exc.code
    app.logger.exception("unhandled error")
    return {"error": "internal server error"}, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)