# Repair prompt: F06 (repair assistance)

> **Not a discovery result.** This is the separate repair conversation of Section 11. Everything below the horizontal rule is the exact text sent to the model.
>
> - Model: Claude Opus 5.5, medium effort
> - Date: _fill in_
> - Conversation: new, no earlier context

---

We are now repairing a confirmed vulnerability in the supplied application.

## Confirmed finding

Path traversal and arbitrary file read in `GET /files` (`download_file`). The user-controlled query parameter `path` is joined to `MATERIALS_DIR` with `pathlib` and passed to `flask.send_file()` with no containment check.

- **Root cause:** nothing resolves the path or checks that it stays inside the materials directory. `..` segments are not collapsed by `pathlib`, an absolute right-hand operand replaces the base directory entirely, and symbolic links inside the directory are followed.
- **Authentication:** the endpoint requires no authentication.
- **Error handling:** a missing file raises an exception that the global error handler returns as a 500 containing the absolute server path.
- **Reproduction:** requests with `../secret.txt`, `sub/../../secret.txt`, `../materials_evil/secret.txt`, an absolute path, and a symbolic link inside `materials/` pointing outside all returned 200 with the contents of a file outside the materials directory. A nonexistent file returned 500 with internal detail. A request without a session returned 200 instead of 401.

### CI failure on the unmodified baseline

- Run: https://github.com/gugax1515/cybersecurity_lab_devsecops/actions/runs/43213835501
- Job: `security-regression` (`python -m pytest -v tests_security`), Python 3.10.22, pytest 9.2.0
- Result for the F06 tests (`test_file_access.py`): **7 failed, 2 passed**

Passing tests (permitted operations that must keep passing):

- `test_authenticated_user_can_download_material`
- `test_authenticated_user_can_download_nested_material`

Failing tests:

| Test | Failing assertion | Violated requirement |
|---|---|---|
| `test_relative_traversal_is_denied[../secret.txt]` | `assert 200 in (400, 403, 404)` | R6 |
| `test_relative_traversal_is_denied[sub/../../secret.txt]` | `assert 200 in (400, 403, 404)` | R6 |
| `test_relative_traversal_is_denied[../materials_evil/secret.txt]` | `assert 200 in (400, 403, 404)` | R6 |
| `test_absolute_path_is_denied` | `assert 200 in (400, 403, 404)` | R6 |
| `test_symlink_escape_is_denied` | `assert 200 in (400, 403, 404)` | R6 |
| `test_missing_file_does_not_leak_internal_path` | `assert 500 in (400, 403, 404)` | R7 |
| `test_unauthenticated_download_returns_401` | `assert 200 == 401` | R1 |

All failures are assertion failures on security requirements. There are no import errors, missing fixtures or skipped tests.

## Required behavior

**R1 - Authentication.** Profile access, grade access, grade updates, and material downloads require an authenticated user. The index and login endpoint may remain public. The `/me` endpoint may return `{"user": null}` when no user is authenticated.

**R6 - File access.** Authenticated users may download teaching materials within the materials directory. Requests must not read files outside that directory.

**R7 - Error handling.** Invalid requests must return appropriate client errors without exposing internal paths, tracebacks, or implementation exception details. Unauthenticated protected requests return 401; authenticated but unauthorized requests return 403. A denied or invalid update must leave stored data unchanged.

### Legitimate uses

- An authenticated user can still download a file inside the materials directory (for example `public.txt`).
- An authenticated user can still download a file in a subfolder of the materials directory (for example `sub/nested.txt`).

## Task

Propose a minimal, reviewable patch addressing the root cause. Preserve the API's legitimate functionality and relevant response contracts. Do not delete endpoints, disable features, weaken tests, or suppress scanner rules to hide the issue. Identify all affected paths that need the same control.

Return a unified diff, explain the control being implemented, and identify remaining assumptions or limitations. Suggest additional regression tests.

## Source: `baseline_secure_coding_api.py`

```python
import dataclasses
import pathlib
import typing

import flask

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

def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


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
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

@app.get("/grades/<student_id>")
def get_grades(student_id):
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
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
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
```

## Tests: `tests_security/test_file_access.py`

```python
import pytest
import baseline_secure_coding_api as api

SECRET = "TOP-SECRET-OUTSIDE"
PUBLIC = "public material"


def login(client, username, password):
    r = client.post("/login", data={"username": username, "password": password},
                    follow_redirects=True)
    assert r.status_code == 200
    assert r.get_json()["user"] == username


def get_file(client, path):
    return client.get("/files", query_string={"path": path})


def assert_denied(resp, root):
    body = resp.get_data(as_text=True)
    assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
    assert SECRET not in body                 
    assert str(root) not in body              


# Operacoes legitimas 
def test_authenticated_user_can_download_material(client, materials):
    login(client, "alice", "alicepw")
    r = get_file(client, "public.txt")
    assert r.status_code == 200
    assert r.get_data(as_text=True) == PUBLIC


def test_authenticated_user_can_download_nested_material(client, materials):
    login(client, "alice", "alicepw")
    r = get_file(client, "sub/nested.txt")
    assert r.status_code == 200
    assert r.get_data(as_text=True) == "nested"


# malicious operation
@pytest.mark.parametrize("attack", [
    "../secret.txt",                  # traversal 
    "sub/../../secret.txt",           # traversal subpasta
    "../materials_evil/secret.txt",   
])
def test_relative_traversal_is_denied(client, materials, attack):
    login(client, "alice", "alicepw")
    assert_denied(get_file(client, attack), materials)


def test_absolute_path_is_denied(client, materials):
    login(client, "alice", "alicepw")
    assert_denied(get_file(client, str(materials / "secret.txt")), materials)


def test_symlink_escape_is_denied(client, materials):
    link = materials / "materials" / "link.txt"
    try:
        link.symlink_to(materials / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks não suportados neste ambiente")
    login(client, "alice", "alicepw")
    assert_denied(get_file(client, "link.txt"), materials)


def test_missing_file_does_not_leak_internal_path(client, materials):
    login(client, "alice", "alicepw")
    assert_denied(get_file(client, "nao_existe.txt"), materials)


# R1
def test_unauthenticated_download_returns_401(client, materials):
    assert get_file(client, "public.txt").status_code == 401
```

## Fixtures: `tests_security/conftest.py`

```python
import copy
import pytest
import baseline_secure_coding_api as api
@pytest.fixture(autouse=True)
def restore_grades():
    original = copy.deepcopy(api.GRADES)
    yield
    api.GRADES[:] = original
@pytest.fixture
def client():
    with api.app.test_client() as client:
        yield client


SECRET = "TOP-SECRET-OUTSIDE"
PUBLIC = "public material"

@pytest.fixture
def materials(tmp_path, monkeypatch):
    base = tmp_path / "materials"
    base.mkdir()
    (base / "public.txt").write_text(PUBLIC)
    (base / "sub").mkdir()
    (base / "sub" / "nested.txt").write_text("nested")

    (tmp_path / "secret.txt").write_text(SECRET)              
    evil = tmp_path / "materials_evil"                        
    evil.mkdir()
    (evil / "secret.txt").write_text(SECRET)

    monkeypatch.setattr(api, "MATERIALS_DIR", base)
    return tmp_path   
```
