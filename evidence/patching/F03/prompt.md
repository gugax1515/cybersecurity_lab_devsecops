# Repair prompt: F03 (repair assistance)

> **Not a discovery result.** This is the separate repair conversation of Section 11. Everything below the horizontal rule is the exact text sent to the model.
>
> - Model: Claude Opus 5.5, medium effort
> - Date: 12 November 2026
> - Conversation: new, no earlier context

---

We are now repairing a confirmed vulnerability in the supplied application.

## Confirmed finding

`GET /grades/<student_id>` (`get_grades`) has no authentication and no authorization. It returns every grade row of the requested student to any caller.

- **Root cause:** the handler never reads the session or compares the requester with the requested record, and it parses the identifier with a bare `int()`.
- **Reproduction:** an unauthenticated request to `/grades/1001` returns 200 with all rows.

### CI failure on the unmodified baseline

- Run: https://github.com/gugax1515/cybersecurity_lab_devsecops/actions/runs/43213835501
- Job: `security-regression` (`python -m pytest -v tests_security`), Python 3.10.22, pytest 9.2.0
- Result for the F03 tests (`test_grades_read_authorization.py`): **21 failed, 2 passed**

Passing tests (permitted operations that must keep passing):

- `test_student_can_read_own_grades`
- `test_administrator_can_read_any_students_grades`
- `test_grade_authorization.py::test_assigned_professor_can_update_grade` (supplied example, unrelated to this endpoint)

Failing tests:

| Test | Failing assertion | Violated requirement |
|---|---|---|
| `test_unauthenticated_request_is_rejected_without_data` | `assert 200 == 401` | R1 |
| `test_request_after_logout_is_rejected` | `assert 200 == 401` | R1 |
| `test_student_cannot_read_another_students_grades` | `assert 200 == 403` | R2 |
| `test_student_cannot_bypass_check_with_id_aliases` (5 cases: `01002`, `+1002`, `1_002`, `%201002`, `1002%20`) | `assert 200 in (400, 403)` | R2, R5 |
| `test_student_denied_for_unknown_student_id_without_existence_oracle` | `assert 200 == 403` | R4 |
| `test_professor_sees_only_rows_of_assigned_course` | extra row `(1001, 'SSD', 16)` returned | R3, R4 |
| `test_professor_denied_when_student_has_no_row_in_assigned_course` | `assert 200 == 403` | R3, R4 |
| `test_professor_denied_for_unknown_student` | `assert 200 == 403` | R4 |
| `test_invalid_student_id_gets_client_error_without_leaking_details` (8 cases) | `abc` and `1.5`: `500 < 500`; `0` and `-5`: `400 <= 200` | R5, R7 |
| `test_second_user_session_does_not_inherit_first_users_access` | `assert 200 == 403` | R2 |

All failures are assertion failures on security requirements. There are no import errors, missing fixtures or skipped tests.

## Required behavior

**R1 - Authentication.** Profile access, grade access, grade updates, and material downloads require an authenticated user. The index and login endpoint may remain public. The `/me` endpoint may return `{"user": null}` when no user is authenticated.

**R2 - Student privacy.** Students may read only their own profile and grades.

**R3 - Academic staff scope.** Professors may read and update grades only for their assigned courses. In this simplified exercise, professors are not permitted to read student profile records. Administrators may read profiles and grades and update grades.

**R4 - Complete authorization.** Check authorization on every relevant request. Login alone, a valid identifier, or a role name alone does not establish permission for a particular record. For a grade-list response, return only records the requester is authorized to read. Deny a request that has no permitted records; do not disclose other grades.

**R5 - Input validation.** Student identifiers must be positive integers. Grade updates require a JSON object with an existing student identifier, a known course identifier, and a numeric grade from 0 to 20 inclusive. Boolean values are not valid grades. Reject missing fields and malformed input without applying an update. Known courses for this baseline are SRS and SSD.

**R7 - Error handling.** Invalid requests must return appropriate client errors without exposing internal paths, tracebacks, or implementation exception details. Unauthenticated protected requests return 401; authenticated but unauthorized requests return 403. A denied or invalid update must leave stored data unchanged.

### Legitimate uses

- A student reads their own grades.
- A professor reads only the rows of assigned courses.
- An administrator reads all grades.

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

## Tests: `tests_security/test_grades_read_authorization.py`

```python
"""F03 - authorization on GET /grades/<student_id> (R1, R2, R3, R4, R5, R7)."""
import pytest

import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def pairs(response):
    """(student_id, course_id, grade) triples of a successful grade list."""
    return sorted((r["student_id"], r["course_id"], r["grade"]) for r in response.get_json())


# ---- R1: authentication ---------------------------------------------------

def test_unauthenticated_request_is_rejected_without_data(client):
    response = client.get("/grades/1001")

    assert response.status_code == 401          # not a redirect, not 200
    assert "grade" not in response.get_data(as_text=True)


def test_request_after_logout_is_rejected(client):
    login(client, "alice", "alicepw")
    assert client.get("/grades/1001").status_code == 200

    client.post("/logout")

    assert client.get("/grades/1001").status_code == 401


# ---- R2: student privacy --------------------------------------------------

def test_student_can_read_own_grades(client):
    login(client, "alice", "alicepw")

    response = client.get("/grades/1001")

    assert response.status_code == 200
    assert pairs(response) == [(1001, "SRS", 14), (1001, "SSD", 16)]


def test_student_cannot_read_another_students_grades(client):
    login(client, "alice", "alicepw")

    response = client.get("/grades/1002")

    assert response.status_code == 403
    body = response.get_data(as_text=True)
    assert "1002" not in body and "15" not in body      # Bob's record not disclosed


@pytest.mark.parametrize("alias", ["01002", "+1002", "1_002", "%201002", "1002%20"])
def test_student_cannot_bypass_check_with_id_aliases(client, alias):
    """int() accepts several spellings of 1002; a patch comparing raw strings,
    or parsing differently from the check, would leak Bob's grades."""
    login(client, "alice", "alicepw")

    response = client.get(f"/grades/{alias}")

    assert response.status_code in (400, 403)
    assert "grade" not in response.get_data(as_text=True)


def test_student_denied_for_unknown_student_id_without_existence_oracle(client):
    login(client, "alice", "alicepw")

    assert client.get("/grades/9999").status_code == 403


# ---- R3 / R4: professor scope and per-record filtering ---------------------

def test_professor_sees_only_rows_of_assigned_course(client):
    login(client, "prof_srs", "profpw")

    response = client.get("/grades/1001")      # Alice has SRS and SSD rows

    assert response.status_code == 200
    assert pairs(response) == [(1001, "SRS", 14)]     # SSD row must be filtered out


def test_professor_denied_when_student_has_no_row_in_assigned_course(client):
    # state change on purpose: restore_grades (autouse) undoes it after the test
    api.GRADES.append({"student_id": 1003, "course_id": "SSD", "grade": 12})
    login(client, "prof_srs", "profpw")

    response = client.get("/grades/1003")

    assert response.status_code == 403
    assert "12" not in response.get_data(as_text=True)


def test_professor_denied_for_unknown_student(client):
    login(client, "prof_srs", "profpw")

    assert client.get("/grades/9999").status_code == 403


def test_administrator_can_read_any_students_grades(client):
    login(client, "admin1", "adminpw")

    alice = client.get("/grades/1001")
    bob = client.get("/grades/1002")

    assert alice.status_code == 200 and bob.status_code == 200
    assert pairs(alice) == [(1001, "SRS", 14), (1001, "SSD", 16)]
    assert pairs(bob) == [(1002, "SRS", 15)]


# ---- R5 / R7: malformed identifiers ---------------------------------------

@pytest.mark.parametrize("bad_id", ["abc", "0", "-5", "1.5"])
@pytest.mark.parametrize("user,pw", [("alice", "alicepw"), ("admin1", "adminpw")])
def test_invalid_student_id_gets_client_error_without_leaking_details(client, user, pw, bad_id):
    login(client, user, pw)

    response = client.get(f"/grades/{bad_id}")

    assert 400 <= response.status_code < 500
    body = response.get_data(as_text=True)
    assert "ValueError" not in body and "Traceback" not in body and "invalid literal" not in body


# ---- session isolation between users --------------------------------------

def test_second_user_session_does_not_inherit_first_users_access():
    """Two independent clients: bob must not get alice's rights."""
    alice, bob = api.app.test_client(), api.app.test_client()
    login(alice, "alice", "alicepw")
    login(bob, "bob", "bobpw")

    assert alice.get("/grades/1001").status_code == 200
    assert bob.get("/grades/1001").status_code == 403
    assert bob.get("/grades/1002").status_code == 200
```

## Fixtures: `tests_security/conftest.py` (relevant part)

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
```
