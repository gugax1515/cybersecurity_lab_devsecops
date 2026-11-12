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
