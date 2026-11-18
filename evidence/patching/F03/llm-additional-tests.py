"""Additional F03 regression tests (grade/profile read path)."""
import pytest

import baseline_secure_coding_api as api


def login(client, username, password):
    r = client.post("/login", data={"username": username, "password": password},
                    follow_redirects=True)
    assert r.status_code == 200


# Unicode digits, huge/whitespace forms, and other int()-accepted spellings.
@pytest.mark.parametrize("alias", ["١٠٠٢", "1002%0A", "%091002",
                                   "1002.0", "0x3EA", "1e3", "", "%2B1002"])
def test_noncanonical_ids_rejected(client, alias):
    login(client, "alice", "alicepw")
    r = client.get(f"/grades/{alias}")
    assert r.status_code in (400, 403, 404)
    assert "grade" not in r.get_data(as_text=True)


def test_forged_role_in_session_cookie_is_ignored(client):
    """Role/courses come from the server-side user, not the cookie."""
    login(client, "alice", "alicepw")
    with client.session_transaction() as s:
        s["role"] = "admin"
        s["courses"] = ["SRS", "SSD"]
    assert client.get("/grades/1002").status_code == 403


def test_session_for_unknown_user_is_unauthenticated(client):
    with client.session_transaction() as s:
        s["user"] = "ghost"
        s["role"] = "admin"
    assert client.get("/grades/1001").status_code == 401


def test_professor_course_change_takes_effect_without_relogin(client, monkeypatch):
    login(client, "prof_srs", "profpw")
    monkeypatch.setattr(api.USERS["prof_srs"], "courses", ["SSD"])
    r = client.get("/grades/1002")          # Bob has only SRS
    assert r.status_code == 403


def test_error_bodies_are_identical_for_unknown_and_foreign_student(client):
    login(client, "alice", "alicepw")
    a = client.get("/grades/1002")
    b = client.get("/grades/9999")
    assert (a.status_code, a.get_data()) == (b.status_code, b.get_data())


def test_rows_returned_unchanged_shape(client):
    login(client, "alice", "alicepw")
    rows = client.get("/grades/1001").get_json()
    assert all(set(r) == {"student_id", "course_id", "grade"} for r in rows)


# ---- same control on the profile read path --------------------------------

def test_profile_requires_authentication(client):
    assert client.get("/students/1001/profile").status_code == 401


def test_student_reads_only_own_profile(client):
    login(client, "alice", "alicepw")
    assert client.get("/students/1001/profile").status_code == 200
    r = client.get("/students/1002/profile")
    assert r.status_code == 403 and "bob" not in r.get_data(as_text=True).lower()
    assert client.get("/students/01002/profile").status_code == 400


def test_professor_cannot_read_profiles(client):
    login(client, "prof_srs", "profpw")
    assert client.get("/students/1001/profile").status_code == 403


def test_admin_reads_profiles(client):
    login(client, "admin1", "adminpw")
    assert client.get("/students/1002/profile").get_json()["name"] == "Bob"
    assert client.get("/students/9999/profile").status_code == 404
    assert client.get("/students/abc/profile").status_code == 400