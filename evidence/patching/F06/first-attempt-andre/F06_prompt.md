We are now repairing a confirmed vulnerability in the supplied application.

Confirmed finding:
Path traversal / arbitrary file read in GET /files (function download_file in baseline_secure_coding_api.py). The user-controlled query parameter "path" is joined to MATERIALS_DIR with pathlib and passed to flask.send_file() with no containment check. "../" segments and absolute paths (pathlib discards the base when the right operand is absolute) resolve outside the materials directory,
and symlinks inside it are followed. The endpoint also requires no
authentication, and a missing file raises an exception that the global error handler returns as a 500 containing the absolute server path.

Reproduction (from my security tests, run before patching):
- ../secret.txt, sub/../../secret.txt, ../materials_evil/secret.txt, an absolute path, and a symlink inside materials/ pointing outside all returned 200 OK with the contents of a file outside the materials directory.
- A nonexistent file returned 500 with internal detail.
- A request without a session returned 200 instead of 401.

Required behavior:
- R1: Material downloads require an authenticated user (401 otherwise).
- R6: Authenticated users may download teaching materials within the materials directory. Requests must not read files outside that directory.
- R7: Invalid requests must return appropriate client errors (4xx) without exposing internal paths, tracebacks, or implementation exception details.
- Legitimate use: an authenticated user can still download public.txt and sub/nested.txt from inside the materials directory.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner rules to hide the issue. Identify all affected paths that need the samecontrol.
Return a unified diff, explain the control being implemented, and identify remaining assumptions or limitations. Suggest additional regression tests.

Relevant source:
@app.get("/files")
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


Failing test output from CI:
    Run python -m pytest -v tests_security
============================= test session starts ==============================
platform linux -- Python 3.10.22, pytest-9.2.0, pluggy-1.7.0 -- /opt/hostedtoolcache/Python/3.10.22/x64/bin/python
cachedir: .pytest_cache
rootdir: /home/runner/work/cybersecurity_lab_devsecops/cybersecurity_lab_devsecops
collecting ... collected 9 items

tests_security/test_file_access.py::test_authenticated_user_can_download_material PASSED [ 11%]
tests_security/test_file_access.py::test_authenticated_user_can_download_nested_material PASSED [ 22%]
tests_security/test_file_access.py::test_relative_traversal_is_denied[../secret.txt] FAILED [ 33%]
tests_security/test_file_access.py::test_relative_traversal_is_denied[sub/../../secret.txt] FAILED [ 44%]
tests_security/test_file_access.py::test_relative_traversal_is_denied[../materials_evil/secret.txt] FAILED [ 55%]
tests_security/test_file_access.py::test_absolute_path_is_denied FAILED  [ 66%]
tests_security/test_file_access.py::test_symlink_escape_is_denied FAILED [ 77%]
tests_security/test_file_access.py::test_missing_file_does_not_leak_internal_path FAILED [ 88%]
tests_security/test_file_access.py::test_unauthenticated_download_returns_401 FAILED [100%]

=================================== FAILURES ===================================
_______________ test_relative_traversal_is_denied[../secret.txt] _______________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_den0')
attack = '../secret.txt'

    @pytest.mark.parametrize("attack", [
        "../secret.txt",                  # traversal
        "sub/../../secret.txt",           # traversal subpasta
        "../materials_evil/secret.txt",
    ])
    def test_relative_traversal_is_denied(client, materials, attack):
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, attack), materials)

tests_security/test_file_access.py:49: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

resp = <WrapperTestResponse 18 bytes [200 OK]>
root = PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_den0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
___________ test_relative_traversal_is_denied[sub/../../secret.txt] ____________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_den1')
attack = 'sub/../../secret.txt'

    @pytest.mark.parametrize("attack", [
        "../secret.txt",                  # traversal
        "sub/../../secret.txt",           # traversal subpasta
        "../materials_evil/secret.txt",
    ])
    def test_relative_traversal_is_denied(client, materials, attack):
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, attack), materials)

tests_security/test_file_access.py:49: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

resp = <WrapperTestResponse 18 bytes [200 OK]>
root = PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_den1')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
_______ test_relative_traversal_is_denied[../materials_evil/secret.txt] ________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_den2')
attack = '../materials_evil/secret.txt'

    @pytest.mark.parametrize("attack", [
        "../secret.txt",                  # traversal
        "sub/../../secret.txt",           # traversal subpasta
        "../materials_evil/secret.txt",
    ])
    def test_relative_traversal_is_denied(client, materials, attack):
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, attack), materials)

tests_security/test_file_access.py:49: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

resp = <WrapperTestResponse 18 bytes [200 OK]>
root = PosixPath('/tmp/pytest-of-runner/pytest-0/test_relative_traversal_is_den2')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
_________________________ test_absolute_path_is_denied _________________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-runner/pytest-0/test_absolute_path_is_denied0')

    def test_absolute_path_is_denied(client, materials):
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, str(materials / "secret.txt")), materials)

tests_security/test_file_access.py:54: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

resp = <WrapperTestResponse 18 bytes [200 OK]>
root = PosixPath('/tmp/pytest-of-runner/pytest-0/test_absolute_path_is_denied0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
________________________ test_symlink_escape_is_denied _________________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-runner/pytest-0/test_symlink_escape_is_denied0')

    def test_symlink_escape_is_denied(client, materials):
        link = materials / "materials" / "link.txt"
        try:
            link.symlink_to(materials / "secret.txt")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks não suportados neste ambiente")
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, "link.txt"), materials)

tests_security/test_file_access.py:64: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

resp = <WrapperTestResponse 18 bytes [200 OK]>
root = PosixPath('/tmp/pytest-of-runner/pytest-0/test_symlink_escape_is_denied0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
________________ test_missing_file_does_not_leak_internal_path _________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-runner/pytest-0/test_missing_file_does_not_lea0')

    def test_missing_file_does_not_leak_internal_path(client, materials):
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, "nao_existe.txt"), materials)

tests_security/test_file_access.py:69: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

resp = <WrapperTestResponse 166 bytes [500 INTERNAL SERVER ERROR]>
root = PosixPath('/tmp/pytest-of-runner/pytest-0/test_missing_file_does_not_lea0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 500
E       assert 500 in (400, 403, 404)
E        +  where 500 = <WrapperTestResponse 166 bytes [500 INTERNAL SERVER ERROR]>.status_code

tests_security/test_file_access.py:21: AssertionError
__________________ test_unauthenticated_download_returns_401 ___________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-runner/pytest-0/test_unauthenticated_download_0')

    def test_unauthenticated_download_returns_401(client, materials):
>       assert get_file(client, "public.txt").status_code == 401
E       AssertionError: assert 200 == 401
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
E        +    where <WrapperTestResponse streamed [200 OK]> = get_file(<FlaskClient <Flask 'baseline_secure_coding_api'>>, 'public.txt')

tests_security/test_file_access.py:74: AssertionError
=========================== short test summary info ============================
FAILED tests_security/test_file_access.py::test_relative_traversal_is_denied[../secret.txt] - AssertionError: got 200
assert 200 in (400, 403, 404)
 +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_relative_traversal_is_denied[sub/../../secret.txt] - AssertionError: got 200
assert 200 in (400, 403, 404)
 +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_relative_traversal_is_denied[../materials_evil/secret.txt] - AssertionError: got 200
assert 200 in (400, 403, 404)
 +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_absolute_path_is_denied - AssertionError: got 200
assert 200 in (400, 403, 404)
 +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_symlink_escape_is_denied - AssertionError: got 200
assert 200 in (400, 403, 404)
 +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code
FAILED tests_security/test_file_access.py::test_missing_file_does_not_leak_internal_path - AssertionError: got 500
assert 500 in (400, 403, 404)
 +  where 500 = <WrapperTestResponse 166 bytes [500 INTERNAL SERVER ERROR]>.status_code
FAILED tests_security/test_file_access.py::test_unauthenticated_download_returns_401 - AssertionError: assert 200 == 401
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
 +    where <WrapperTestResponse streamed [200 OK]> = get_file(<FlaskClient <Flask 'baseline_secure_coding_api'>>, 'public.txt')
========================= 7 failed, 2 passed in 0.08s ==========================
Error: Process completed with exit code 1.



Security tests:
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