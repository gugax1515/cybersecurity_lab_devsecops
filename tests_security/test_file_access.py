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