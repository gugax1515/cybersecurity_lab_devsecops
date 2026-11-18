import pytest
from tests_security.test_file_access import login, get_file, assert_denied, PUBLIC


@pytest.mark.parametrize("attack", [
    "..", "sub/..", "", "sub",                 # base dir / directories
    "..%2fsecret.txt",                         # literal %2f after decoding once
    "public.txt\x00.png",                      # embedded NUL
    "sub/../../materials_evil/secret.txt",
    "./../secret.txt",
])
def test_odd_paths_are_denied(client, materials, attack):
    login(client, "alice", "alicepw")
    assert_denied(get_file(client, attack), materials)


def test_symlinked_directory_escape_is_denied(client, materials):
    link = materials / "materials" / "evil_dir"
    try:
        link.symlink_to(materials / "materials_evil", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    login(client, "alice", "alicepw")
    assert_denied(get_file(client, "evil_dir/secret.txt"), materials)


def test_symlink_loop_is_denied(client, materials):
    a = materials / "materials" / "loop_a"
    b = materials / "materials" / "loop_b"
    try:
        a.symlink_to(b); b.symlink_to(a)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    login(client, "alice", "alicepw")
    assert_denied(get_file(client, "loop_a"), materials)


def test_internal_symlink_is_still_allowed(client, materials):
    link = materials / "materials" / "alias.txt"
    try:
        link.symlink_to(materials / "materials" / "public.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    login(client, "alice", "alicepw")
    r = get_file(client, "alias.txt")
    assert r.status_code == 200 and r.get_data(as_text=True) == PUBLIC


def test_dotdot_that_stays_inside_is_allowed(client, materials):
    login(client, "alice", "alicepw")
    r = get_file(client, "sub/../public.txt")
    assert r.status_code == 200 and r.get_data(as_text=True) == PUBLIC


def test_unauthenticated_traversal_returns_401_without_content(client, materials):
    r = get_file(client, "../secret.txt")
    assert r.status_code == 401
    assert "TOP-SECRET" not in r.get_data(as_text=True)


def test_logout_revokes_download(client, materials):
    login(client, "alice", "alicepw")
    client.post("/logout")
    assert get_file(client, "public.txt").status_code == 401


def test_unknown_route_is_404_not_500(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404
    assert "Traceback" not in r.get_data(as_text=True)