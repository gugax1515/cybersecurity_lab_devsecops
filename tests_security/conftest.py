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