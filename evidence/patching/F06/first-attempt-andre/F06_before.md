andremelo@din-wdei135 cybersecurity_lab_devsecops % docker run --rm -v "$PWD":/app -w /app python:3.10 \
  sh -c "pip install -q -r requirements.txt && python -m pytest -v tests_security"
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv

[notice] A new release of pip is available: 23.0.1 -> 26.3
[notice] To update, run: pip install --upgrade pip
============================= test session starts ==============================
platform linux -- Python 3.10.22, pytest-9.2.0, pluggy-1.7.0 -- /usr/local/bin/python
cachedir: .pytest_cache
rootdir: /app
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
materials = PosixPath('/tmp/pytest-of-root/pytest-0/test_relative_traversal_is_den0')
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
root = PosixPath('/tmp/pytest-of-root/pytest-0/test_relative_traversal_is_den0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
___________ test_relative_traversal_is_denied[sub/../../secret.txt] ____________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-root/pytest-0/test_relative_traversal_is_den1')
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
root = PosixPath('/tmp/pytest-of-root/pytest-0/test_relative_traversal_is_den1')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
_______ test_relative_traversal_is_denied[../materials_evil/secret.txt] ________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-root/pytest-0/test_relative_traversal_is_den2')
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
root = PosixPath('/tmp/pytest-of-root/pytest-0/test_relative_traversal_is_den2')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
_________________________ test_absolute_path_is_denied _________________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-root/pytest-0/test_absolute_path_is_denied0')

    def test_absolute_path_is_denied(client, materials):
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, str(materials / "secret.txt")), materials)

tests_security/test_file_access.py:54: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

resp = <WrapperTestResponse 18 bytes [200 OK]>
root = PosixPath('/tmp/pytest-of-root/pytest-0/test_absolute_path_is_denied0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
________________________ test_symlink_escape_is_denied _________________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-root/pytest-0/test_symlink_escape_is_denied0')

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
root = PosixPath('/tmp/pytest-of-root/pytest-0/test_symlink_escape_is_denied0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 200
E       assert 200 in (400, 403, 404)
E        +  where 200 = <WrapperTestResponse 18 bytes [200 OK]>.status_code

tests_security/test_file_access.py:21: AssertionError
________________ test_missing_file_does_not_leak_internal_path _________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-root/pytest-0/test_missing_file_does_not_lea0')

    def test_missing_file_does_not_leak_internal_path(client, materials):
        login(client, "alice", "alicepw")
>       assert_denied(get_file(client, "nao_existe.txt"), materials)

tests_security/test_file_access.py:69: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

resp = <WrapperTestResponse 164 bytes [500 INTERNAL SERVER ERROR]>
root = PosixPath('/tmp/pytest-of-root/pytest-0/test_missing_file_does_not_lea0')

    def assert_denied(resp, root):
        body = resp.get_data(as_text=True)
>       assert resp.status_code in (400, 403, 404), f"got {resp.status_code}"
E       AssertionError: got 500
E       assert 500 in (400, 403, 404)
E        +  where 500 = <WrapperTestResponse 164 bytes [500 INTERNAL SERVER ERROR]>.status_code

tests_security/test_file_access.py:21: AssertionError
__________________ test_unauthenticated_download_returns_401 ___________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
materials = PosixPath('/tmp/pytest-of-root/pytest-0/test_unauthenticated_download_0')

    def test_unauthenticated_download_returns_401(client, materials):
>       assert get_file(client, "public.txt").status_code == 401
E       AssertionError: assert 200 == 401
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
E        +    where <WrapperTestResponse streamed [200 OK]> = get_file(<FlaskClient <Flask 'baseline_secure_coding_api'>>, 'public.txt')

tests_security/test_file_access.py:74: AssertionError
=========================== short test summary info ============================
FAILED tests_security/test_file_access.py::test_relative_traversal_is_denied[../secret.txt]
FAILED tests_security/test_file_access.py::test_relative_traversal_is_denied[sub/../../secret.txt]
FAILED tests_security/test_file_access.py::test_relative_traversal_is_denied[../materials_evil/secret.txt]
FAILED tests_security/test_file_access.py::test_absolute_path_is_denied - Ass...
FAILED tests_security/test_file_access.py::test_symlink_escape_is_denied - As...
FAILED tests_security/test_file_access.py::test_missing_file_does_not_leak_internal_path
FAILED tests_security/test_file_access.py::test_unauthenticated_download_returns_401
========================= 7 failed, 2 passed in 0.14s ==========================

What's next:
    Debug this container error with Gordon → docker ai 




## CI
https://github.com/andremelo5/cybersecurity_lab_devsecops/actions/runs/43208681607

test, sast --> passaram
security-regression --> falhou como era suposto
build --> saltou porque o security-regression nao falhou


Detalhes:
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





### 

Requisito do enunciado	Cobertura no F06
Operação legítima que continua a funcionar	test_authenticated_user_can_download_material e ..._nested_material
Operação maliciosa que tem de falhar	../secret.txt, caminho absoluto, e 401 sem sessão
Variação que desafia um patch incompleto	sub/../../secret.txt (traversal a partir de subpasta), ../materials_evil/secret.txt (quebra startswith), symlink (quebra verificações só sobre a string), ficheiro inexistente (vazamento de caminho via R7)
Rejeição não altera dados guardados	Não aplicável

O último ponto não se aplica porque /files é só de leitura e não altera nada. O enunciado diz “where applicable”. O equivalente aqui é verificar que o conteúdo de fora nunca é divulgado, e isso está no assert_denied (SECRET not in body). Se quiseres, justifica isto numa linha no F06-before.md, para ficar claro que não é uma omissão.

Cada teste de ataque cobre uma coisa distinta, o que cumpre a regra de que os casos extra não podem repetir o exemplo com valores diferentes.

Há duas lacunas pequenas que podes fechar, se quiseres reforçar:

Pedido a um diretório (path=sub ou path=): um patch que só verifica a contenção, mas não que o alvo é um ficheiro, pode ainda devolver 500. É um bom teste de variação.
Variante codificada (..%2fsecret.txt): o query_string do test client já codifica, por isso na prática repete o traversal simples. Não vale a pena acrescentar.

Para o F03 (get_grades), os testes ainda não existem. Aí o quarto ponto também não se aplica (leitura), mas o equivalente é verificar que a resposta do professor não contém a linha SSD. Só o F02/F04 de atualização de notas exigiria o “dados inalterados após rejeição”.
