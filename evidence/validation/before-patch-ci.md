# Security tests before patching (CI evidence)

- Run: https://github.com/gugax1515/cybersecurity_lab_devsecops/actions/runs/43213835501
- Job: `security-regression` (`python -m pytest -v tests_security`), Python 3.10.22, pytest 9.2.0
- Application: unmodified baseline (no patch applied)
- Result: **28 failed, 5 passed** (33 tests). `build` is skipped, as expected.

## Passing tests (permitted operations)

- `test_file_access.py::test_authenticated_user_can_download_material`
- `test_file_access.py::test_authenticated_user_can_download_nested_material`
- `test_grade_authorization.py::test_assigned_professor_can_update_grade` (supplied example)
- `test_grades_read_authorization.py::test_student_can_read_own_grades`
- `test_grades_read_authorization.py::test_administrator_can_read_any_students_grades`

## F06 - path traversal in `GET /files` (7 failed, 2 passed)

| Test | Failing assertion | Violated requirement |
|---|---|---|
| `test_relative_traversal_is_denied[../secret.txt]` | `assert 200 in (400, 403, 404)` | R6 |
| `test_relative_traversal_is_denied[sub/../../secret.txt]` | `assert 200 in (400, 403, 404)` | R6 |
| `test_relative_traversal_is_denied[../materials_evil/secret.txt]` | `assert 200 in (400, 403, 404)` | R6 |
| `test_absolute_path_is_denied` | `assert 200 in (400, 403, 404)` | R6 |
| `test_symlink_escape_is_denied` | `assert 200 in (400, 403, 404)` | R6 |
| `test_missing_file_does_not_leak_internal_path` | `assert 500 in (400, 403, 404)` | R7 |
| `test_unauthenticated_download_returns_401` | `assert 200 == 401` | R1 |

## F03 - authorization on `GET /grades/<student_id>` (21 failed, 2 passed)

| Test | Failing assertion | Violated requirement |
|---|---|---|
| `test_unauthenticated_request_is_rejected_without_data` | `assert 200 == 401` | R1 |
| `test_request_after_logout_is_rejected` | `assert 200 == 401` | R1 |
| `test_student_cannot_read_another_students_grades` | `assert 200 == 403` | R2 |
| `test_student_cannot_bypass_check_with_id_aliases[01002, +1002, 1_002, %201002, 1002%20]` (5 cases) | `assert 200 in (400, 403)` | R2, R5 |
| `test_student_denied_for_unknown_student_id_without_existence_oracle` | `assert 200 == 403` | R4 |
| `test_professor_sees_only_rows_of_assigned_course` | extra row `(1001, 'SSD', 16)` returned | R3, R4 |
| `test_professor_denied_when_student_has_no_row_in_assigned_course` | `assert 200 == 403` | R3, R4 |
| `test_professor_denied_for_unknown_student` | `assert 200 == 403` | R4 |
| `test_invalid_student_id_gets_client_error_without_leaking_details` (8 cases) | `abc` and `1.5`: `500 < 500`; `0` and `-5`: `400 <= 200` | R5, R7 |
| `test_second_user_session_does_not_inherit_first_users_access` | `assert 200 == 403` | R2 |

All failures are assertion failures on security requirements; there are no import errors, missing fixtures or skipped tests.
