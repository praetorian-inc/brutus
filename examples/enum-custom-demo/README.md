# enum custom demo

A self-contained demo of Brutus's `enum custom` declarative oracle, run against
an **intentionally account-enumeration-vulnerable** web app.

It has three parts, all in this directory:

| File                          | What it is                                                        |
| ----------------------------- | ----------------------------------------------------------------- |
| `main.go`                     | A deliberately vulnerable HTTP server (the target).               |
| `forgot-password-oracle.yaml` | A custom oracle spec for the password-reset enumeration vector.   |
| `login-oracle.yaml`           | A second spec for the login enumeration vector.                   |

> ⚠️ **Safety note.** `main.go` is intentionally vulnerable teaching code. It
> leaks whether an account exists. It binds to localhost by default. **Do not
> deploy it.** Use it only on your own machine.

---

## The vulnerability

Account enumeration happens when an app's response *differs* between accounts
that exist and accounts that don't. An attacker who can tell the difference can
harvest a list of valid users (for phishing, password spraying, etc.) without
ever logging in.

This demo app leaks existence two ways:

**`POST /api/forgot-password`** with `{"email":"..."}`:

| Email                | Status | Body                                                                  |
| -------------------- | ------ | --------------------------------------------------------------------- |
| valid (e.g. alice)   | `200`  | `{"status":"ok","message":"Password reset link sent to your email"}`  |
| invalid (e.g. nobody)| `404`  | `{"status":"error","message":"No account found for that email address"}` |

**`POST /api/login`** with `{"email":"...","password":"..."}`:

| Email                | Status | Body                                   |
| -------------------- | ------ | -------------------------------------- |
| valid (any password) | `401`  | `{"message":"Incorrect password"}`     |
| invalid              | `404`  | `{"message":"No account with that email"}` |

The four demo accounts are: `alice@demo.local`, `bob@demo.local`,
`carol@demo.local`, `admin@demo.local`.

---

## 1. Run the target

```bash
go run ./examples/enum-custom-demo
```

It listens on `:8080` by default (override with `-addr :9000` or the `PORT`
env var) and logs each request to stderr so you can watch Brutus probe it. You
should see the banner:

```
⚠ INTENTIONALLY VULNERABLE demo target — do not deploy.
Valid demo accounts: alice@demo.local, bob@demo.local, carol@demo.local, admin@demo.local
Listening on :8080 (POST /api/forgot-password, POST /api/login, GET /)
```

Leave it running in one terminal.

> If your environment pins a specific Go toolchain (see the repo `Makefile`),
> use that wrapper for `go run`/`go build`. The demo is plain `net/http` with no
> external dependencies, so any recent Go works.

## 2. Build brutus

In a second terminal:

```bash
go build -o brutus ./cmd/brutus
```

## 3. Run the oracle

```bash
./brutus enum custom \
  -f examples/enum-custom-demo/forgot-password-oracle.yaml \
  -e alice@demo.local,nobody@demo.local
```

Expected: `alice@demo.local` resolves to **exists** (the app returned 200 +
"reset link sent"), `nobody@demo.local` resolves to **absent** (404 + "No
account found"). In the target's terminal you'll see the matching request log
lines.

The login vector works the same way:

```bash
./brutus enum custom \
  -f examples/enum-custom-demo/login-oracle.yaml \
  -e alice@demo.local,nobody@demo.local
```

### Other ways to supply subjects

`enum custom` takes subjects from `-e` (inline), `-E` (a file, or `-` for
stdin), or `--generate`:

```bash
# From a file (one subject per line)
printf 'alice@demo.local\nbob@demo.local\nnobody@demo.local\n' > /tmp/subjects.txt
./brutus enum custom -f examples/enum-custom-demo/forgot-password-oracle.yaml -E /tmp/subjects.txt

# From stdin
printf 'alice@demo.local\nnobody@demo.local\n' \
  | ./brutus enum custom -f examples/enum-custom-demo/forgot-password-oracle.yaml -E -

# Generate candidate emails from embedded name lists
./brutus enum custom -f examples/enum-custom-demo/forgot-password-oracle.yaml \
  --generate --domain demo.local --format first
```

---

## How the spec works

The spec maps the app's observable behaviour to a verdict. Walking through
`forgot-password-oracle.yaml`:

```yaml
version: "1"                       # schema version (must be "1")
oracle:
  name: demo-forgot-password       # label for the oracle
  request:                         # the HTTP request sent once per subject
    method: POST
    url: "http://localhost:8080/api/forgot-password"
    headers:
      Content-Type: application/json
    body: '{"email":"{{email}}"}'  # {{email}} is substituted per subject
    body_encoding: json            # placeholders are JSON-escaped
  match:
    rules:                         # ordered; FIRST matching rule wins
      - when:                      # conditions are AND-ed
          status: 200
          body_contains: "reset link sent"
        verdict: exists            # both conditions hold -> account exists
        confidence: high
      - when:
          status: 404
          body_contains: "No account found"
        verdict: absent            # 404 + this message -> no account
        confidence: high
    default: error                 # no rule matched -> error (ambiguous)
```

### Request template + placeholders

For each subject Brutus sends the templated request. Placeholders are
substituted per subject and escaped according to `body_encoding`:

| Placeholder      | Meaning                                            |
| ---------------- | -------------------------------------------------- |
| `{{email}}`      | the full subject value                             |
| `{{username}}`   | the subject value                                  |
| `{{localpart}}`  | part before `@` (for `alice@demo.local` -> `alice`)|
| `{{domain}}`     | part after `@` (-> `demo.local`)                   |

URL placeholders are URL-escaped; body placeholders are escaped per
`body_encoding` (`json`, `form`, or `raw`). Only `http`/`https` URLs are allowed.

### Match rules → verdict

Rules are evaluated top to bottom and the **first** one whose conditions all
hold decides the verdict. Each `when` condition is optional — only the ones you
set are active, and active conditions are AND-ed:

| `when` field      | Matches when…                                        |
| ----------------- | ---------------------------------------------------- |
| `status`          | response status equals the int (or is in the list)   |
| `body_contains`   | response body contains the substring                 |
| `body_regex`      | response body matches the RE2 regex                  |
| `json_field`      | a dot-path value `equals` / is `in` a set            |
| `header`          | a response header is `present` / `equals` a value    |

A rule's `verdict` is `exists`, `absent`, or `error`. If no rule matches, the
`default` verdict applies.

**The critical coordination:** the `body_contains` substrings in the spec must
be exact substrings of what the app returns. Here, `"reset link sent"` is a
substring of `Password reset link sent to your email`, and `"No account found"`
is a substring of `No account found for that email address`. Change one without
the other and the oracle breaks — which is the whole point of the exercise: the
oracle keys off the app's distinguishable responses.

`login-oracle.yaml` follows the same shape against `/api/login`, keying off the
`401 "Incorrect password"` (exists) vs `404 "No account with that email"`
(absent) split.
