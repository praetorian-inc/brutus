# Security Architecture Assessment: `brutus enum apollo` + `brutus enum lusha`

**Author:** security-lead
**Date:** 2026-06-25
**Status:** Architecture review — pre-implementation security gate (Phase 7)
**Feature:** Apollo.io + Lusha paid-HUMINT-API contact enumeration subcommands for the Brutus Go CLI
**Framing:** Brutus is an authorized offensive-security / OSINT tool used in pentest engagements. The controls below exist to prevent credential leakage, terminal injection, runaway spend, and accidental ToS violations — **not** to block the feature. Every control is scoped to a short-lived, single-operator CLI. Anything heavier (zeroing, audit infra, DI) is explicitly rejected as YAGNI.

---

## 0. Evidence Base (verified by reading source this session — not assumed)

| Claim | Verified location | Note |
| --- | --- | --- |
| `enum.ReadResponseBody(resp, 0)` caps body at 1 MB (P0-3 primitive) | `pkg/enum/httpclient.go:60-65`; default `maxResponseBody = 1<<20` at `:28` | Reuse as-is for **every** call. |
| `NewEnumHTTPClient` suppresses redirects + sets UA | `pkg/enum/httpclient.go:48-56` (`CheckRedirect → http.ErrUseLastResponse`) | Reuse; never build a bare `http.Client`. |
| `sanitizeTerminal()` strips C0/C1 + full ANSI/VT100 (P0-4 primitive) | `cmd/brutus/cmd_enum_output.go:306-369` | Same `package main` — call directly, no import. (The older zoominfo doc cites `:198`; current worktree line is `:306`.) |
| `truncate()` rune-safe truncation | `cmd/brutus/cmd_enum_output.go:372-381+` | Pair with `sanitizeTerminal` on every human field. |
| Key-free credential resolution (flag → env → key-free error) | `resolveHunterAPIKey` `cmd/brutus/cmd_enum_hunter.go:117-125` | Mirror exactly per service. |
| Key-free error classification | `classifyHunterError` `cmd/brutus/cmd_enum_hunter.go:128-139` | Mirror; map sentinels to static text. |
| Verbose logs counts/status only — never key/URL | `cmd/brutus/cmd_enum_hunter.go:103-105` | `logVerbose(flagVerbose, "...counts...")`. |
| The no-key-leak unit-test assertion already in use | `cmd/brutus/cmd_enum_hunter_test.go:109-110` (`assert.NotContains(t, result.Error(), "api_key")`) | This is the canonical negative test to extend. |
| Hunter puts its key in the **query string** (API contract) | `pkg/enum/hunter/hunter.go:171-179` | **Apollo/Lusha do NOT** — they use headers, which is strictly safer. See §1 note. |
| ZoomInfo precedent for free-search / paid-enrich gating + ToS notice | `.worktrees/zoominfo-enum/.feature-development/security-assessment.md` (P0-6, P0-10) | Apollo `--reveal` mirrors ZoomInfo `--enrich`. |

**The codebase operates a labeled control taxonomy (P0-1, P0-3, P0-4).** This assessment reuses that numbering and extends it for the Apollo/Lusha-specific threats (header-based key leak vector, free/paid split, always-paid Lusha enrich, DNC flag, ToS).

---

## 1. Threat Model

### Trust boundaries

```
[operator shell] --flags/env--> [brutus process memory] --HTTPS hdr--> [api.apollo.io | api.lusha.com]
                                       |
                                       +--stdout (human table / JSONL)--> [terminal | -o file | pipe]
                                       +--stderr (verbose / errors / cost notice)--> [terminal | log capture]
```

Three boundaries matter: (1) **shell → process** — how the key enters (process list / shell history exposure via `--api-key`); (2) **process → vendor** — TLS transport, key in a request header, bounded response handling; (3) **process → output sinks** — attacker-or-third-party-controlled PII (names, titles, company, email, phone) crossing into a terminal or a PII file.

### STRIDE applied

| Threat | Apollo/Lusha-specific vector | Control |
| --- | --- | --- |
| **Spoofing** | Endpoint impersonating the vendor to harvest the API key | TLS verification (default; never `InsecureSkipVerify`); pin scheme `https`; no redirect following (reuse `NewEnumHTTPClient`, `httpclient.go:51`) |
| **Tampering** | MITM altering response, or a hostile/oversized body to OOM the process | TLS + bounded read `enum.ReadResponseBody` on **every** call (P0-3) |
| **Repudiation** | Out of scope — single-operator CLI, not a shared service. No audit trail (YAGNI). | Documented as accepted non-control |
| **Information Disclosure** | (a) API key leaking into errors / verbose / `httputil.DumpRequest` (header capture) / process list. (b) Personal emails + phones written to a world-readable `-o` file. (c) ANSI-laced PII fields manipulating the operator's terminal. | P0-1 (key-free logging), P0-1c (no request dumping), P0-4 (terminal sanitization), P1-PII (file perms) |
| **Denial of Service** | (a) Hostile oversized response. (b) The tool tripping vendor 429s and locking the operator's paid account. | Bounded read; surface 429 as actionable error, **no silent auto-retry** (P0-5) |
| **Elevation of Privilege** | N/A for a standalone CLI. The real "escalation" is **credit/cost escalation** — Apollo `--reveal` and Lusha enrich spend money. | P0-6 (Apollo `--reveal` opt-in), P0-7 (cost notice + bounded `--limit`) |

### Highest-value assets (ranked)
1. **The API key** (`APOLLO_API_KEY` / `LUSHA_API_KEY`) — long-lived, reusable, grants full paid API access + spends credits. Single most sensitive value.
2. **Returned PII** (personal emails, phone numbers, DNC status) — privacy liability **and** a paid resource the operator already spent credits on.
3. **Credit balance** — finite, paid; a 10k-contact reveal loop is a real-money DoS against the operator.

### Note on the header-vs-query-string key (Apollo/Lusha are safer than Hunter here)
Hunter places `api_key` in the URL query string because its API contract requires it (`hunter.go:171-179`), which is why Hunter's mitigation is "never log the full URL." **Apollo (`X-Api-Key`) and Lusha (`api_key`) send the key in a request header instead — strictly better**, because the key cannot land in proxy access logs or `Referer` headers. The leak vector shifts: the danger for header-based auth is any helper that dumps the full request (`httputil.DumpRequest`/`DumpResponse`), which captures headers. Hence **P0-1c** below explicitly forbids request dumping.

---

## 2. Required Security Controls

Legend: **P0 = must implement before merge.** **P1 = should implement; flag in review if skipped.** "Service" = `apollo` and `lusha` each get their own copy of the named symbol (`resolveApolloAPIKey`/`resolveLushaAPIKey`, etc.) — no premature shared abstraction (Rule of Three not met; KISS).

### 2.1 Credential handling (P0-1 family)

| ID | Pri | Control | Implementation (exact code locations the developer will create) |
| --- | --- | --- | --- |
| **P0-1** | P0 | **API key NEVER logged.** No key substring in any error, verbose line, or stderr notice. | `classifyApolloError` / `classifyLushaError` (new, in `cmd/brutus/cmd_enum_apollo.go` / `cmd_enum_lusha.go`) return only status-derived static text — mirror `classifyHunterError` (`cmd_enum_hunter.go:128-139`). `logVerbose` lines reference **counts/page/status only**, mirroring `cmd_enum_hunter.go:103-105`. |
| **P0-1b** | P0 | **Key stored in unexported struct field only.** | `apollo.Client` / `lusha.Client` hold `apiKey string` (lowercase, unexported), mirroring `hunter.Client` (`hunter.go:99-104`). No getters, no JSON tags on it. |
| **P0-1c** | P0 | **No full-request dumping.** Because the key rides in a header (`X-Api-Key` / `api_key`), `httputil.DumpRequest`/`DumpResponse` would capture it. | Forbid `httputil.Dump*` anywhere in `pkg/enum/apollo/` and `pkg/enum/lusha/`. The error path logs status code + endpoint name only. Set the auth header inline in the per-request builder (mirror how Hunter builds requests in `fetchPage`, `hunter.go:171-189`, but via `req.Header.Set("X-Api-Key", c.apiKey)` / `req.Header.Set("api_key", c.apiKey)` — never in the URL). |
| **P0-1d** | P0 | **`--api-key` flag help carries the process-list/history warning.** | Flag registration in each command's `init()` must use the warning string exactly as `cmd_enum_hunter.go:61-62` does. Document `APOLLO_API_KEY` / `LUSHA_API_KEY` as the preferred default in `Long:`/`Example:` text. Resolution precedence flag→env→key-free error via `resolveApolloAPIKey`/`resolveLushaAPIKey` (mirror `resolveHunterAPIKey`, `cmd_enum_hunter.go:117-125`). |
| **P1-1** | P1 | **No credential-zeroing routine.** | Go strings are immutable / GC-copyable; zeroing is theatre for a short-lived CLI. Deliberate non-control (KISS). Do not write `Zero()`. |

#### P0-1 enforcement — the mandatory negative test (each service MUST pass)
Extend the existing pattern at `cmd_enum_hunter_test.go:109-110`. For **each** service, a table-driven test feeds a sentinel API key value through both the error classifier and the verbose-logging path and asserts the key never appears:

```go
// cmd/brutus/cmd_enum_apollo_test.go  (and _lusha_test.go, mutatis mutandis)
const sentinelKey = "SECRETKEY-DO-NOT-LEAK-abc123"

func TestClassifyApolloError_NoKeyLeak(t *testing.T) {
    cases := []error{
        &apollo.APIError{StatusCode: 401, Details: sentinelKey}, // vendor echoed key into body
        &apollo.APIError{StatusCode: 429, Details: "rate limit"},
        &apollo.APIError{StatusCode: 403, Details: "forbidden"},
        &apollo.APIError{StatusCode: 422, Details: "bad params"},
        fmt.Errorf("wrapped: %w", &apollo.APIError{StatusCode: 500, Details: sentinelKey}),
    }
    for _, in := range cases {
        out := classifyApolloError(in).Error()
        assert.NotContains(t, out, sentinelKey)       // key never surfaces
        assert.NotContains(t, out, "X-Api-Key")        // header name not echoed
    }
}
```

Plus a verbose-path assertion: capture stderr while `runEnumApollo` logs at `--verbose`, and `assert.NotContains(t, stderr, sentinelKey)`. The crucial twist vs. Hunter: include the case where the **vendor echoes the key back in the error body** (`Details: sentinelKey`) — the classifier must NOT pass vendor `Details` through verbatim; it returns its own static message.

### 2.2 HTTP request / response security (P0-3, P0-5)

| ID | Pri | Control | Implementation |
| --- | --- | --- | --- |
| **P0-3** | P0 | **Bounded read on EVERY call.** | `enum.ReadResponseBody(resp, 0)` (1 MB cap, `httpclient.go:60-65`) for **every** HTTP response: Apollo `mixed_people/api_search` (search), Apollo `people/match` (each reveal), Lusha `v3/contacts/search-and-enrich`, Lusha `v3/contacts/enrich`. Never `io.ReadAll(resp.Body)` directly. Mirror `hunter.go:193`. If a legitimate search page can exceed 1 MB (Apollo `per_page` ≤100 — unlikely), pass an explicit higher cap; never uncapped. |
| **P0-3b** | P0 | **HTTPS-only + reuse the safe client.** | Build via `enum.NewEnumHTTPClient(timeout)` in each `NewClient` (mirror `hunter.go:114`). Assert base URL scheme is `https` and host is the expected vendor host so a typo/config can't downgrade to plaintext. |
| **P0-5** | P0 | **429 surfaces as an actionable error; no silent auto-retry.** A paid account can be locked by aggressive retries. | Map 429 → `ErrRateLimited` sentinel (mirror `hunter.go:35` + `APIError.Unwrap` `hunter.go:82-92`). `classifyXError` returns "rate limit exceeded — wait and retry, or lower --limit" (mirror `cmd_enum_hunter.go:132-133`). **No retry loop.** Lusha rate-limit headers (`x-rate-limit-daily`, `x-daily-requests-left`) are read for `--verbose` display **only**, never for flow control. |

### 2.3 Untrusted-data / output security (P0-4)

Apollo and Lusha return attacker-or-third-party-controlled strings: `name`, `first_name`, `last_name`, `title`/`jobTitle`, `organization`/`company`, `email`, `phone`, `seniority`, `department`. Any of these can carry ANSI/VT100 escape sequences → terminal injection (cursor manipulation, fake prompts, clipboard hijack on some terminals).

| ID | Pri | Control | Implementation |
| --- | --- | --- | --- |
| **P0-4** | P0 | **Every API-sourced string in HUMAN output passes through `sanitizeTerminal()` then `truncate()`.** | In `outputApolloHuman` / `outputLushaHuman` (new, in `cmd/brutus/cmd_enum_output.go`), wrap **every** vendor field exactly as `outputHunterHuman` does (the Hunter human formatter at `cmd_enum_output.go:385-460` wraps each field in `sanitizeTerminal(...)` then `truncate(...)`). This explicitly includes `email` and `phone` — they are vendor-controlled too. |
| **P0-4b** | P0 | **Do NOT sanitize JSONL output.** | `encoding/json` already escapes control chars into `\uXXXX` (documented at `cmd_enum_output.go:303-305`), so JSONL is safe and must stay byte-faithful for downstream tooling. `outputApolloJSONL` / `outputLushaJSONL` rely on `encoding/json` + `omitempty` only — mirror `outputHunterJSONL` (`cmd_enum_output.go:385-460`). Sanitizing JSON would corrupt legitimate data. |

#### P0-4 enforcement — mandatory test
A test feeding an ANSI-laced value through the human formatter for **each** service, mirroring `TestSanitizeTerminal` (`cmd_enum_hunter_test.go:270-329`):

```go
result := &apollo.Result{People: []apollo.Person{{
    Name:    "Eve\x1b[2J\x1b[31mPwned",
    Title:   "CEO\x1b]0;hijack\x07",
    Email:   "eve@evil\x1b[1m.com",
}}}
var buf bytes.Buffer
outputApolloHuman(&buf, result, false)
out := buf.String()
assert.NotContains(t, out, "\x1b")  // no ESC survives to the terminal
```

### 2.4 PII / compliance handling (P0-DNC, P0-ToS)

These APIs return personal emails + phone numbers; Lusha additionally returns a **Do-Not-Call (DNC)** flag per phone. Apollo personal-email reveal and Lusha contact enrichment are deliberate PII-pulling operations in an authorized engagement.

| ID | Pri | Control | Implementation |
| --- | --- | --- | --- |
| **P0-DNC** | P0 | **Surface the Lusha DNC flag — never hide or drop it.** Suppressing a DNC flag could lead an operator to contact a number they must not. | Map the per-phone `doNotCall` field into the `lusha.Phone` struct; render it in `outputLushaHuman` (e.g. a `DNC` column / `[DNC]` marker) and include it in `outputLushaJSONL` (`"do_not_call": true`, **not** `omitempty` when true — but a plain bool with `omitempty` drops `false`, which is acceptable since absence = not-flagged; document this). Field name is UNVERIFIED per discovery §3 — isolate in the struct, flag for live-key check. |
| **P1-PII** | P1 | **No local persistence beyond the user's `-o` file; restrict its perms.** | Do NOT write any cache/temp/history file. The only PII sink is the operator-chosen `-o` path via the existing `setupOutputWriter` (used by Hunter at `cmd_enum_hunter.go:80`). Confirm `setupOutputWriter` creates files `0600`; if it creates world-readable files, raise as a finding and match/raise existing behavior rather than special-casing — do not fork output handling. |
| **P0-ToS** | P0 | **One-line authorized-use / ToS note in each command's help.** Apollo and Lusha ToS restrict use to authorized, contractually-permitted purposes. | Add a single line to each `Long:` help text (mirror `enumHunterCmd.Long` structure, `cmd_enum_hunter.go:41-46`): e.g. *"You are responsible for ensuring your use complies with the provider's Terms of Service and that you have authorization to enumerate the targeted individuals/organizations."* If a vendor returns a legal-block status (HTTP 451-equivalent), define an `ErrLegalReasons` sentinel like `hunter.go:36`. |

**GDPR / CCPA context (brief, no over-engineering):** personal emails and phone numbers are personal data under GDPR (lawful-basis / data-minimization obligations sit with the operator and the engagement's legal authorization) and personal information under CCPA. The CLI's role is correctly limited to (a) not persisting beyond the user's explicit `-o` file (P1-PII), (b) surfacing DNC so the operator can honor suppression (P0-DNC), and (c) the authorized-use note (P0-ToS). Building consent-tracking, retention timers, or data-subject tooling into a pentest CLI would be scope creep (YAGNI) — those are engagement/process controls, not CLI controls. Document this boundary; do not implement it.

### 2.5 Cost / abuse controls (paid credits — P0-6, P0-7)

| ID | Pri | Control | Implementation |
| --- | --- | --- | --- |
| **P0-6** | P0 | **Apollo: paid reveal is explicit opt-in via `--reveal` (default off).** Apollo `mixed_people/api_search` is FREE and returns no email/phone; `people/match` with `reveal_personal_emails` spends credits + returns PII. The default path must spend **zero** credits. | Gate the `people/match` call behind `--reveal` (default `false`), mirroring ZoomInfo `--enrich` (zoominfo assessment P0-6). Keep search and reveal as **distinct client methods** (`apollo.Client.Search` vs `apollo.Client.Reveal`) so the free path can never accidentally call the paid one. **Lusha note:** Lusha enrichment is *always* paid (it has no free tier — that is the command's entire purpose), so Lusha needs **no** gate flag; the cost notice (P0-7) is unconditional instead. |
| **P0-7** | P0 | **Stderr cost notice before any spend.** Operator must see that credits are about to be consumed. | Before issuing paid calls — Apollo when `--reveal` is set, Lusha always — print a one-line stderr notice (suppressed under `--quiet`/`--json`, mirroring the stderr-gating at `cmd_enum_hunter.go:92-95`): e.g. *"Revealing N contacts via Apollo people/match — this consumes paid credits."* State the count N (= number to be revealed after `--limit` is applied) so the operator sees the magnitude before it happens. |
| **P0-8** | P0 | **Bounded default `--limit` to prevent a credit blowout.** Without a cap, a domain with 10k people × `--reveal` = a 10k-credit drain in one command. | `--limit` flag (default **25**, per discovery §5 recommendation) caps the number of contacts revealed/enriched. For Apollo, `--limit` bounds how many discovered `id`s are passed to `people/match`. Make the default conservative and document that raising it raises spend. (Note: Hunter's `--limit` is a *page size*, `cmd_enum_hunter.go:63`; here `--limit` is a *spend cap* — different semantics, document clearly in help text to avoid operator confusion.) |
| **P1-2** | P1 | **`--dry-run` for the paid path:** report how many contacts *would* be revealed/enriched (and thus credits spent) without spending. | Cheap, high operator value, prevents surprise drain. Recommended, not blocking. |

### 2.6 Apollo phone-via-webhook — confirmed OUT of scope, and that is the secure choice

Discovery §2 establishes Apollo delivers phone numbers **asynchronously via a `webhook_url`**, not in the `people/match` response. **Avoiding `reveal_phone_number`/`webhook_url` is both the simpler and the more secure design**, and the assessment affirms it as a deliberate security decision, not just a feature cut:

- **No inbound listener.** A CLI that registered a `webhook_url` would have to either stand up a local HTTP server (inbound attack surface on the operator's host: unauthenticated POST endpoint, port exposure, firewall implications) or rely on a third-party relay (the relay then sees the operator's harvested phone data — a new disclosure boundary).
- **No SSRF / callback surface.** Supplying a server-controlled `webhook_url` to Apollo and processing whatever Apollo (or anything spoofing it) POSTs back introduces an unauthenticated-callback / SSRF-adjacent surface with no authentication of the caller. A short-lived CLI cannot validate webhook authenticity meaningfully.
- **Decision recorded:** Apollo v1 reveals **emails only** (`reveal_personal_emails`). Phone is out of scope (YAGNI + attack-surface reduction). If phone is ever needed, it is a separate design requiring an authenticated callback channel — not an incremental flag.

---

## 3. FOLLOW / AVOID (verified patterns)

### FOLLOW
- **Credential resolution:** copy `resolveHunterAPIKey` (`cmd_enum_hunter.go:117-125`) → `resolveApolloAPIKey` / `resolveLushaAPIKey`. Flag → env → key-free error.
- **HTTP client:** `enum.NewEnumHTTPClient(timeout)` (`httpclient.go:48`) inside each `NewClient`. Never a bare `http.Client`.
- **Bounded read:** `enum.ReadResponseBody(resp, 0)` (`httpclient.go:60`) on every response.
- **Typed sentinels + `Unwrap()`:** `apollo.APIError`/`lusha.APIError` with `ErrUnauthorized`/`ErrRateLimited`/`ErrForbidden`/`ErrBadRequest` (+ `ErrNoCredits` for Lusha 402/quota per discovery §3) — mirror `hunter.go:32-92`. Classify in the command layer (`classifyXError`).
- **Terminal sanitization in human output:** wrap every field in `sanitizeTerminal()` then `truncate()` (`outputHunterHuman` pattern, `cmd_enum_output.go:385-460`).
- **Raw JSONL:** rely on `encoding/json` + `omitempty`; no manual sanitization (`outputHunterJSONL`).
- **Key-free verbose logging:** `logVerbose(flagVerbose, "...counts...")` (`cmd_enum_hunter.go:104`).
- **Stderr gating:** `if !flagQuiet && !flagJSON { ... stderr ... }` (`cmd_enum_hunter.go:92-95`) — applies to the cost notice too.
- **Signal-aware context:** `signal.NotifyContext` (`cmd_enum_hunter.go:89`) — ctrl-C must cleanly abort a multi-page / multi-reveal run between requests.

### AVOID
- **Do NOT** put the API key in a URL query string — Apollo/Lusha use headers (`X-Api-Key` / `api_key`); keep it there so it can't reach proxy logs.
- **Do NOT** use `httputil.DumpRequest`/`DumpResponse` — captures the auth header (P0-1c).
- **Do NOT** pass the vendor's error `Details` body straight into a user-facing error — the vendor may echo the key; return your own static message (P0-1).
- **Do NOT** `io.ReadAll(resp.Body)` directly — always the bounded reader (P0-3).
- **Do NOT** auto-retry 429 — surface it; protect the operator's paid account (P0-5).
- **Do NOT** spend credits on any default path; Apollo reveal is opt-in (P0-6), Lusha enrich announces cost (P0-7).
- **Do NOT** register a `webhook_url` / open an inbound listener for Apollo phone (§2.6).
- **Do NOT** hide the Lusha DNC flag (P0-DNC).
- **Do NOT** extract a premature "HUMINT provider" interface (Rule of Three not met; KISS) or add credential-zeroing (P1-1).
- **Do NOT** persist PII anywhere except the operator's `-o` file (P1-PII).

---

## 4. Required tests (enforced by tester/reviewer)

| Test | Asserts | Per |
| --- | --- | --- |
| `TestClassifyXError_NoKeyLeak` (incl. vendor-echoes-key-in-body case) | key + header name never appear in any classified error (extends `cmd_enum_hunter_test.go:109-110`) | apollo, lusha |
| Verbose-path no-leak | sentinel key absent from captured stderr at `--verbose` | apollo, lusha |
| `TestOutputXHuman` ANSI injection | no `\x1b` survives to human output (extends `TestSanitizeTerminal`) | apollo, lusha |
| `TestOutputXJSONL` | valid JSON, `omitempty` drops blanks, byte-faithful (no sanitization) | apollo, lusha |
| Apollo default-path-no-spend | default (no `--reveal`) never calls `people/match` (httptest server records hits) | apollo |
| Cost-notice emitted | stderr contains the credit notice before paid call; suppressed under `--quiet`/`--json` | apollo (on `--reveal`), lusha (always) |
| `--limit` spend cap | with N>limit discovered, exactly `limit` reveal/enrich calls are made | apollo, lusha |
| DNC surfaced | `doNotCall` value appears in both human and JSONL output | lusha |

`go test ./...` must pass; `go test -race` only if any concurrency is introduced (default design is sequential, like Hunter — no race surface).

---

## 5. Verdict

**APPROVED to proceed to implementation, conditioned on all P0 controls landing in the plan and the §4 tests enforced.** The Hunter.io integration supplies verified, secure primitives that cover P0-1 (key-free logging), P0-3 (bounded read), and P0-4 (terminal sanitization) directly via reuse. Apollo/Lusha are **lower** net-new risk than ZoomInfo (single API key each, header-based auth, no PKI/JWT lifecycle). The Apollo/Lusha-specific P0 deltas the Hunter template does not cover are: **P0-1c** (no request dumping — header leak vector), **P0-5** (429 no-auto-retry to protect a paid account), **P0-6/P0-7/P0-8** (Apollo reveal opt-in + unconditional Lusha cost notice + bounded `--limit` spend cap), **P0-DNC** (surface Lusha DNC), and **P0-ToS** (authorized-use note). Apollo phone-via-webhook is correctly out of scope and its avoidance is affirmed as the secure choice (no inbound/SSRF surface, §2.6).

**Handoff:** `backend-developer` — implement two independent subcommands following the Hunter.io template (`pkg/enum/hunter/hunter.go`, `cmd/brutus/cmd_enum_hunter.go`, `cmd/brutus/cmd_enum_output.go`) with the §2 controls. `sanitizeTerminal`/`truncate` live in `cmd_enum_output.go:306-381`; reuse `enum.ReadResponseBody` and `enum.NewEnumHTTPClient` from `pkg/enum/httpclient.go`. Field names in Lusha v3 responses (incl. DNC) are unverified — isolate in structs and confirm against a live key.

---

## Metadata

```json
{
  "agent": "security-lead",
  "output_type": "security-architecture",
  "timestamp": "2026-06-25T00:00:00Z",
  "feature_directory": "/Users/engineer/github/brutus/.worktrees/apollo-lusha-enum/.feature-development",
  "skills_invoked": [
    "using-skills",
    "focusing-on-the-goal",
    "enforcing-evidence-based-analysis",
    "gateway-security",
    "persisting-agent-outputs",
    "verifying-before-completion",
    "using-todowrite"
  ],
  "library_skills_read": [
    "/Users/engineer/.claude/plugins/cache/praetorian-ai-marketplace/engineering/1.38.17/skill-library/security/secrets-management/SKILL.md",
    "/Users/engineer/.claude/plugins/cache/praetorian-ai-marketplace/engineering/1.38.17/skill-library/security/reviewing-backend-security/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/enum/httpclient.go:28-65",
    "pkg/enum/hunter/hunter.go:32-213",
    "cmd/brutus/cmd_enum_hunter.go:30-139",
    "cmd/brutus/cmd_enum_output.go:299-381",
    "cmd/brutus/cmd_enum_hunter_test.go:33-352",
    ".worktrees/apollo-lusha-enum/.feature-development/discovery.md:1-132",
    ".worktrees/zoominfo-enum/.feature-development/security-assessment.md:1-219"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Implement apollo + lusha enum subcommands following Hunter.io template with all P0 controls (P0-1 key-free logging incl. P0-1c no httputil.Dump request dumping since key is in a header; P0-3 bounded read on every call; P0-4 terminal sanitization on every human field incl. email/phone; P0-5 429 no-auto-retry; P0-6 Apollo --reveal opt-in; P0-7 stderr cost notice before spend, unconditional for Lusha; P0-8 bounded --limit default 25 spend cap; P0-DNC surface Lusha DNC flag; P0-ToS authorized-use note in Long help). Apollo phone-via-webhook OUT of scope (no inbound/SSRF surface). sanitizeTerminal/truncate at cmd_enum_output.go:306-381. Required negative test: sentinel key never appears in classifier output or verbose stderr, including the vendor-echoes-key-in-body case."
  }
}
```
