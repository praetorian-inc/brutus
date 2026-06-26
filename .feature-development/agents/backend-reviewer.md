# Backend Review: Apollo + Lusha enum integrations

**Reviewer:** backend-reviewer
**Date:** 2026-06-26
**Scope:** `pkg/enum/apollo/apollo.go`, `pkg/enum/lusha/lusha.go`, `cmd/brutus/cmd_enum_apollo.go`,
`cmd/brutus/cmd_enum_apollo_output.go`, `cmd/brutus/cmd_enum_lusha.go`,
`cmd/brutus/cmd_enum_lusha_output.go`, `cmd/brutus/cmd_enum.go` registration, plus
`pkg/enum/{apollo,lusha}/*_test.go` and `cmd/brutus/cmd_enum_{apollo,lusha}_test.go`.
**Contract:** `.feature-development/architecture.md` + `plan.md` (ORCHESTRATION DELTAS applied:
`--limit` default 100, per-service output files, orchestrator registration).

---

## Verification Results

| Command | Result |
| ------- | ------ |
| `go build ./...` | PASS (exit 0) |
| `go vet ./pkg/enum/apollo/ ./pkg/enum/lusha/ ./cmd/brutus/` | PASS (exit 0) |
| `go test ./pkg/enum/apollo/ ./pkg/enum/lusha/` | PASS (52 cases) |
| `go test -race ./pkg/enum/apollo/ ./pkg/enum/lusha/` | PASS |
| `go test ./cmd/brutus/` | **FAIL** — `TestClassifyLushaError_NoKeyLeak/wrapped_500_with_sentinel_in_Details` and `TestClassifyApolloError_NoKeyLeak/401_with_sentinel_in_Details` |
| `golangci-lint run` | NOT RUN — installed binary built with go1.25 < repo's go1.26; `go vet` used as substitute |
| help smoke (`enum apollo --help`, `enum lusha --help`) | PASS — all flags + credit warnings present |
| DRY grep `func sanitizeTerminal` / `func truncate` in `cmd/brutus/*.go` | 1 each (PASS) |
| P0-1c grep `httputil.Dump` in new packages | none (only a comment) (PASS) |
| P0-3 grep raw `io.ReadAll(resp.Body)` in new packages | none (PASS) |

`go test ./cmd/brutus/` is **RED**. Two failing subtests — one is a real production bug, one is a buggy test assertion. Details below.

---

## Findings

### P0-1 — `classifyLushaError` default branch leaks vendor `APIError.Details` (real credential-leak bug)
**Severity: P0 blocker**
**File:** `cmd/brutus/cmd_enum_lusha.go:228-230`

```go
default:
    return fmt.Errorf("lusha enrichment failed: %w", err)
```

`%w`-wrapping the underlying error embeds `(*lusha.APIError).Error()`, which formats
`Details`. `Details` is populated from the vendor response envelope in `lusha.go:197-201`,
so any non-2xx status that is NOT one of the mapped sentinels (e.g. 500/502/400/409) surfaces
the raw server body — which can echo the submitted `api_key` back to the operator's terminal /
output file. This is the exact P0-1 failure the plan's `TestClassifyLushaError_NoKeyLeak`
(security-assessment §2.1) was written to catch, and it fails:

```
"lusha enrichment failed: wrapped: lusha API error (HTTP 500): SECRETKEY-DO-NOT-LEAK-abc123"
  should not contain "SECRETKEY-DO-NOT-LEAK-abc123"
```

**Recommended fix:** mirror the already-correct Apollo classifier (`cmd_enum_apollo.go:166-171`) —
in the default branch use `errors.As` to extract `*lusha.APIError` and report only its
`StatusCode`, never `%w`-wrap:

```go
default:
    var apiErr *lusha.APIError
    if errors.As(err, &apiErr) {
        return fmt.Errorf("lusha enrichment failed (HTTP %d)", apiErr.StatusCode)
    }
    return fmt.Errorf("lusha enrichment failed")
}
```

> Note: Hunter (`cmd_enum_hunter.go:137`) has the same `%w` default and the same latent leak, but
> Hunter is out of scope for this review and its key is query-string (different threat surface).
> The Apollo classifier in this PR is the correct pattern of record; Lusha must match it.

---

### P1 — `TestClassifyApolloError_NoKeyLeak` asserts `NotContains(out, "api-key")`, contradicting the intended actionable message (buggy test)
**Severity: P1 should-fix**
**File:** `cmd/brutus/cmd_enum_apollo_test.go:121` (and the analogous Lusha assertion at `cmd_enum_lusha_test.go` only checks `"api_key"`, so it does not collide)

The Apollo 401 case fails:

```
"apollo: invalid or missing API key (check APOLLO_API_KEY / --api-key)"
  should not contain "api-key"
```

The production message at `cmd_enum_apollo.go:157` is **correct and intended** — the plan (T004)
requires an actionable message that points the user at `APOLLO_API_KEY` / `--api-key`. The test's
`assert.NotContains(out, "api-key")` is over-broad: it forbids the very flag name the message is
supposed to surface. The P0-1 intent is "never leak the key *value* or the *header name*
(`X-Api-Key`)", not "never mention the `--api-key` flag".

**Recommended fix (test, not production):** drop the `NotContains(out, "api-key")` assertion (the
flag name is safe and desirable) and keep `NotContains(out, sentinelKey)` + `NotContains(out,
"X-Api-Key")`. Do NOT change the production message — weakening it to satisfy a wrong assertion
would regress UX. (The Apollo *production* classifier is correct; only this test assertion is wrong.)

---

### P1 — CLI-layer tests violate the plan's TDD contract by being inconsistent with the code they guard
**Severity: P1 should-fix (process / gate integrity)**

The package-level client tests (`apollo_test.go`, `lusha_test.go`, 52 cases) are thorough,
correctly httptest-driven, and match the T001-T003 / T101-T102 specs (pagination incl. `--limit`
truncation + mid-pagination 429; reveal merge / skip-empty-id / serial-count; context cancellation;
empty-200; malformed JSON; auth-header-not-in-URL; DNC round-trip). Good.

But the suite as delivered is **RED**, which means the GREEN gate the plan mandates (Phase 14
"reruns (PASS)") was not actually reached before handoff. One failure is a real bug (P0 above), one
is a wrong assertion (P1 above). Either way the developer/tester loop must close to GREEN before
this is approvable. Re-run `go test ./cmd/brutus/` and confirm 0 failures.

---

### P2 — Apollo `--reveal` example in help still shows `--limit 25`; default is now 100
**Severity: P2 nit**
**File:** `cmd/brutus/cmd_enum_apollo.go:61`

```
brutus enum apollo -d example.com --reveal --limit 25
```

The ORCHESTRATION DELTA raised the default `--limit` to 100 (flag registered correctly at
`cmd_enum_apollo.go:73`). The example showing `25` is harmless but slightly inconsistent with the
new cost-rail default. Consider aligning the example to `--limit 100` or leaving an explicit
smaller value with a "lower to cap spend" note. Cosmetic only.

---

### P2 — Lusha `TestEnrich_Success` captures the request body via a single `r.Body.Read(buf)` (fragile, can under-read)
**Severity: P2 nit**
**File:** `cmd/brutus/.../lusha_test.go` → actually `pkg/enum/lusha/lusha_test.go:122-126`

```go
buf := make([]byte, r.ContentLength)
_, err = r.Body.Read(buf)
_ = err
capturedReqBody = buf
```

A single `Read` is not guaranteed to fill `buf`; it may return a short read, and the error is
discarded. The assertion `Contains(string(capturedReqBody), "Ada")` happens to pass for this small
body, but the pattern is brittle. Prefer `io.ReadAll(r.Body)`. Test-only; no production impact.

---

## Plan Adherence

| Plan Requirement | Status | Notes |
| ---------------- | ------ | ----- |
| Apollo `Client` shape mirrors Hunter (apiKey/httpClient/baseURL/pageSize) | PASS | `apollo.go:114-133` |
| Lusha minimal `Client` (no pageSize) | PASS | `lusha.go:127-141` |
| Pagination termination order (empty → limit → short → total → maxPages → ctx) | PASS | `apollo.go:142-174` matches §2.4 exactly |
| `RevealEmails` partial-honesty `Revealed=true` even on empty email | PASS | `apollo.go:184-203`; verified by `TestRevealEmails_Merge` |
| `RevealEmails` skips empty ID | PASS | `apollo.go:187-189`; `TestRevealEmails_SkipsEmptyID` |
| Lusha empty-200 → empty `*Contact`, not error | PASS | `lusha.go:145-157`; `TestEnrich_EmptyMatch` |
| Sentinels + `APIError.Unwrap` per service (Apollo 401/403/422/429; Lusha 401/402/403/404/429) | PASS | `apollo.go:95-107`, `lusha.go:106-120` |
| `do` is single P0-1/P0-3 choke point (header auth, bounded read, no key/body/URL log) | PASS | `apollo.go:255-291`, `lusha.go:168-206` |
| Per-service output files (DELTA, not appended to `cmd_enum_output.go`) | PASS | `cmd_enum_apollo_output.go`, `cmd_enum_lusha_output.go` |
| `sanitizeTerminal`/`truncate` reused, not duplicated | PASS | grep = 1 each |
| Apollo `--limit` default 100 (DELTA) | PASS | `cmd_enum_apollo.go:73` |
| `pageSizeForLimit` = min(limit,100), 100 when 0 | PASS | `cmd_enum_apollo.go:178-186` |
| Lusha identity mutual-exclusion validation | PASS | `validateLushaIdentity` `cmd_enum_lusha.go:157-199`; `TestValidateLushaIdentity` (9 cases) |
| `--phone` / `--email-only` mutual exclusion | PASS | `cmd_enum_lusha.go:158-160` |
| Cost notices to stderr (Apollo opt-in N people; Lusha unconditional) | PASS | `cmd_enum_apollo.go:116-119`, `cmd_enum_lusha.go:117-120` |
| `omitempty` on PII (Apollo email/email_status preview) | PASS | `cmd_enum_apollo_output.go:100-101`; `TestOutputApolloJSONL` preview omits email |
| DNC surfaced (human marker + JSON `do_not_call` always emitted) | PASS | `cmd_enum_lusha_output.go:72-79,97` |
| Registration by orchestrator in `cmd_enum.go` (developers don't edit) | PASS | both `AddCommand` lines + help present `cmd_enum.go:122-123` |
| No premature shared HUMINT interface (Rule of Three intentionally not met) | PASS | two independent packages, as designed |
| Apollo/Lusha paths/fields/headers isolated in consts + unexported structs (UNVERIFIED-safe) | PASS | `apollo.go:41-49,322-379`, `lusha.go:41-47,260-299` |
| `classifyApolloError` default = status-code only, no `%w` | PASS | `cmd_enum_apollo.go:166-171` |
| `classifyLushaError` default = status-code only, no `%w` | **FAIL (P0 above)** | `cmd_enum_lusha.go:228-230` leaks via `%w` |

## Go Idioms / Quality

- Error wrapping: correct `%w` use for internal/decoding errors; the ONLY misuse is the Lusha
  classifier default (P0). Sentinels via `errors.New`, `Unwrap` for `errors.Is`, `errors.As` for
  the typed error — idiomatic and consistent with Hunter.
- Context: `http.NewRequestWithContext` in both `do` helpers; `ctx.Err()` checked between pages
  (Apollo) and per reveal iteration; matches Hunter.
- `defer resp.Body.Close()` present in both `do` helpers (with `_ =` to satisfy errcheck).
- No goroutines (serial by design, §6) → no leak surface; race detector clean.
- Function organization: exported/public-API-first, helpers last, early returns, nesting ≤2 —
  conforms to `go-best-practices`. File sizes: apollo.go ~380 lines, lusha.go ~300, both under the
  400/500 limits (no `apollo_types.go` split needed, as the plan permitted).
- Exported surface is minimal and matches the architecture's §2.3/§3.3 public types. `apiKey` is
  unexported, no JSON tag, no getter (P0-1b) in both clients.
- YAGNI/KISS: no errgroup/limiter/retry (correctly deferred per §6/§12); no dead code observed;
  `pageSizeForLimit` is a justified small helper (used once but it isolates a non-obvious clamp).

## Security (P0 mapping)

- P0-1 key-never-logged: clients PASS (header set inline, never logged; `--verbose` logs counts
  only). **CLI classifier: Lusha FAILS (P0 above); Apollo PASSES.**
- P0-1b unexported apiKey field: PASS both.
- P0-1c no `httputil.Dump*`: PASS (grep clean).
- P0-1d `--api-key` process-list/history warning + prefer env: PASS both help strings.
- P0-3 bounded read via `enum.ReadResponseBody(resp, 0)`: PASS both; no raw `io.ReadAll(resp.Body)`.
- P0-4 terminal sanitization on every API string in human output: PASS both; JSONL relies on
  `encoding/json` escaping (documented).
- P0-5 no silent 429 retry: PASS (mapped to `ErrRateLimited`, surfaced).
- P0-6/P0-7 cost rails: PASS.

---

## Review Result
REVIEW_REJECTED

### Issues
- **P0:** `classifyLushaError` default branch (`cmd_enum_lusha.go:228-230`) `%w`-wraps `*lusha.APIError`, leaking vendor-echoed `Details` (possible API key) for any unmapped status. Real P0-1 credential leak; `TestClassifyLushaError_NoKeyLeak/wrapped_500` fails. Fix: mirror the Apollo default branch (extract `*APIError` via `errors.As`, report `StatusCode` only, no `%w`).
- **P1:** `TestClassifyApolloError_NoKeyLeak` asserts `NotContains(out, "api-key")` (`cmd_enum_apollo_test.go:121`), which wrongly forbids the intended actionable `--api-key` hint. Fix the *test* (drop that assertion), not the production message.
- **P1:** `go test ./cmd/brutus/` is RED on handoff — the mandated GREEN gate was not reached. Close the loop to 0 failures.
- **P2:** Apollo `--reveal` help example shows `--limit 25` but default is now 100 (`cmd_enum_apollo.go:61`).
- **P2:** `pkg/enum/lusha/lusha_test.go:122-126` captures the request body with a single `r.Body.Read` (can under-read; error discarded) — prefer `io.ReadAll`.

**Verdict: NEEDS_CHANGES.** The package clients, pagination, reveal honesty, identity validation,
DNC handling, DRY, and P0-3/P0-4 controls are all correctly implemented and well-tested. One real
P0 credential-leak in the Lusha error classifier and one buggy Apollo test assertion leave the
`cmd/brutus` suite RED. Both are small, localized fixes (Apollo already shows the correct
classifier pattern to copy). Route to `backend-developer` for the P0 + P2-help, and to
`backend-tester` for the P1 test-assertion fix; re-run `go test ./cmd/brutus/` to GREEN before
re-review.

---

## Metadata

```json
{
  "agent": "backend-reviewer",
  "output_type": "code-review",
  "timestamp": "2026-06-26",
  "feature_directory": "/Users/engineer/github/brutus/.worktrees/apollo-lusha-enum/.feature-development",
  "skills_invoked": ["using-skills", "focusing-on-the-goal", "enforcing-evidence-based-analysis", "discovering-reusable-code", "gateway-backend", "persisting-agent-outputs", "verifying-before-completion", "analyzing-with-adversarial-pov", "calibrating-time-estimates", "preferring-simple-solutions", "adhering-to-dry", "adhering-to-yagni"],
  "library_skills_read": [
    "/Users/engineer/.claude/plugins/cache/praetorian-ai-marketplace/engineering/1.38.17/skill-library/development/backend/reviewing-backend-implementations/SKILL.md",
    "/Users/engineer/.claude/plugins/cache/praetorian-ai-marketplace/engineering/1.38.17/skill-library/development/backend/go-best-practices/SKILL.md",
    "/Users/engineer/.claude/plugins/cache/praetorian-ai-marketplace/engineering/1.38.17/skill-library/development/error-handling-patterns/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/enum/apollo/apollo.go:1-380",
    "pkg/enum/apollo/apollo_test.go:1-547",
    "pkg/enum/lusha/lusha.go:1-300",
    "pkg/enum/lusha/lusha_test.go:1-327",
    "cmd/brutus/cmd_enum_apollo.go:1-187",
    "cmd/brutus/cmd_enum_apollo_output.go:1-136",
    "cmd/brutus/cmd_enum_apollo_test.go:84-125",
    "cmd/brutus/cmd_enum_lusha.go:1-232",
    "cmd/brutus/cmd_enum_lusha_output.go:1-144",
    "cmd/brutus/cmd_enum_lusha_test.go:320-365",
    "cmd/brutus/cmd_enum.go:30-124",
    "cmd/brutus/cmd_enum_hunter.go:1-140"
  ],
  "status": "complete",
  "verdict": "NEEDS_CHANGES",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Fix P0 classifyLushaError default branch (cmd_enum_lusha.go:228-230) to mirror Apollo's errors.As/status-code-only pattern (no %w). Fix P2 apollo help example --limit. backend-tester: drop the NotContains(out, 'api-key') assertion in TestClassifyApolloError_NoKeyLeak (flag name is safe). Re-run go test ./cmd/brutus/ to GREEN."
  }
}
```
