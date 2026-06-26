# Apollo + Lusha enum integrations — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use plan-execute (or developing-with-subagents) to implement
> this plan task-by-task.

**Goal:** Add `brutus enum apollo` (domain → people discovery + opt-in `--reveal` email enrichment)
and `brutus enum lusha` (single-identity contact enrichment via Lusha v3), mirroring the verified
Hunter.io pattern.

> **ORCHESTRATION DELTAS (2026-06-26, applied for safe parallel execution — intentional, NOT drift):**
> 1. **Apollo `--limit` default = 100** (user decision at Phase 7 checkpoint), not 25. Aligns with
>    Hunter's default page size. Cost notice + tests reflect 100.
> 2. **Output formatters live in per-service files, NOT appended to `cmd_enum_output.go`:** Apollo →
>    `cmd/brutus/cmd_enum_apollo_output.go`, Lusha → `cmd/brutus/cmd_enum_lusha_output.go`. This
>    removes the shared-file (`cmd_enum_output.go`) write contention between the two parallel tracks.
>    They still reuse `sanitizeTerminal`/`truncate` from `cmd_enum_output.go` (DRY preserved).
> 3. **Command registration (`cmd_enum.go`, T006/T105) is performed by the ORCHESTRATOR** as a single
>    serialized step after both tracks land — developers do NOT edit `cmd_enum.go`. This leaves ZERO
>    files shared between the two parallel developer tracks.
> 4. **Dev/test agent split (forced by the `agent-first-enforcement` hook):** the hook routes
>    production `.go` under `pkg/`/`cmd/` to `backend-developer` and `_test.go` to `backend-tester`,
>    and denies all other writers (incl. the orchestrator and `integration-developer`). Therefore the
>    per-task RED/GREEN is realized across phases, NOT in one agent: **Phase 8** `backend-developer`
>    writes production code (apollo.go, lusha.go, cmd_enum_{apollo,lusha}.go, cmd_enum_{apollo,lusha}_output.go)
>    to the EXACT signatures/consts the task specs require; **Phase 14** `backend-tester` writes the
>    full per-task test matrix (T001/T002/T003/T004 + T101/T102/T103/T104 test blocks) and runs it;
>    failures route back to `backend-developer` via the tight-feedback loop. The test SPECS in each
>    task below are the contract the tester implements and the developer must satisfy. The
>    `enum{Apollo,Lusha}Cmd` registration test moves to after orchestrator registration.

**Architecture:** See `architecture.md` in this directory. Two independent client packages +
cobra subcommands + output formatters + tests. No shared abstraction beyond existing helpers
(`enum.NewEnumHTTPClient`, `enum.ReadResponseBody`, `sanitizeTerminal`, `truncate`, CLI globals).

**Security:** See `security-assessment.md` (security-lead, Phase 7). P0 controls below are derived
from it: P0-1/P0-1b/P0-1c/P0-1d (credential handling), P0-3 (bounded read), P0-4 (terminal
sanitization), P0-5 (no silent 429 retry), P0-6/P0-7 (cost rails). P1-PII output-file perms are
already satisfied by `setupOutputWriter` (`flags.go:312`, `0o600`).

**Tech Stack:** Go 1.26, `github.com/spf13/cobra` v1.10.2, `github.com/stretchr/testify` v1.11.1
(assert/require), stdlib `net/http`/`net/http/httptest`/`context`/`encoding/json`. No new deps.

**TDD throughout:** every task writes the failing test first, runs it (RED), implements minimal
code (GREEN), reruns (PASS), commits. DRY/YAGNI/KISS per architecture.

> **CRITICAL for developer:** Apollo endpoint paths/fields (architecture §7) and Lusha v3 schema
> (architecture §11) are research-derived, NOT verified against a live API. Keep them isolated in
> unexported consts + request/response structs (the tasks enforce this) and verify against live
> docs/a key. `httptest` tests use controlled payloads, so they pass regardless — but live calls
> require correct paths/fields/headers.

---

## Parallelization & shared-file conflict management

**Apollo (Track A: T001–T006) and Lusha (Track B: T101–T105) are fully independent** — separate
packages (`pkg/enum/apollo/`, `pkg/enum/lusha/`) and separate command files
(`cmd/brutus/cmd_enum_apollo*.go`, `cmd/brutus/cmd_enum_lusha*.go`). Two developers can run Track A
and Track B in parallel with **zero file conflicts** for T001–T005 and T101–T104.

**Only two files are shared by both tracks:**
- `cmd/brutus/cmd_enum.go` (registration + help text) — touched by **T006** (Apollo) and **T105**
  (Lusha).
- `cmd/brutus/cmd_enum_output.go` (output formatters) — touched by **T003** (Apollo) and **T103**
  (Lusha).

**Conflict-avoidance rules (mandatory):**
1. **`cmd_enum_output.go` is APPEND-ONLY.** Each track appends its two `output*` functions at the
   end of the file. Appends to different ends never overlap line-wise; if both land at once, the
   merge is trivial (two independent function blocks). Do NOT reorder or edit existing functions.
2. **`cmd_enum.go` edits use distinct insertion points.** Apollo adds its `AddCommand` +
   help lines for `apollo`; Lusha adds separate lines for `lusha`. Add each on its **own line**
   (do not combine). If both developers edit simultaneously, **serialize**: whoever lands second
   rebases their two-line addition onto the other's (no semantic conflict — independent lines).
3. **Recommended serialization:** land **T006 before T105** (or vice-versa) rather than merging
   `cmd_enum.go` concurrently. The registration tasks are tiny (~4 lines each); doing them
   back-to-back is faster than resolving a merge.

```
Track A (Apollo):  T001 → T002 → T003 → T004 → T006(reg) ─┐
Track B (Lusha):   T101 → T102 → T103 → T104 → T105(reg) ─┤
                                                          └→ T200 (final gate, both)
```

---

# TRACK A — Apollo (`pkg/enum/apollo/` + `cmd/brutus/cmd_enum_apollo*.go`)

---

## T001: Apollo types, sentinels, APIError+Unwrap, toPerson

**Files:**
- Create: `pkg/enum/apollo/apollo.go`
- Test: `pkg/enum/apollo/apollo_test.go`

**Implementation notes:**
- Package doc comment + Apache license header (copy header from `pkg/enum/hunter/hunter.go:1-13`).
- Sentinels: `ErrUnauthorized` (401), `ErrForbidden` (403), `ErrBadRequest` (422), `ErrRateLimited`
  (429) — architecture §2.6.
- `APIError{StatusCode int; Details string}` with `Error()` and `Unwrap()` (401→Unauthorized,
  403→Forbidden, 422→BadRequest, 429→RateLimited, else nil). Mirror `hunter.go:70-92`.
- Public types `Person`, `DomainResult` (architecture §2.3).
- Unexported request/response structs (architecture §7 isolation): `apolloSearchRequest`,
  `apolloSearchResponse{People []apolloPerson; Pagination apolloPagination}`, `apolloPerson`,
  `apolloPagination`, `apolloMatchRequest`, `apolloMatchResponse{Person apolloPerson}`.
- `toPerson(*apolloPerson) Person` mapper (search fields; PII empty, `Revealed=false`). Mirror
  `toPerson` at `hunter.go:216-236`.
- Consts: `defaultBaseURL = "https://api.apollo.io"`, `searchPath = "/api/v1/mixed_people/api_search"`,
  `matchPath = "/api/v1/people/match"`, `headerAPIKey = "X-Api-Key"`, `defaultPageSize = 100`,
  `maxPages = 500`.
- **P0-1b:** `apiKey` field is unexported, no JSON tag, no getter.

**Step 1 — failing test** (`apollo_test.go`): `TestToPerson` (search fields map; `Email` empty,
`Revealed=false`); `TestAPIError_Unwrap` (table: 401→ErrUnauthorized, 403→ErrForbidden,
422→ErrBadRequest, 429→ErrRateLimited, 500→nil for each); `TestAPIError_Error` (contains status +
details). Pattern: `hunter_test.go:37-91`.
**Step 2 — run, expect FAIL:** `go test ./pkg/enum/apollo/ -run 'TestToPerson|TestAPIError'` (undefined symbols).
**Step 3 — implement** types/errors/converter/consts (no network code).
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add apollo client types and sentinel errors`

**Exit Criteria:**
- [ ] 3 test functions pass (verify: `go test ./pkg/enum/apollo/ -run 'TestToPerson|TestAPIError' -v`)
- [ ] `go vet ./pkg/enum/apollo/` exit 0
- [ ] `errors.Is(&APIError{StatusCode:422}, ErrBadRequest)` true (asserted)

**Dependencies:** none.

---

## T002: Apollo Client, NewClient, do helper, searchPage, matchPerson (single calls)

**Files:**
- Modify: `pkg/enum/apollo/apollo.go`
- Test: `pkg/enum/apollo/apollo_test.go`

**Implementation notes:**
- `Client` struct + `NewClient(apiKey string, timeout time.Duration, pageSize int) *Client`
  (architecture §2.1; `httpClient: enum.NewEnumHTTPClient(timeout)`, `pageSize<=0 → defaultPageSize`).
- `do(ctx, method, path string, body any) ([]byte, error)`: JSON-encode body, build request with
  `req.Header.Set(headerAPIKey, c.apiKey)` + `Content-Type: application/json`, `c.httpClient.Do`,
  `defer resp.Body.Close()`, read via `enum.ReadResponseBody(resp, 0)` (P0-3), map non-2xx →
  `*APIError` (extract details from error envelope if decodable, else `resp.Status` — mirror
  `hunter.go:198-206`). **P0-1: never log the key, header, body, or URL. P0-1c: NEVER use
  `httputil.DumpRequest`/`DumpResponse` (would capture the `X-Api-Key` header).** Single
  P0-1/P0-3 choke point.
- `searchPage(ctx, domain string, titles []string, page int) (people []Person, total int, err error)`:
  build `apolloSearchRequest{Domains:[]string{domain}, Titles:titles, Page:page, PerPage:c.pageSize}`,
  POST `searchPath`, decode `apolloSearchResponse`, map each via `toPerson`, return
  `pagination.total_entries`.
- `matchPerson(ctx, id string) (email, status string, err error)`: POST `matchPath` with
  `apolloMatchRequest{ID:id, RevealPersonalEmails:true}`, decode `apolloMatchResponse`, return
  `person.email` + `person.email_status`.
- Add `newTestClient(baseURL string) *Client` test helper overriding `c.baseURL` (mirror
  `hunter_test.go:122-126`).

**Step 1 — failing test:** `TestSearchPage_Decode` (httptest returns 2 people + pagination → assert
fields incl. `ID`, `Title`, `Organization`; `Email` empty; total returned). `TestSearchPage_401`
(server 401 → `errors.Is(err, ErrUnauthorized)` + `errors.As` to `*APIError` with 401).
`TestSearchPage_422` (→ `ErrBadRequest`). `TestMatchPerson_Decode` (server returns
`person.email`+`email_status` → returned). `TestDo_MalformedJSON` (200 + `not-json{{{` → decode
error). `TestDo_SetsAuthHeader` (capture request, assert `X-Api-Key` header == test key, assert key
NOT in URL). Pattern: `hunter_test.go:128-229`.
**Step 2 — run, expect FAIL.**
**Step 3 — implement** `Client`, `NewClient`, `do`, `searchPage`, `matchPerson`.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add apollo HTTP client, people search and match`

**Exit Criteria:**
- [ ] 6 test functions pass (verify: `go test ./pkg/enum/apollo/ -run 'TestSearchPage|TestMatchPerson|TestDo' -v`)
- [ ] `X-Api-Key` set as a header and absent from the request URL (asserted in `TestDo_SetsAuthHeader`)
- [ ] body read via `enum.ReadResponseBody` (verify by code read: no raw `io.ReadAll(resp.Body)` in package)
- [ ] no `httputil.Dump*` in package (verify: `grep -rn 'httputil.Dump' pkg/enum/apollo/` returns nothing) (P0-1c)

**Dependencies:** T001.

---

## T003: Apollo SearchPeople pagination + RevealEmails + output formatters

**Files:**
- Modify: `pkg/enum/apollo/apollo.go`
- Modify: `cmd/brutus/cmd_enum_output.go` (APPEND `outputApolloHuman` + `outputApolloJSONL` at end)
- Test: `pkg/enum/apollo/apollo_test.go`
- Test: `cmd/brutus/cmd_enum_apollo_test.go` (create)

**Implementation notes:**
- `SearchPeople(ctx, domain string, titles []string, limit int) (*DomainResult, error)` — loop from
  architecture §2.4. Termination order: empty page → `--limit` truncation → short page → known
  total → `maxPages` → `ctx.Err()`. Page is 1-based.
- `RevealEmails(ctx, result *DomainResult) error` — architecture §2.5: serial loop over
  `result.People`, skip empty `ID`, `matchPerson` per id, set `Email`/`EmailStatus`/`Revealed=true`
  (true even when returned email is empty — partial honesty), set `result.Revealed=true` if
  `len(People)>0`. Return first error (no swallow).
- Output (`cmd_enum_output.go`, append — DRY: reuse `sanitizeTerminal`/`truncate`, do NOT redefine):
  - `outputApolloHuman(w io.Writer, result *apollo.DomainResult, useColor bool)` — architecture §9:
    header (`Apollo: <sanitized domain>`, `People found: N (total: M)`); dim preview note when
    `!result.Revealed`; columns `Name|Title|Dept|Org` (preview) or `+Email|Status` (revealed);
    every API string `sanitizeTerminal`+`truncate` (P0-4); empty → `No people found for this domain`.
  - `outputApolloJSONL(w io.Writer, result *apollo.DomainResult)` — local struct, `type:"apollo"`,
    always `domain`+`revealed`+`id`, `omitempty` on name/title/dept/org/email/email_status.

**Step 1 — failing test:**
- In `apollo_test.go`: `TestSearchPeople_Pagination` table (mirror `hunter_test.go:264-345`, paged
  httptest keyed on `page`, `atomic.Int32` counter): single page; two full pages + short final;
  empty domain (0 people, 1 request); `--limit=2` over 5 people → 2 returned; mid-pagination 429 →
  `errors.Is(err, ErrRateLimited)`. `TestSearchPeople_ContextCancellation` (slow server + short ctx
  → error, mirror `hunter_test.go:347-367`). `TestRevealEmails_Merge` (3 people, server returns
  email for 2, none for 3rd → those 2 have email + `Revealed=true`; 3rd empty email + `Revealed=true`;
  `result.Revealed=true`). `TestRevealEmails_SkipsEmptyID` (person with `ID==""` → no match call;
  assert request counter). `TestRevealEmails_SerialCount` (5 ids → exactly 5 match requests).
- In `cmd_enum_apollo_test.go`: `TestOutputApolloJSONL` (single revealed person → 1 line, correct
  type/domain/revealed/id; preview person omits `email`; empty result → 0 lines). `TestOutputApolloHuman`
  (header + row; revealed shows Email column; preview shows note; empty → "No people found"). Use
  `bytes.Buffer`. Pattern: `cmd_enum_hunter_test.go:153-268`.
**Step 2 — run, expect FAIL** (`go test ./pkg/enum/apollo/ ./cmd/brutus/ -run 'Apollo'`).
**Step 3 — implement** `SearchPeople`, `RevealEmails`, both output functions.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add apollo pagination, email reveal and output formatters`

**Exit Criteria:**
- [ ] `TestSearchPeople_Pagination` (5 subtests) + `TestSearchPeople_ContextCancellation` pass (verify: `go test ./pkg/enum/apollo/ -run TestSearchPeople -v`)
- [ ] `--limit=2` over 5 people returns exactly 2; mid-pagination 429 surfaces `ErrRateLimited` (asserted)
- [ ] 3 `RevealEmails` tests pass: merge, skip-empty-id, serial-count = N (verify: `go test ./pkg/enum/apollo/ -run TestRevealEmails -v`)
- [ ] 2 output tests pass; preview JSONL omits `email`, revealed JSONL includes it (verify: `go test ./cmd/brutus/ -run TestOutputApollo -v`)
- [ ] No duplicate sanitizer (verify: `grep -c 'func sanitizeTerminal' cmd/brutus/*.go` returns 1)

**Dependencies:** T002.

---

## T004: Apollo command, flags, runEnumApollo, resolveApolloAPIKey, classifyApolloError

**Files:**
- Create: `cmd/brutus/cmd_enum_apollo.go`
- Test: `cmd/brutus/cmd_enum_apollo_test.go` (extend)

**Implementation notes:**
- Mirror `cmd_enum_hunter.go:30-139`. File-local flags: `flagApolloDomain`, `flagApolloTitles`
  (`[]string` via `StringSliceVar`), `flagApolloReveal` (bool), `flagApolloLimit` (int, default 25),
  `flagApolloAPIKey`.
- `enumApolloCmd` cobra command (`Use:"apollo"`, Short/Long/Example). Example MUST show: free
  discovery; `--titles` filter; `--reveal` with a **credit warning**; the `--api-key`
  process-list/history warning + prefer-`APOLLO_API_KEY` note (P0-1d — use the warning string
  exactly as `cmd_enum_hunter.go:61-62`).
- `init()`: declare flags; `--domain`/`-d`; `MarkFlagRequired("domain")`.
- `runEnumApollo` (mirror `cmd_enum_hunter.go:68-113`): require domain → `resolveApolloAPIKey` →
  `setupOutputWriter(flagOutputFile)` (set `flagJSON=true` if forceJSON) → `signal.NotifyContext(...,
  os.Interrupt, syscall.SIGTERM)` → stderr progress if `!quiet && !json` → compute pageSize =
  `min(limit,100)` (or `defaultPageSize` when limit==0) → `apollo.NewClient(key, flagTimeout,
  pageSize)` → `SearchPeople(ctx, domain, titles, limit)` → if `flagApolloReveal`: stderr cost
  notice `[*] --reveal will consume Apollo credits for N people` (N=len(result.People)) when
  `!quiet && !json`, then `RevealEmails(ctx, result)` → `classifyApolloError` on any error →
  `outputApolloJSONL`/`outputApolloHuman`.
- `resolveApolloAPIKey(flagValue string) (string, error)`: flag, else `os.Getenv("APOLLO_API_KEY")`,
  else error mentioning `APOLLO_API_KEY`. Mirror `cmd_enum_hunter.go:117-125`.
- `classifyApolloError(err) error`: switch `errors.Is` on Unauthorized/Forbidden/BadRequest/
  RateLimited → actionable key-free messages; default wraps. Mirror `cmd_enum_hunter.go:128-139`.

**Step 1 — failing test:** `TestResolveApolloAPIKey` (table: flag wins over env; env when flag
empty; error when both empty — assert message contains `APOLLO_API_KEY`; use `t.Setenv`). Pattern:
`cmd_enum_hunter_test.go:33-74`. `TestClassifyApolloError_NoKeyLeak` (P0-1, mirror security-assessment
§2.1): feed a sentinel key `const sentinelKey = "SECRETKEY-DO-NOT-LEAK-abc123"` via
`&apollo.APIError{StatusCode:401, Details:sentinelKey}` (vendor echoed key into body) plus 429/403/422
and a wrapped 500-with-sentinel; for EVERY case assert `NotContains(out, sentinelKey)` AND
`NotContains(out, "X-Api-Key")` AND `NotContains(out, "api-key")`. Pattern: `cmd_enum_hunter_test.go:76-113`.
**Step 2 — run, expect FAIL.**
**Step 3 — implement** the command file.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add apollo subcommand`

**Exit Criteria:**
- [ ] `TestResolveApolloAPIKey` (3 subtests) pass (verify: `go test ./cmd/brutus/ -run TestResolveApolloAPIKey -v`)
- [ ] `TestClassifyApolloError_NoKeyLeak` (5 cases incl. sentinel-in-Details + wrapped) passes; every error asserted NOT to contain the sentinel key, `X-Api-Key`, or `api-key` (P0-1)
- [ ] `go vet ./cmd/brutus/` exit 0

**Dependencies:** T003.

---

## T006: Register apollo subcommand + update enum help text (SHARED FILE — see conflict rules)

**Files:**
- Modify: `cmd/brutus/cmd_enum.go` (`init()` AddCommand list ~line 111; `Long`/`Example` ~lines 44-66)
- Test: `cmd/brutus/cmd_enum_apollo_test.go` (extend)

**Implementation notes:**
- Add `enumCmd.AddCommand(enumApolloCmd)` on its **own line** after the existing
  `enumCmd.AddCommand(...)` calls (`cmd_enum.go:106-111`).
- Add an `apollo` line to the `Long` subcommand list, the `brutus enum apollo --help` hint, and one
  `Example` line (mirror the existing hunter entries at `cmd_enum.go:44,51,62-63`).
- **CONFLICT RULE:** this is one of the two shared files. Use the own-line discipline from the
  Parallelization section. Prefer landing this immediately before/after T105 (do not co-edit
  `cmd_enum.go` concurrently with Track B).

**Step 1 — failing test:** `TestEnumApolloRegistered` (mirror `cmd_enum_hunter_test.go:119-147`):
walk `enumCmd.Commands()`, find `Use=="apollo"`; assert flags `--domain`, `--titles`, `--reveal`,
`--limit`, `--api-key` exist; assert `-d` shorthand; assert `--domain` marked required.
**Step 2 — run, expect FAIL** (command not registered).
**Step 3 — implement** registration + help text.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): register apollo subcommand`

**Exit Criteria:**
- [ ] `TestEnumApolloRegistered` passes (verify: `go test ./cmd/brutus/ -run TestEnumApolloRegistered -v`)
- [ ] 5 flags + `-d` shorthand asserted present; `--domain` required
- [ ] `enumCmd` has exactly one `apollo` subcommand (asserted)

**Dependencies:** T004. (Shared file with T105 — serialize per conflict rules.)

---

# TRACK B — Lusha (`pkg/enum/lusha/` + `cmd/brutus/cmd_enum_lusha*.go`)

---

## T101: Lusha types, sentinels, APIError+Unwrap, toContact

**Files:**
- Create: `pkg/enum/lusha/lusha.go`
- Test: `pkg/enum/lusha/lusha_test.go`

**Implementation notes:**
- Apache header (copy from `hunter.go:1-13`) + package doc.
- Sentinels: `ErrUnauthorized` (401), `ErrForbidden` (403), `ErrNoCredits` (402), `ErrRateLimited`
  (429), `ErrNotFound` (404 — UNVERIFIED no-match signal, §11). Architecture §3.5.
- `APIError{StatusCode int; Details string}` + `Error()` + `Unwrap()` (401→Unauthorized,
  403→Forbidden, 402→NoCredits, 429→RateLimited, 404→NotFound, else nil).
- Public types `ContactQuery`, `RevealOptions`, `EmailEntry`, `PhoneEntry`, `Contact`
  (architecture §3.3).
- Unexported request/response structs (architecture §11 isolation): `lushaEnrichRequest` (identity
  + reveal control), `lushaEnrichResponse{EmailAddresses []lushaEmail; PhoneNumbers []lushaPhone;
  Name, JobTitle string; Company ...}`, `lushaEmail`, `lushaPhone`.
- `toContact(*lushaEnrichResponse) *Contact` mapper (architecture §3.3). Map `doNotCall` → `PhoneEntry.DoNotCall`.
- Consts: `defaultBaseURL = "https://api.lusha.com"`, `enrichPath = "/v3/contacts/search-and-enrich"`,
  `headerAPIKey = "api_key"`.
- **P0-1b:** `apiKey` field unexported, no JSON tag, no getter.

**Step 1 — failing test:** `TestToContact` (email + phone arrays map; `DoNotCall` preserved; name/
title/company map). `TestAPIError_Unwrap` (table: 401→Unauthorized, 402→NoCredits, 403→Forbidden,
404→NotFound, 429→RateLimited, 500→nil for each). `TestAPIError_Error`. Pattern: `hunter_test.go:37-91`.
**Step 2 — run, expect FAIL.**
**Step 3 — implement** types/errors/converter/consts.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add lusha client types and sentinel errors`

**Exit Criteria:**
- [ ] 3 test functions pass (verify: `go test ./pkg/enum/lusha/ -run 'TestToContact|TestAPIError' -v`)
- [ ] `go vet ./pkg/enum/lusha/` exit 0
- [ ] `errors.Is(&APIError{StatusCode:402}, ErrNoCredits)` true; `DoNotCall` round-trips (asserted)

**Dependencies:** none. (Independent of Track A.)

---

## T102: Lusha Client, NewClient, do helper, buildEnrichRequest, Enrich

**Files:**
- Modify: `pkg/enum/lusha/lusha.go`
- Test: `pkg/enum/lusha/lusha_test.go`

**Implementation notes:**
- `Client` struct + `NewClient(apiKey string, timeout time.Duration) *Client` (architecture §3.1;
  no pageSize). `httpClient: enum.NewEnumHTTPClient(timeout)`.
- `do(ctx, method, path string, body any) ([]byte, error)`: JSON-encode body, set
  `req.Header.Set(headerAPIKey, c.apiKey)` + `Content-Type: application/json`, `Do`,
  `defer Body.Close()`, read via `enum.ReadResponseBody(resp, 0)` (P0-3), map non-2xx → `*APIError`
  (envelope details or `resp.Status`). **P0-1: never log key/header/body. P0-1c: NO
  `httputil.Dump*` (captures the `api_key` header).**
- `buildEnrichRequest(q ContactQuery, r RevealOptions) lushaEnrichRequest`: map exactly one identity
  group + reveal flags to the v3 request shape (architecture §11 — field names isolated here).
- `Enrich(ctx, q ContactQuery, r RevealOptions) (*Contact, error)`: `do` POST `enrichPath` → decode
  `lushaEnrichResponse` → `toContact`. Empty 200 (no datapoints) → `*Contact` with empty slices
  (not an error). 404 → `ErrNotFound` via `do` mapping.
- Add `newTestClient(baseURL string) *Client` helper overriding `c.baseURL`.

**Step 1 — failing test:** `TestEnrich_Success` (httptest returns 1 email + 1 phone with
`doNotCall:true` → `Contact` has both; DNC preserved; assert `api_key` header sent and NOT in URL;
capture+assert request body contains the identity). `TestBuildEnrichRequest` (table: name+company,
name+domain, email-only, linkedin-only → correct request shape per group). `TestEnrich_401`
(→ `ErrUnauthorized`). `TestEnrich_402` (→ `ErrNoCredits`). `TestEnrich_429` (→ `ErrRateLimited`).
`TestEnrich_EmptyMatch` (200 + empty arrays → `*Contact` empty, no error). `TestEnrich_MalformedJSON`
(→ decode error). `TestEnrich_ContextCancellation` (slow server + short ctx → error). Pattern:
`hunter_test.go:128-229, 347-367`.
**Step 2 — run, expect FAIL.**
**Step 3 — implement** `Client`, `NewClient`, `do`, `buildEnrichRequest`, `Enrich`.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add lusha v3 search-and-enrich client`

**Exit Criteria:**
- [ ] 8 test functions pass (verify: `go test ./pkg/enum/lusha/ -run 'TestEnrich|TestBuildEnrichRequest' -v`)
- [ ] `api_key` set as header, absent from URL; key absent from any captured request log (asserted)
- [ ] empty 200 returns empty `*Contact` not error; 402→`ErrNoCredits`; malformed JSON→decode error (asserted)
- [ ] body read via `enum.ReadResponseBody` (code read: no raw `io.ReadAll(resp.Body)`)
- [ ] no `httputil.Dump*` in package (verify: `grep -rn 'httputil.Dump' pkg/enum/lusha/` returns nothing) (P0-1c)

**Dependencies:** T101.

---

## T103: Lusha output formatters (SHARED FILE — append-only)

**Files:**
- Modify: `cmd/brutus/cmd_enum_output.go` (APPEND `outputLushaHuman` + `outputLushaJSONL` at end)
- Test: `cmd/brutus/cmd_enum_lusha_test.go` (create)

**Implementation notes:**
- APPEND-ONLY (conflict rule). Reuse `sanitizeTerminal`/`truncate` — do NOT redefine (DRY).
- `outputLushaHuman(w io.Writer, c *lusha.Contact, useColor bool)` — architecture §9: header
  `Lusha: <sanitized identity/name summary>`; email rows (`address | type | confidence`); phone rows
  (`number | type | DNC`) with an explicit `DNC` marker when `DoNotCall`; every API string
  `sanitizeTerminal`+`truncate` (P0-4); empty contact → `No contact data returned`.
- `outputLushaJSONL(w io.Writer, c *lusha.Contact)` — local struct, `type:"lusha"`,
  `name/job_title/company` (`omitempty`), `emails[]` (address/type/confidence) and `phones[]`
  (number/type/`do_not_call` bool), `omitempty` on the arrays. One JSON object (single contact).

**Step 1 — failing test** (`cmd_enum_lusha_test.go`): `TestOutputLushaJSONL` (contact with 1 email +
1 DNC phone → 1 line, `type:"lusha"`, `phones[0].do_not_call==true`; empty contact → object with no
emails/phones arrays). `TestOutputLushaHuman` (renders email + phone rows; DNC phone shows `DNC`
marker; empty → "No contact data returned"). Use `bytes.Buffer`. Pattern: `cmd_enum_hunter_test.go:153-268`.
**Step 2 — run, expect FAIL** (`go test ./cmd/brutus/ -run TestOutputLusha`).
**Step 3 — implement** both functions (append).
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add lusha output formatters`

**Exit Criteria:**
- [ ] 2 output test functions pass (verify: `go test ./cmd/brutus/ -run TestOutputLusha -v`)
- [ ] DNC phone renders `DNC` marker (human) and `do_not_call:true` (JSONL) (asserted)
- [ ] No duplicate sanitizer (verify: `grep -c 'func sanitizeTerminal' cmd/brutus/*.go` returns 1)

**Dependencies:** T102. (Shared file with T003 — append-only, no overlap.)

---

## T104: Lusha command, flags, runEnumLusha, resolveLushaAPIKey, classifyLushaError, identity validation

**Files:**
- Create: `cmd/brutus/cmd_enum_lusha.go`
- Test: `cmd/brutus/cmd_enum_lusha_test.go` (extend)

**Implementation notes:**
- Mirror `cmd_enum_hunter.go:30-139`. File-local flags: `flagLushaFirstName`, `flagLushaLastName`,
  `flagLushaCompany`, `flagLushaDomain`, `flagLushaEmail`, `flagLushaLinkedin`, `flagLushaPhone`
  (bool), `flagLushaEmailOnly` (bool), `flagLushaAPIKey`.
- `enumLushaCmd` (`Use:"lusha"`, Short/Long/Example). Example shows each identity form (name+company,
  email, linkedin), `--phone`, and the **always-costs-credits** note + `--api-key` warning (P0-1d,
  exact warning string per `cmd_enum_hunter.go:61-62`) + prefer `LUSHA_API_KEY`.
- `init()`: declare flags; do NOT `MarkFlagRequired` (identity validated in Run).
- `validateLushaIdentity()` helper (architecture §9): exactly one of {name group | email | linkedin};
  name group requires first+last+exactly-one-of(company|domain); `--phone` and `--email-only`
  mutually exclusive. Return actionable errors. (Pure function on the flag values — testable without
  a server, per `preferring-simple-solutions`.)
- `runEnumLusha` (mirror `cmd_enum_hunter.go:68-113`): `validateLushaIdentity` → `resolveLushaAPIKey`
  → `setupOutputWriter` (set `flagJSON=true` if forceJSON) → `signal.NotifyContext` →
  **unconditional** stderr cost notice `[*] lusha enrichment consumes credits` when `!quiet && !json`
  → build `ContactQuery` + `RevealOptions` (default email; `--phone` adds phone; `--email-only`
  forces email-only) → `lusha.NewClient(key, flagTimeout)` → `Enrich(ctx, query, reveal)` →
  `classifyLushaError` on error → `outputLushaJSONL`/`outputLushaHuman`.
- `resolveLushaAPIKey(flagValue)`: flag, else `os.Getenv("LUSHA_API_KEY")`, else error mentioning
  `LUSHA_API_KEY`. Mirror `cmd_enum_hunter.go:117-125`.
- `classifyLushaError(err)`: switch `errors.Is` on Unauthorized/Forbidden/NoCredits/RateLimited/
  NotFound → actionable key-free messages; default wraps.

**Step 1 — failing test:** `TestValidateLushaIdentity` (table: valid name+company; valid
name+domain; valid email; valid linkedin; ERROR none set; ERROR two groups (email+linkedin); ERROR
name without last-name; ERROR name without company/domain; ERROR `--phone`+`--email-only` together).
`TestResolveLushaAPIKey` (flag wins; env fallback; error mentions `LUSHA_API_KEY`; `t.Setenv`).
`TestClassifyLushaError_NoKeyLeak` (sentinel-in-Details per security-assessment §2.1: each sentinel
+ a wrapped 500 with `Details:sentinelKey`; **all** assert `NotContains(out, sentinelKey)` AND
`NotContains(out, "api_key")` — P0-1). Pattern: `cmd_enum_hunter_test.go:33-113`.
**Step 2 — run, expect FAIL.**
**Step 3 — implement** the command file + validation helper.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): add lusha subcommand with identity validation`

**Exit Criteria:**
- [ ] `TestValidateLushaIdentity` (9 subtests incl. mutual-exclusion + incomplete name) pass (verify: `go test ./cmd/brutus/ -run TestValidateLushaIdentity -v`)
- [ ] `TestResolveLushaAPIKey` (3 subtests) + `TestClassifyLushaError_NoKeyLeak` (≥5 cases) pass; every error asserted NOT to contain the sentinel key or `api_key` (P0-1)
- [ ] `go vet ./cmd/brutus/` exit 0

**Dependencies:** T103.

---

## T105: Register lusha subcommand + update enum help text (SHARED FILE — see conflict rules)

**Files:**
- Modify: `cmd/brutus/cmd_enum.go` (`init()` AddCommand list ~line 111; `Long`/`Example`)
- Test: `cmd/brutus/cmd_enum_lusha_test.go` (extend)

**Implementation notes:**
- Add `enumCmd.AddCommand(enumLushaCmd)` on its **own line** after the existing AddCommand calls.
- Add a `lusha` line to the `Long` subcommand list, a `--help` hint, and one `Example` line (mirror
  hunter entries).
- **CONFLICT RULE:** shared file with T006. Own-line discipline; serialize with T006 (land one then
  the other; do not co-edit `cmd_enum.go` concurrently).

**Step 1 — failing test:** `TestEnumLushaRegistered` (mirror `cmd_enum_hunter_test.go:119-147`):
find `Use=="lusha"`; assert flags `--first-name`, `--last-name`, `--company`, `--domain`, `--email`,
`--linkedin`, `--phone`, `--email-only`, `--api-key` exist; `--domain` NOT required (cobra).
**Step 2 — run, expect FAIL.**
**Step 3 — implement** registration + help text.
**Step 4 — run, expect PASS.**
**Step 5 — commit:** `feat(enum): register lusha subcommand`

**Exit Criteria:**
- [ ] `TestEnumLushaRegistered` passes (verify: `go test ./cmd/brutus/ -run TestEnumLushaRegistered -v`)
- [ ] 9 flags asserted present
- [ ] `enumCmd` has exactly one `lusha` subcommand (asserted)

**Dependencies:** T104. (Shared file with T006 — serialize.)

---

## T200: Final verification gate (both tracks)

**Files:** none (verification only).

**Step 1 — build:** `go build ./...`
**Step 2 — vet:** `go vet ./...`
**Step 3 — full tests:** `go test ./pkg/enum/apollo/ ./pkg/enum/lusha/ ./cmd/brutus/`
**Step 4 — race:** `go test -race ./pkg/enum/apollo/ ./pkg/enum/lusha/`
**Step 5 — smoke (no creds):** `go run ./cmd/brutus enum apollo --help` shows all 5 flags + `--reveal`
credit warning; `go run ./cmd/brutus enum lusha --help` shows all 9 flags + always-costs-credits note.
**Step 6 — leak grep (P0-1/P0-1c):** `grep -rn 'apiKey\|X-Api-Key\|api_key\|httputil.Dump' pkg/enum/apollo/ pkg/enum/lusha/ cmd/brutus/cmd_enum_apollo.go cmd/brutus/cmd_enum_lusha.go` — manually confirm none feed a log/print/error sink and no request-dumping exists.
**Step 7 — DRY check:** `grep -c 'func sanitizeTerminal' cmd/brutus/*.go` returns 1; `grep -c 'func truncate' cmd/brutus/*.go` returns 1.

**Exit Criteria:**
- [ ] `go build ./...` exit 0
- [ ] `go vet ./...` exit 0
- [ ] `go test ./pkg/enum/apollo/ ./pkg/enum/lusha/ ./cmd/brutus/` exit 0, 0 failures
- [ ] `go test -race ./pkg/enum/apollo/ ./pkg/enum/lusha/` exit 0
- [ ] `enum apollo --help` lists 5 flags + `--reveal` credit warning; `enum lusha --help` lists 9 flags + credit note (verify: run both)
- [ ] Leak grep reviewed: neither API key reaches a log/print/error sink; no `httputil.Dump*` (P0-1/P0-1c manual confirmation)
- [ ] sanitizeTerminal/truncate defined exactly once each (DRY)

**Dependencies:** T006 + T105.

---

## Task Dependency Graph

```
Track A (Apollo, pkg/enum/apollo + cmd_enum_apollo*):
  T001 (types/errors) → T002 (client/do/search/match) → T003 (pagination/reveal/output) → T004 (command) → T006 (register*)

Track B (Lusha, pkg/enum/lusha + cmd_enum_lusha*):
  T101 (types/errors) → T102 (client/do/enrich) → T103 (output*) → T104 (command) → T105 (register*)

  T006* + T105*  →  T200 (final gate)
  (* shared cmd_enum.go — serialize T006/T105; T003/T103 share cmd_enum_output.go append-only)
```

## Security Checklist (verify across all tasks before done — see security-assessment.md)

- [ ] **P0-1:** Apollo `X-Api-Key` / Lusha `api_key` never logged. Asserted in T002/T102 (key set as
  header, not in URL; not in captured request log) and T004/T104 (sentinel-in-`APIError.Details`
  never surfaces in any classified error). Manual grep in T200.
- [ ] **P0-1b:** key held in unexported `apiKey` struct field, no JSON tag, no getter (T001/T101).
- [ ] **P0-1c:** NO `httputil.DumpRequest`/`DumpResponse` anywhere in `pkg/enum/apollo/` or
  `pkg/enum/lusha/` (header-based auth → dumping would capture the key). Grep-asserted T002/T102/T200.
- [ ] **P0-1d:** `--api-key` help carries the process-list/history warning; env var documented as
  preferred default (T004/T104).
- [ ] **P0-3:** every HTTP response read via `enum.ReadResponseBody(resp, 0)` (search, match, enrich).
  Code-reviewed in T002/T102; no raw `io.ReadAll(resp.Body)` in either package.
- [ ] **P0-4:** `sanitizeTerminal` applied to every API-sourced string in `outputApolloHuman` and
  `outputLushaHuman` (T003/T103). JSONL relies on `encoding/json` escaping.
- [ ] **P0-5:** 429 surfaced as `ErrRateLimited` with actionable message; NO silent auto-retry.
- [ ] **P0-6/P0-7 (cost rails):** Apollo `--reveal` opt-in, bounded by `--limit` (default 25) +
  stderr cost notice (T004); Lusha unconditional credit notice (T104).
- [ ] Sentinels static; `APIError.Details` carries only `resp.Status`/server-envelope text, never
  the request body or key.
- [ ] **P1-PII:** `-o` output file written `0o600` — already satisfied by `setupOutputWriter`
  (`flags.go:312`); no new file-writing code introduced.

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "integration-architecture",
  "timestamp": "2026-06-25",
  "feature_directory": "/Users/engineer/github/brutus/.worktrees/apollo-lusha-enum/.feature-development",
  "skills_invoked": ["using-skills", "focusing-on-the-goal", "enforcing-evidence-based-analysis", "preferring-simple-solutions", "adhering-to-dry", "adhering-to-yagni", "analyzing-with-adversarial-pov", "plan-write", "persisting-agent-outputs", "using-todowrite", "verifying-before-completion", "gateway-backend", "gateway-integrations"],
  "library_skills_read": [
    "/Users/engineer/.claude/plugins/cache/praetorian-ai-marketplace/engineering/1.38.17/skill-library/development/error-handling-patterns/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/enum/hunter/hunter.go:33-282",
    "pkg/enum/hunter/hunter_test.go:1-368",
    "cmd/brutus/cmd_enum_hunter.go:30-139",
    "cmd/brutus/cmd_enum_hunter_test.go:1-353",
    "cmd/brutus/cmd_enum_output.go:290-449",
    "cmd/brutus/cmd_enum.go:30-112",
    "cmd/brutus/flags.go:300-368",
    "pkg/enum/httpclient.go:1-65",
    "go.mod:1-32",
    ".feature-development/security-assessment.md:1-99"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "integration-developer",
    "context": "Execute Track A (T001-T004,T006) and Track B (T101-T105) in parallel; only cmd_enum.go (T006/T105) and cmd_enum_output.go (T003/T103) are shared — serialize cmd_enum.go edits, cmd_enum_output.go is append-only. TDD per task. Verify Apollo paths/fields and Lusha v3 schema against live docs/key (isolated in consts/structs); httptest tests pass regardless. Then T200 final gate."
  }
}
```
