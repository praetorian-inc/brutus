# Discovery — Apollo + Lusha HUMINT enum integrations

Phase 3–5 output. All internal references READ in this repo; all external API facts
sourced from live vendor docs (June 2026). Unverified API details are flagged so the
developer corrects them against a live key — they are isolated in consts/structs so a
single edit fixes a mismatch without touching control flow (the ZoomInfo mitigation).

## 1. Verified internal pattern (the template to mirror)

The repo already ships the **Hunter.io** integration (PR #160). Apollo/Lusha mirror it
exactly. Pattern = standalone client package + cobra subcommand + output helpers + tests.
This is NOT the `enum.Plugin` (email-exists oracle) interface used by microsoft365/google.

| Concern | Reference (verified) |
|---|---|
| Client struct + `NewClient(apiKey, timeout, …)` | `pkg/enum/hunter/hunter.go:99-118` |
| Sentinel errors + `APIError` + `Unwrap()` (status→sentinel) | `pkg/enum/hunter/hunter.go:33-37, 71-92` |
| Paginated `Search` loop (accumulate, advance, terminate empty/short/total, honor ctx) | `pkg/enum/hunter/hunter.go:122-162` |
| JSON structs unexported, map exactly to API; `toPerson` mapper | `pkg/enum/hunter/hunter.go:215-281` |
| Shared HTTP client (no-redirect, UA) + `ReadResponseBody` 1MB cap | `pkg/enum/httpclient.go:44-65` |
| Subcommand: flags, cobra cmd, `runEnumX`, `resolveXAPIKey`, `classifyXError` | `cmd/brutus/cmd_enum_hunter.go:30-139` |
| Command registration (`enumCmd.AddCommand`) + Long/Example text | `cmd/brutus/cmd_enum.go:107-121` |
| Output: `outputXHuman` (table, sanitized) + `outputXJSONL` (omitempty) | `cmd/brutus/cmd_enum_output.go:385-460` |
| Shared output helpers `sanitizeTerminal`, `truncate` (reuse as-is) | `cmd/brutus/cmd_enum_output.go:306-381` |
| CLI globals: `flagTimeout, flagJSON, flagOutputFile, flagNoColor, flagQuiet, flagVerbose` | `cmd/brutus/flags.go` |
| Helpers: `setupOutputWriter`, `isColorEnabled`, `logVerbose`, `dim`, `heading`, `colorIf`, `SymbolInfo` | `flags.go:308,361`; `output.go:114` |
| Test style: `httptest.NewServer` + testify, table-driven pagination, error-mapping, no-key-leak assertions | `pkg/enum/hunter/hunter_test.go`; `cmd/brutus/cmd_enum_hunter_test.go` |

### P0 security constraints (mandatory, from Hunter + ZoomInfo precedent)
- **P0-1** API key / token NEVER logged. `resolveXAPIKey` + `classifyXError` return only
  status-derived, key-free text. Verbose logs counts only. Unit test asserts the key never
  appears in any error string.
- **P0-3** Every HTTP body read via `enum.ReadResponseBody(resp, 0)` (1 MB cap) before decode.
- **P0-4** Every API-sourced string in human output wrapped in `sanitizeTerminal()` + `truncate()`.
  JSONL relies on `encoding/json` control-char escaping (no manual sanitize).

### go.mod / deps
`module github.com/praetorian-inc/brutus`, `go 1.26`. Tests: `testify` (assert/require) +
stdlib `net/http/httptest`. No new deps required (single API key each → no YAML creds file,
unlike ZoomInfo's two-secret PKI).

---

## 2. Apollo API contract (verified against docs.apollo.io, June 2026)

**Role:** sales-intelligence → org/domain people *discovery* + optional email *enrichment*.
Maps to the ZoomInfo free-search / paid-enrich gate.

### Auth
- Header `X-Api-Key: <master key>` (direct API-key method). `Authorization: Bearer` is
  ONLY for OAuth partner flows — not us. Isolate header name in one const.
- Env `APOLLO_API_KEY` + `--api-key` flag (warning: visible in process list/history).

### Discovery — People Search (FREE, no PII)
- `POST https://api.apollo.io/api/v1/mixed_people/api_search`
- Body: `q_organization_domains_list[]` (array of domains, ≤1000), optional `person_titles[]`,
  `page`, `per_page` (≤100). **Does NOT consume credits. Does NOT return email/phone.**
- Pagination: `page`/`per_page`, max 100/page × 500 pages = 50k cap; response has
  `pagination: {page, per_page, total_entries, total_pages}` and a `people[]` array.
- Person fields (free): `id, first_name, last_name, name, title, seniority, departments[],
  organization{name,…}`. Email field present but masked/absent at this tier.

### Enrichment — People Match (CREDITS, PII) — opt-in via `--reveal`
- `POST https://api.apollo.io/api/v1/people/match`
- Body: `id` (from search) OR `first_name`+`last_name`+`domain`/`organization_name`,
  plus `reveal_personal_emails: true`. Returns synchronously: `person{email, email_status,
  name, title, organization, …}`.
- **⚠ `reveal_phone_number` requires a `webhook_url`** — phones are delivered ASYNC via
  webhook, NOT in the response. A CLI cannot receive webhooks. → **Apollo v1 reveals EMAILS
  ONLY** (`reveal_personal_emails`). Phone is explicitly out of scope (documented). 

### Errors: 401 (unauth), 403 (forbidden/plan), 422 (bad params), 429 (rate limit). Map
401→ErrUnauthorized, 429→ErrRateLimited, 403→ErrForbidden, 422→ErrBadRequest.

---

## 3. Lusha API contract (verified against docs.lusha.com, June 2026)

**Role:** contact enrichment (email + phone) for *individuals*. Input = a person identity.

### ⚠ Version decision: TARGET v3, NOT v2
- v2 (`GET /v2/person`) is **sunsetting 2026-11-18**; emits `Sunset` header since 2026-05-18
  (already active). Docs explicitly recommend **v3 for new integrations** (cheaper search,
  stable IDs). Building on v2 would ship deprecated-on-arrival.
- v3 contact enrich: `POST https://api.lusha.com/v3/contacts/search-and-enrich`
  (single call: provide identifiers → enriched contact). Also `POST /v3/contacts/enrich`
  (by `contactId` from a prior search).

### Auth
- Header `api_key: <key>`. Env `LUSHA_API_KEY` + `--api-key` flag (warning).

### Request identifiers (mutually-exclusive identity, choose one)
- `firstName`+`lastName`+(`companyName` OR `companyDomain`), OR `email`, OR `linkedinUrl`.
- A `reveal` control selects email vs phone vs company data (charged per revealed field).

### Response (field names UNVERIFIED — isolate in structs, flag for live check)
- `emailAddresses[]` {email/address, type (personal|business), confidence}
- `phoneNumbers[]` {number, type, doNotCall (DNC) flag}
- name, jobTitle, company.
- Billing: charged per revealed datapoint. Rate-limit headers: `x-rate-limit-daily`,
  `x-daily-requests-left` (read for `--verbose` only, not flow control).

### Errors: 401, 403, 429, plus per-datapoint billing/quota → map to
ErrUnauthorized / ErrForbidden / ErrRateLimited (+ ErrNoCredits if a 402/quota code appears).

---

## 4. Recommended design decisions (for lead review)

1. **Two independent subcommands**, no shared abstraction beyond existing helpers
   (Rule of Three not met — Hunter+Apollo+Lusha differ in shape; do NOT prematurely extract
   a "HUMINT provider" interface). KISS.
2. **Apollo = `brutus enum apollo --domain <d> [--titles ...] [--reveal] [--limit N]`** —
   single command, `--reveal` is the credit gate (mirrors ZoomInfo `--enrich`): default lists
   people (name/title/dept, masked email); `--reveal` calls people/match per discovered id to
   unlock emails (credits). Emails only (no phone webhook). Stderr cost notice when `--reveal`.
3. **Lusha = `brutus enum lusha`** with mutually-exclusive identity flags
   (`--first-name/--last-name`+`--company`/`--domain`, OR `--email`, OR `--linkedin`).
   v3 `search-and-enrich`. Enrichment always costs credits (that's the command's purpose) →
   stderr cost notice, no separate gate flag. Optional `--phone`/`--email-only` reveal toggles.
4. **Single API key each** → mirror Hunter's `resolveXAPIKey(flag) → env`. No creds file.
5. **Sentinels + APIError.Unwrap** per service; `classifyXError` produces key-free messages;
   no auto-retry on 429 (matches Hunter).
6. **Out of scope (YAGNI):** Apollo phone (webhook), Lusha bulk file/stdin enrichment,
   Apollo org-enrich endpoint, ToS-gated auto-throttling. Note as future extensions.

## 5. Open questions deferred to leads / Phase 7 checkpoint
- Apollo `--reveal`: enrich ALL discovered people or only first N (`--limit`/`--reveal-limit`)?
  (cost footgun — recommend `--limit` default 25, cap reveal spend.)
- Lusha batch: confirm v1 is single-identity only (recommended) vs. stdin identity list.
- Confirm v3 over v2 is acceptable given exact v3 schema needs live-key verification.
