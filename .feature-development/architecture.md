# Apollo + Lusha HUMINT enum integrations — Technical Architecture

**Feature:** Two new standalone enum subcommands:
- `brutus enum apollo` — domain → people *discovery* (free) + opt-in `--reveal` email *enrichment* (credits).
- `brutus enum lusha` — single-identity contact *enrichment* (email + phone, credits) via Lusha v3.

**Goal:** Add two independent enum subcommands that mirror the verified Hunter.io pattern
(`pkg/enum/hunter/`, `cmd/brutus/cmd_enum_hunter*.go`). Apollo discovers people for a company
domain and optionally reveals emails for a bounded set. Lusha enriches one person identity.

**Status:** Architecture plan (no code written). Implements the Hunter pattern; ZoomInfo
(`.worktrees/zoominfo-enum/`) is a structural sibling consulted only for detail-level — none of
its content is copied (different APIs, different shapes).

**Scope lock (from task):** Apollo + Lusha only. Hunter shipped (out of scope). ZoomInfo out of
scope. Apollo = emails only (phone requires an async `webhook_url`, impossible for a CLI). Lusha =
v3 only (v2 sunsets 2026-11-18). Single API key per service (no YAML creds file).

---

## 0. Evidence Base (Verified internal APIs)

All design below references code READ in this worktree. No assumptions about internal APIs.
External Apollo/Lusha facts are from `discovery.md` (live vendor docs, June 2026); fields not
confirmable without a live key are isolated and flagged in the Assumptions tables (§7, §11).

### Reference: Hunter client structure
**Source:** `pkg/enum/hunter/hunter.go:98-118`
```go
type Client struct {
    apiKey     string
    httpClient *http.Client
    baseURL    string
    pageSize   int
}
func NewClient(apiKey string, timeout time.Duration, pageSize int) *Client {
    if pageSize <= 0 { pageSize = defaultPageSize }
    return &Client{
        apiKey:     apiKey,
        httpClient: enum.NewEnumHTTPClient(timeout),
        baseURL:    defaultBaseURL,
        pageSize:   pageSize,
    }
}
```

### Reference: Sentinel errors + APIError.Unwrap (status → sentinel)
**Source:** `pkg/enum/hunter/hunter.go:33-37, 70-92`
```go
var (
    ErrUnauthorized = errors.New("invalid or missing API key")
    ErrRateLimited  = errors.New("rate limit exceeded")
    ErrLegalReasons = errors.New("unavailable for legal reasons")
)
type APIError struct { StatusCode int; Details string }
func (e *APIError) Error() string { return fmt.Sprintf("hunter API error (HTTP %d): %s", ...) }
func (e *APIError) Unwrap() error {
    switch e.StatusCode {
    case http.StatusUnauthorized:    return ErrUnauthorized
    case http.StatusTooManyRequests: return ErrRateLimited
    case http.StatusUnavailableForLegalReasons: return ErrLegalReasons
    }
    return nil
}
```
**Contract note:** `Unwrap()` maps status → sentinel; the `*APIError` itself is still retrievable
via `errors.As`. I mirror this per service (Apollo: 401/403/422/429; Lusha: 401/403/402/429).

### Reference: Paginated Search loop (accumulate, advance, terminate, honor ctx)
**Source:** `pkg/enum/hunter/hunter.go:122-162` — loop fetches a page, accumulates, advances the
offset by the returned count, terminates on empty page / short final page / reached known total,
and checks `ctx.Err()` between requests. Apollo mirrors this (paging by `page`/`per_page` instead
of `offset`/`limit`; same termination logic).

### Reference: GET + query-string request + bounded read + error mapping
**Source:** `pkg/enum/hunter/hunter.go:171-213` — `fetchPage` builds the request, calls
`c.httpClient.Do`, `defer resp.Body.Close()`, reads via `enum.ReadResponseBody(resp, 0)` (P0-3),
maps non-200 → `*APIError` (extracting details from the error envelope if present, else
`resp.Status`), then `json.Unmarshal`. Apollo/Lusha use **POST with a JSON body + header auth**
instead of GET + query-string key, but the body-read / error-map / decode sequence is identical.

### Reference: Shared HTTP utilities (verified — reuse, no new client)
**Source:** `pkg/enum/httpclient.go:44-65`
```go
func NewEnumHTTPClient(timeout time.Duration) *http.Client { ... } // no-redirect, default UA
func ReadResponseBody(resp *http.Response, limit int64) ([]byte, error) { // 0 => 1 MB cap
    if limit <= 0 { limit = maxResponseBody } // maxResponseBody = 1<<20
    return io.ReadAll(io.LimitReader(resp.Body, limit))
}
```

### Reference: CLI subcommand wiring
**Source:** `cmd/brutus/cmd_enum_hunter.go:30-139` and `cmd/brutus/cmd_enum.go:99-112`
- Subcommand registered via `enumCmd.AddCommand(enumHunterCmd)` inside `cmd_enum.go`'s `init()`
  (the call list is at `cmd_enum.go:106-111`).
- File-local flag vars (`flagHunterDomain` etc.) declared in the command file to avoid
  cross-command state bleed (`cmd_enum_hunter.go:32-36`).
- Run flow (`cmd_enum_hunter.go:68-113`): validate → `resolveHunterAPIKey` → `setupOutputWriter`
  (set `flagJSON=true` if `forceJSON`) → `signal.NotifyContext(... os.Interrupt, SIGTERM)` →
  stderr progress if `!quiet && !json` → `NewClient` → `client.Search` → `classifyHunterError` on
  error → `outputHunterJSONL`/`outputHunterHuman`.
- `resolveHunterAPIKey(flagValue)` returns flag value, else `os.Getenv("HUNTER_API_KEY")`, else
  error (`cmd_enum_hunter.go:117-125`). `classifyHunterError` maps sentinels → key-free actionable
  messages (`cmd_enum_hunter.go:128-139`).

### Reference: Output helpers + shared sanitizers (reuse as-is — DRY)
**Source:** `cmd/brutus/cmd_enum_output.go:294-356` (`outputHunterHuman`/`outputHunterJSONL`),
and shared `sanitizeTerminal`/`truncate` used there (same file, package-level). JSONL uses a local
anonymous struct with `omitempty` and `encoding/json` for control-char escaping (no manual
sanitize). Human output wraps every API string in `sanitizeTerminal(...)` then `truncate(...)`.

### Reference: Shared CLI globals + helpers (all verified present)
**Source:** `cmd/brutus/flags.go:307-317, 360-363` and `cmd/brutus/cmd_enum_hunter.go:69,80-95,104`
- Globals: `flagTimeout time.Duration`, `flagJSON bool`, `flagOutputFile string`,
  `flagNoColor bool`, `flagQuiet bool`, `flagVerbose bool`.
- Helpers: `setupOutputWriter(string) (io.Writer, bool, func(), error)` (`flags.go:308`),
  `isColorEnabled(bool) bool` (`flags.go:361`), `logVerbose(verbose bool, format string, ...any)`,
  `dim`, `heading`, `colorIf`, `SymbolInfo`, plus `sanitizeTerminal`/`truncate`
  (`cmd_enum_output.go`). All reused as-is.

### Reference: go.mod
**Source:** `go.mod:1-3, 29-31` — `module github.com/praetorian-inc/brutus`, `go 1.26`.
`golang.org/x/sync` (errgroup) and `golang.org/x/time` (rate) are already present (lines 29-30)
but **not needed** (serial requests — see §6). `gopkg.in/yaml.v3` present but **not used** (single
API key each, no creds file). Test deps: `testify` (assert/require) + stdlib `net/http/httptest`.

---

## 1. Design philosophy — two independent commands, no shared abstraction

**Decision: build Apollo and Lusha as two fully independent packages + commands, reusing only the
existing shared helpers. Do NOT introduce a "HUMINT provider" interface.**

Chain-of-thought (KISS / DRY Rule-of-Three):
- We now have three HUMINT-ish integrations (Hunter, Apollo, Lusha). Rule of Three *appears* met —
  but DRY's "coincidental similarity" caveat applies: they differ in **shape**, not just values.
  - Hunter: GET, query-string key, domain→emails, single phase.
  - Apollo: POST + `X-Api-Key` header, domain→people discovery (free) then per-person email
    reveal (credits) — **two phases**.
  - Lusha: POST + `api_key` header, **single identity in → one enriched contact out** — no
    pagination, no domain, mutually-exclusive identity inputs.
- A shared `Provider` interface would have to be the union of "paginated domain search",
  "per-id enrich", and "single-identity enrich" — a leaky abstraction that every implementer
  partially ignores. That is premature abstraction (the exact anti-pattern in
  `preferring-simple-solutions` §1).
- What they genuinely share is already extracted: `enum.NewEnumHTTPClient`, `enum.ReadResponseBody`,
  `sanitizeTerminal`, `truncate`, the CLI globals/helpers, and the `APIError`+`Unwrap` *pattern*
  (a pattern to copy, not a type to share). Each package gets its own sentinels + `APIError`
  (different status sets) — copying ~20 lines is cheaper and clearer than a shared error type that
  must enumerate every service's statuses.

**Self-consistency check:** would I extract a shared client if a 4th identical-shape provider
arrived? Yes — but only when a real third *same-shape* case exists. Today they diverge. Holds.

---

## 2. Apollo — package `pkg/enum/apollo/apollo.go`

### 2.1 Client struct
Mirror Hunter's struct. `pageSize` is a real tuning knob (people-search `per_page`, ≤100), so it
stays in the struct exactly as Hunter does (`hunter.go:98-104`).

```go
type Client struct {
    apiKey     string        // X-Api-Key — NEVER logged (P0-1)
    httpClient *http.Client
    baseURL    string        // default "https://api.apollo.io" (UNVERIFIED-safe: host only)
    pageSize   int           // people-search per_page; <=0 => defaultPageSize (100)
}

func NewClient(apiKey string, timeout time.Duration, pageSize int) *Client {
    if pageSize <= 0 { pageSize = defaultPageSize }
    return &Client{
        apiKey:     apiKey,
        httpClient: enum.NewEnumHTTPClient(timeout),
        baseURL:    defaultBaseURL,
        pageSize:   pageSize,
    }
}
```

### 2.2 Public API surface (two phases, single command)
```go
// Phase 1 (FREE, no PII): paginate people-search for a domain. Emails are masked/absent here.
func (c *Client) SearchPeople(ctx context.Context, domain string, titles []string, limit int) (*DomainResult, error)

// Phase 2 (CREDITS): reveal emails for the already-discovered people, in place, by id.
// Called only when --reveal is set. Operates on result.People from SearchPeople.
func (c *Client) RevealEmails(ctx context.Context, result *DomainResult) error
```

`RevealEmails` mutates `result.People` (sets `Email`, `EmailStatus`, `Revealed=true`) and sets
`result.Revealed=true` if any reveal ran — mirroring ZoomInfo's two-tier `Contact.Enriched`
correctness rail so a consumer never misreads an un-revealed blank email as "no email on file".

### 2.3 Public types
```go
type Person struct {
    // --- From /mixed_people/api_search (FREE, no PII) ---
    ID         string   // Apollo person id — required for reveal
    FirstName  string
    LastName   string
    Name       string   // full name as Apollo returns it
    Title      string
    Seniority  string
    Department string   // first of departments[] (see §7 assumption)
    Organization string // organization.name

    // --- From /people/match (CREDITS, PII) — empty unless --reveal ---
    Email       string
    EmailStatus string  // e.g. "verified" / "guessed" (UNVERIFIED field name; §7)
    Revealed    bool    // true if this person went through reveal
}

type DomainResult struct {
    Domain   string
    People   []Person
    Total    int   // pagination.total_entries
    Revealed bool  // true if RevealEmails ran (any credits spent)
}
```

### 2.4 SearchPeople pagination (mirror Hunter loop, page-based)
**Decision: mirror `hunter.go:122-162` exactly, paging by `page`/`per_page` and bounding total by
`--limit` (the credit-relevant number for a subsequent reveal).**

```go
func (c *Client) SearchPeople(ctx context.Context, domain string, titles []string, limit int) (*DomainResult, error) {
    result := &DomainResult{Domain: domain}
    page := 1
    for {
        people, total, err := c.searchPage(ctx, domain, titles, page)
        if err != nil { return nil, err }
        if page == 1 { result.Total = total }

        result.People = append(result.People, people...)

        fetched := len(people)
        if fetched == 0 { break }                                    // empty page
        if limit > 0 && len(result.People) >= limit {                // user cap (truncate)
            result.People = result.People[:limit]
            break
        }
        if fetched < c.pageSize { break }                            // short final page
        if result.Total > 0 && len(result.People) >= result.Total { break } // known total
        if page >= maxPages { break }                                // hard safety cap
        if err := ctx.Err(); err != nil { return nil, err }          // cancellation
        page++
    }
    return result, nil
}
```
`maxPages` is a hard safety cap (const `maxPages = 500`; Apollo's free people-search documents a
100/page × 500-page = 50k ceiling — see discovery §2). The `limit > 0` truncation is the normal
bound; `maxPages` is belt-and-suspenders against an API that never returns a short page.

### 2.5 RevealEmails (per-person, serial, bounded by --limit)
**Decision: `/people/match` is one call per person (it matches a single identity). Loop the
discovered people serially, calling match with `id` + `reveal_personal_emails: true`, merge the
returned email back by id. NO phone (`reveal_phone_number` needs a `webhook_url` — out of scope,
documented in §11). Spend is bounded because we only reveal `result.People`, which `SearchPeople`
already capped at `--limit`.**

```go
func (c *Client) RevealEmails(ctx context.Context, result *DomainResult) error {
    for i := range result.People {
        p := &result.People[i]
        if p.ID == "" { continue } // can't match without an id
        email, status, err := c.matchPerson(ctx, p.ID)
        if err != nil { return err } // surface first error (mirrors Hunter: no partial swallow)
        p.Email, p.EmailStatus, p.Revealed = email, status, true
        if err := ctx.Err(); err != nil { return err }
    }
    if len(result.People) > 0 { result.Revealed = true }
    return nil
}
```
Serial (no goroutines) — see §6. `matchPerson` returns empty email + `Revealed=true` when Apollo
has no email for that id (requested, none returned) — same partial-result honesty as ZoomInfo.

### 2.6 Sentinels + error mapping (Apollo)
```go
var (
    ErrUnauthorized = errors.New("invalid or missing Apollo API key") // 401
    ErrForbidden    = errors.New("access forbidden (plan or permissions)") // 403
    ErrBadRequest   = errors.New("invalid request parameters")        // 422
    ErrRateLimited  = errors.New("rate limit exceeded")               // 429
)
// APIError.Unwrap: 401→Unauthorized, 403→Forbidden, 422→BadRequest, 429→RateLimited, else nil.
```

---

## 3. Lusha — package `pkg/enum/lusha/lusha.go`

### 3.1 Client struct (simplest — no pagination, no page size)
**Decision: minimal struct. No `pageSize` (single identity → single contact, no pagination). This
is the `preferring-simple-solutions` ladder applied: Lusha needs state (apiKey + http client +
baseURL) → struct (level 4), but nothing more.**

```go
type Client struct {
    apiKey     string        // api_key header — NEVER logged (P0-1)
    httpClient *http.Client
    baseURL    string        // default "https://api.lusha.com"
}

func NewClient(apiKey string, timeout time.Duration) *Client {
    return &Client{
        apiKey:     apiKey,
        httpClient: enum.NewEnumHTTPClient(timeout),
        baseURL:    defaultBaseURL,
    }
}
```

### 3.2 Public API surface (single call)
```go
// Enrich resolves one identity to an enriched contact via v3 search-and-enrich (CREDITS).
// query carries exactly one identity (validated by the caller — see §3.4).
func (c *Client) Enrich(ctx context.Context, query ContactQuery, reveal RevealOptions) (*Contact, error)
```

### 3.3 Public types
```go
type ContactQuery struct {
    // Exactly one identity set is used (mutually exclusive — validated at the CLI layer).
    FirstName   string
    LastName    string
    CompanyName string // pairs with FirstName+LastName
    CompanyDomain string // alternative to CompanyName
    Email       string
    LinkedinURL string
}

type RevealOptions struct {
    Email bool // request email datapoints
    Phone bool // request phone datapoints
}

type EmailEntry struct {
    Address    string // UNVERIFIED: "email" vs "address" (§11)
    Type       string // personal | business
    Confidence string // UNVERIFIED shape
}
type PhoneEntry struct {
    Number    string
    Type      string
    DoNotCall bool   // DNC flag — surface in output (compliance signal)
}
type Contact struct {
    Name     string
    JobTitle string
    Company  string
    Emails   []EmailEntry
    Phones   []PhoneEntry
}
```

### 3.4 Enrich flow (single POST, v3)
```go
func (c *Client) Enrich(ctx context.Context, q ContactQuery, r RevealOptions) (*Contact, error) {
    body := buildEnrichRequest(q, r) // maps identity + reveal flags to the v3 request shape (§11)
    raw, err := c.do(ctx, http.MethodPost, enrichPath, body) // enrichPath = "/v3/contacts/search-and-enrich"
    if err != nil { return nil, err }
    var resp enrichResponse
    if err := json.Unmarshal(raw, &resp); err != nil {
        return nil, fmt.Errorf("decoding lusha response: %w", err)
    }
    return toContact(&resp), nil
}
```
`do` is the single P0-1/P0-3 choke point: sets `api_key` header, JSON-encodes body, reads via
`enum.ReadResponseBody(resp, 0)`, maps non-2xx → `*APIError`, never logs the key or body.

**Empty-match handling:** if v3 returns 200 with no contact / no datapoints, `Enrich` returns a
`*Contact` with empty slices (not an error) — the CLI prints "no contact data returned". A 404 (if
Lusha uses it for no-match) maps to a `ErrNotFound` sentinel; flagged UNVERIFIED in §11.

### 3.5 Sentinels + error mapping (Lusha)
```go
var (
    ErrUnauthorized = errors.New("invalid or missing Lusha API key") // 401
    ErrForbidden    = errors.New("access forbidden")                 // 403
    ErrNoCredits    = errors.New("insufficient Lusha credits")       // 402 / quota code (§11)
    ErrRateLimited  = errors.New("rate limit exceeded")              // 429
)
// APIError.Unwrap: 401→Unauthorized, 403→Forbidden, 402→NoCredits, 429→RateLimited, else nil.
```

---

## 4. Auth flow (both services)

| | Apollo | Lusha |
|---|---|---|
| Pattern | API key in request **header** | API key in request **header** |
| Header name | `X-Api-Key: <key>` (isolate in one const) | `api_key: <key>` (isolate in one const) |
| Env var | `APOLLO_API_KEY` | `LUSHA_API_KEY` |
| Flag | `--api-key` (warning: visible in process list/history) | `--api-key` (same warning) |
| Resolution | `resolveApolloAPIKey(flag)` → flag, else env, else error | `resolveLushaAPIKey(flag)` → flag, else env, else error |
| ValidateCredentials | No separate ping — first real API call surfaces 401 → `ErrUnauthorized` via `classifyXError`. Matches Hunter (no validate endpoint). | Same. |

Both resolvers mirror `resolveHunterAPIKey` (`cmd_enum_hunter.go:117-125`) exactly. **No YAML creds
file** — single secret each (the task locks this; ZoomInfo's `--credentials-file` was for its
two-secret PKI, which does not apply).

**Decision — no auth-only validate endpoint.** Apollo/Lusha have no documented lightweight
"whoami". Adding a probe call would spend a request (and possibly a credit) for no benefit; the
first real call returns 401 just as fast. Matches Hunter. (YAGNI.)

---

## 5. Pagination strategy

| Service | Strategy | maxPages | Parallel fetch |
|---|---|---|---|
| Apollo | **Page-based** (`page`/`per_page`, 1-based), mirror Hunter loop | `500` (const; API's documented 50k/100 ceiling) | **No** (serial — §6) |
| Lusha | **None** — single identity → single contact | n/a | n/a |

Apollo termination order (matches Hunter `hunter.go:144-158`): empty page → `--limit` truncation →
short final page → known `total_entries` → `maxPages` cap → `ctx.Err()`.

---

## 6. Concurrency / rate-limiting strategy

**Decision: serial requests for both. No errgroup, no `golang.org/x/time/rate` limiter, no
auto-retry on 429.**

Chain-of-thought:
- Apollo's reveal loop is the only place concurrency could apply (N independent `/people/match`
  calls). But: (1) Hunter and the ZoomInfo sibling are both serial — consistency; (2) the loop is
  bounded by `--limit` (default 25), so wall-clock cost is small; (3) Apollo rate-limits per
  minute/hour/day — firing 25 concurrent matches is the *fastest* way to trip a 429. Serial issue
  is self-throttling and predictable. Adding `errgroup` + a `rate.Limiter` is unrequested
  complexity (YAGNI) for a 25-item loop.
- Lusha is a single call — nothing to parallelize.
- **429 handling:** map to `ErrRateLimited` via `APIError.Unwrap`, surface via `classifyXError`
  with an actionable message ("wait and retry, or lower --limit"). **No automatic retry/backoff** —
  Hunter doesn't retry (the task's pattern of record), and silent multi-second hangs would surprise
  a CLI user. Documented as a future extension.
- **Rate-limit headers** (`x-rate-limit-daily` / `x-daily-requests-left` for Lusha; Apollo's
  `x-rate-limit-*`): read opportunistically for the `--verbose` log line only, never for flow
  control. (YAGNI — header-driven throttling is a real but unrequested feature.)

**Self-consistency check:** would I add a limiter if the reveal cap were 10k? Yes — but the cap is
25 by design (the cost rail, §8). At 25 serial calls a limiter is pure overhead. Holds.

---

## 7. Apollo data-model mapping + Assumptions

| Apollo entity (external) | Tabularium-equivalent role | brutus type | Key fields |
|---|---|---|---|
| `people[]` (search) | person/contact discovery | `apollo.Person` (free tier) | `id, first_name, last_name, name, title, seniority, departments[], organization.name` |
| `person` (match) | enriched contact (PII) | `apollo.Person` (reveal tier) | `email, email_status` |

> This is a standalone enum CLI (people/email discovery), **not** the Chariot asset/risk ingestion
> pipeline. There is no `Job.Send`, no `VMFilter`, no `CheckAffiliation` — those P0s belong to
> Chariot *integrations*, not `brutus enum` subcommands (confirmed: Hunter, the pattern of record,
> has none of them). The applicable P0s here are the enum-CLI security P0s (P0-1/P0-3/P0-4, §10).

### Apollo Assumptions (NOT verified against a live key — isolate, flag for developer)
| Assumption | Why unverified | Risk if wrong | Isolation |
|---|---|---|---|
| Search path `POST /api/v1/mixed_people/api_search`; match path `POST /api/v1/people/match` | No live Apollo key in repo (docs-derived, discovery §2) | 404 / wrong endpoint | `const searchPath`, `const matchPath` — one edit each |
| Request fields `q_organization_domains_list[]`, `person_titles[]`, `page`, `per_page`, `reveal_personal_emails` | docs-derived | Bad params → 422 | unexported request structs in `apollo_types.go` |
| Response: `people[]`, `pagination.{total_entries,total_pages,page,per_page}`, `person.email`, `person.email_status`, `organization.name`, `departments[]` (array; take first) | docs-derived | Decode yields zero values / wrong pagination | unexported response structs; `toPerson` mapper |
| Auth header literal `X-Api-Key` | docs-derived | 401 | `const headerAPIKey = "X-Api-Key"` |
| `email_status` field name + values | docs-derived | Cosmetic (status label blank) | field in `apolloPerson` struct |

**These are intentionally isolated** behind unexported consts + JSON structs so the developer
corrects each against the live API/docs with a single edit, without touching control flow (the
ZoomInfo mitigation). `httptest`-based tests use controlled payloads and pass regardless.

---

## 8. Apollo `--reveal` cost rail (resolves open question §5.1)

**Decision: `--reveal` enriches ONLY the people the command returns, and that set is bounded by
`--limit` (default 25). `--limit` IS the reveal-spend cap.**

Chain-of-thought (the documented cost footgun):
- `/people/match` consumes credits per call. Domain search can yield up to 50k people. Revealing
  all of them on a single flag would drain an account on one typo.
- **Option A — reveal all discovered.** Maximally useful, catastrophic spend. Rejected.
- **Option B (CHOSEN) — reveal only `result.People`, capped by `--limit` (default 25).** A single
  accidental `--reveal` costs at most 25 credits. The user raises `--limit` deliberately to reveal
  more — explicit consent scales with spend. Mirrors ZoomInfo's `--enrich` + `--limit` rail.
- **Cost notice:** when `--reveal` is set and `!quiet && !json`, print to **stderr** before
  spending: `[*] --reveal will consume Apollo credits for N people` (N = `len(result.People)`).
  No interactive prompt (would break scripting/`--json`); the explicit `--reveal` flag is consent.
  Mirrors Hunter's stderr progress line (`cmd_enum_hunter.go:92-95`).

**Self-consistency check:** is default 25 right? Hunter's `--limit` default is 100 (page size,
free). ZoomInfo's is 100 (contacts cap). Apollo's `--limit` here bounds *credit-spending* reveals,
so a smaller, safer default (25) is correct — large enough to be useful, small enough that an
accidental reveal is cheap. Holds. (Without `--reveal`, `--limit` still caps the free people list;
25 free results is a fine default and a one-flag bump raises it.)

---

## 9. CLI design

### Apollo — `brutus enum apollo`
File-local flags in `cmd/brutus/cmd_enum_apollo.go` (mirror `cmd_enum_hunter.go:32-65`). Reuses
globals `--timeout`, `--json`, `--output/-o`, `--no-color`, `--quiet/-q`, `--verbose/-v`.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--domain` / `-d` | string | "" | Company domain to discover people for (required). |
| `--titles` | []string | nil | Optional `person_titles[]` filter (repeatable / comma-sep via `StringSliceVar`). |
| `--reveal` | bool | false | Opt-in email enrichment via `/people/match`. **Consumes credits.** |
| `--limit` | int | 25 | Max people to return AND max to reveal. Bounds credit spend. 0 = no cap (free list only; with `--reveal` 0 is treated as unbounded — guard with cost notice). |
| `--api-key` | string | "" | Overrides `APOLLO_API_KEY`. WARNING in help: visible in process list/shell history; prefer the env var. |

`runEnumApollo` (mirror `cmd_enum_hunter.go:68-113`): require `--domain` → `resolveApolloAPIKey` →
`setupOutputWriter` (set `flagJSON=true` if forceJSON) → `signal.NotifyContext` → stderr progress
if `!quiet && !json` → `NewClient(key, flagTimeout, perPageFromLimit)` → `SearchPeople(ctx, domain,
titles, limit)` → if `--reveal`: stderr cost notice then `RevealEmails(ctx, result)` →
`classifyApolloError` on any error → `outputApolloJSONL`/`outputApolloHuman`.

> Note on `--limit` vs page size: pass `min(limit, 100)` (or `defaultPageSize` when `limit==0`) as
> the `NewClient` pageSize so we never request a `per_page` above Apollo's 100 max; `--limit`
> separately bounds the accumulated total inside `SearchPeople`. (Distinct knobs, like ZoomInfo §1.)

### Lusha — `brutus enum lusha`
File-local flags in `cmd/brutus/cmd_enum_lusha.go`. Reuses the same globals.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--first-name` | string | "" | With `--last-name` + (`--company` or `--domain`). |
| `--last-name` | string | "" | Pairs with `--first-name`. |
| `--company` | string | "" | Company name (with name pair). |
| `--domain` | string | "" | Company domain (alternative to `--company`). |
| `--email` | string | "" | Enrich by email (mutually exclusive identity). |
| `--linkedin` | string | "" | Enrich by LinkedIn URL (mutually exclusive identity). |
| `--phone` | bool | false | Request phone datapoints (in addition to email). |
| `--email-only` | bool | false | Request only email (suppress phone). Mutually exclusive with `--phone`. |
| `--api-key` | string | "" | Overrides `LUSHA_API_KEY`. Same process-list/history WARNING. |

**Identity validation (`runEnumLusha`)** — exactly one identity group must be set:
1. name group: `--first-name` + `--last-name` + exactly one of (`--company` | `--domain`), OR
2. `--email`, OR
3. `--linkedin`.

Setting more than one group, or an incomplete name group (e.g. `--first-name` without
`--last-name`, or name without company/domain), is an error with an actionable message. **No
default reveal both** — default requests email; `--phone` adds phone; `--email-only` is the
explicit email-only form (and conflicts with `--phone`). Enrichment **always** costs credits
(that's the command's purpose) → unconditional stderr cost notice when `!quiet && !json`
(`[*] lusha enrichment consumes credits`), no separate gate flag (matches discovery §4.3).

Run flow mirrors Hunter: validate identity → `resolveLushaAPIKey` → `setupOutputWriter` →
`signal.NotifyContext` → cost notice → `NewClient(key, flagTimeout)` → `Enrich(ctx, query, reveal)`
→ `classifyLushaError` → `outputLushaJSONL`/`outputLushaHuman`.

### Output (both — mirror Hunter, reuse sanitizers)
Two functions per service appended to `cmd/brutus/cmd_enum_output.go`, mirroring
`outputHunterHuman`/`outputHunterJSONL` (`cmd_enum_output.go:294-356`). **Reuse `sanitizeTerminal`
and `truncate` as-is** (package-level, same file — DRY, no new copies; a test asserts
`grep -c 'func sanitizeTerminal'` stays 1).

- **`outputApolloHuman`:** header `Apollo: <sanitized domain>`, `People found: N (total: M)`; dim
  preview note when `!result.Revealed` (`(preview — run with --reveal for emails; consumes
  credits)`); columns adapt: preview `Name | Title | Dept | Org`, revealed `+ Email | Status`;
  every API string `sanitizeTerminal`+`truncate` (P0-4); empty → `No people found for this domain`.
- **`outputApolloJSONL`:** local struct, `type:"apollo"`, always `domain`+`revealed`+`id`;
  `omitempty` on name/title/dept/org/email/email_status so preview JSONL never emits a misleading
  `"email":""`.
- **`outputLushaHuman`:** header `Lusha: <sanitized identity summary>`; rows for each email
  (`address | type | confidence`) and phone (`number | type | DNC`); DNC flag rendered explicitly
  (`DNC` marker) so the operator sees do-not-call compliance status; empty → `No contact data
  returned`. All strings `sanitizeTerminal`+`truncate` (P0-4).
- **`outputLushaJSONL`:** local struct, `type:"lusha"`, `name/job_title/company` (`omitempty`),
  `emails[]` and `phones[]` arrays (each with `do_not_call` bool for phones), `omitempty` on the
  arrays.

---

## 10. P0 security mapping

| Constraint | Apollo | Lusha |
|---|---|---|
| **P0-1** API key NEVER logged | `resolveApolloAPIKey` + `classifyApolloError` return only status-derived, key-free text; `searchPage`/`matchPerson` never log the key, header, or body; `--verbose` logs counts + non-secret rate headers only (mirror `cmd_enum_hunter.go:103-105`). Unit test asserts the key never appears in any classified error string (mirror `cmd_enum_hunter_test.go:109-111`). | `resolveLushaAPIKey` + `classifyLushaError` same; `do` never logs the `api_key` header or body. Same no-leak unit test. |
| **P0-3** bounded body read (1 MB) | every HTTP body via `enum.ReadResponseBody(resp, 0)` before decode (search, match), exactly like `hunter.go:193`. No raw `io.ReadAll(resp.Body)`. | `do` reads via `enum.ReadResponseBody(resp, 0)` before decode. |
| **P0-4** terminal sanitization | `outputApolloHuman` wraps every API string (name/title/dept/org/email/status) in `sanitizeTerminal`+`truncate`; JSONL relies on `encoding/json` escaping (documented). | `outputLushaHuman` wraps name/title/company/email/phone/type; JSONL relies on `encoding/json`. |
| Sentinels never expose secrets | sentinels are static strings; `*APIError.Details` carries only `resp.Status`/server error-envelope text, never the request body or key. | same |

(P0-2 / P0-5+ Chariot-integration P0s — VMFilter, CheckAffiliation, ValidateCredentials, errgroup
limits — **do not apply**: this is a `brutus enum` CLI, not a Chariot integration. Confirmed by the
Hunter precedent, which has none of them.)

---

## 11. Lusha v3 Assumptions (resolves open questions §5.2, §5.3)

**v3 confirmed over v2 (§5.3):** v2 (`GET /v2/person`) sunsets 2026-11-18 and already emits a
`Sunset` header (active since 2026-05-18). Today is 2026-06-25 — v2 would ship with <5 months of
life and a deprecation header. v3 (`POST /v3/contacts/search-and-enrich`) is the documented
recommendation for new integrations. **Target v3.** Exact v3 schema needs live-key verification →
isolate + flag below.

**Batch scope (§5.2):** single-identity per invocation. Bulk/stdin identity lists are explicitly
out of scope (YAGNI); noted as a future extension (§12). The command takes one identity group.

### Lusha Assumptions (NOT verified against a live key — isolate, flag for developer)
| Assumption | Why unverified | Risk if wrong | Isolation |
|---|---|---|---|
| Endpoint `POST /v3/contacts/search-and-enrich` | docs-derived (discovery §3) | 404 | `const enrichPath` |
| Auth header literal `api_key` | docs-derived | 401 | `const headerAPIKey = "api_key"` |
| Request identity field names (`firstName`,`lastName`,`companyName`,`companyDomain`,`email`,`linkedinUrl`) + reveal control shape | docs-derived | 422 / unmatched | `buildEnrichRequest` + unexported request struct in `lusha_types.go` |
| Response: `emailAddresses[]`{email/address,type,confidence}, `phoneNumbers[]`{number,type,doNotCall}, name, jobTitle, company | docs-derived; "email" vs "address" key uncertain | Decode yields empty contact | unexported response structs; `toContact` mapper |
| No-match signal (200 + empty vs 404) | docs-derived | Wrong empty/error branch | `do` maps 404→`ErrNotFound` (add sentinel) AND `Enrich` treats empty 200 as empty contact; developer keeps whichever the live API uses |
| 402 / quota code for "out of credits" | docs-derived | NoCredits not surfaced | `APIError.Unwrap` 402→`ErrNoCredits`; widen if live API uses a different code |

Same isolation discipline as Apollo (§7): one edit per const/struct corrects any mismatch without
touching control flow. `httptest` tests pass regardless of live-schema correctness.

---

## 12. Out of scope (YAGNI — documented future extensions)

- **Apollo phone reveal** — `reveal_phone_number` requires a `webhook_url` for async delivery; a
  CLI cannot receive webhooks. Emails only. (Hard constraint, discovery §2.)
- **Apollo org-enrich endpoint** — not requested.
- **Lusha bulk / stdin identity list** — single identity per invocation in v1.
- **Auto-retry / exponential backoff on 429** — surface as a sentinel; no silent retry.
- **Header-driven client-side throttling** (`x-rate-limit-*`) — read for `--verbose` only.
- **A shared "HUMINT provider" interface** — Rule of Three not met (different shapes); see §1.

---

## 13. File-by-File summary

**Create:**
1. `pkg/enum/apollo/apollo.go` — `Client`, `NewClient`, `SearchPeople`, `searchPage`,
   `RevealEmails`, `matchPerson`, `do` helper, `APIError`+`Unwrap`, sentinels, request/response
   structs, consts, `toPerson`. (Split `apollo_types.go` only if the file exceeds ~400 lines — see
   note below.)
2. `pkg/enum/apollo/apollo_test.go` — httptest-driven: `toPerson`, `APIError.Unwrap`,
   `searchPage` decode + error mapping, `SearchPeople` pagination (incl. `--limit` truncation,
   mid-pagination 429), `RevealEmails` merge + partial + serial-count, context cancellation.
3. `pkg/enum/lusha/lusha.go` — `Client`, `NewClient`, `Enrich`, `do`, `buildEnrichRequest`,
   `APIError`+`Unwrap`, sentinels, request/response structs, consts, `toContact`.
4. `pkg/enum/lusha/lusha_test.go` — httptest-driven: `toContact`, `APIError.Unwrap`, `Enrich`
   success (email+phone), `buildEnrichRequest` per identity group, error mapping
   (401/402/403/429/404), empty-match, context cancellation, key-not-in-request-log assertion.
5. `cmd/brutus/cmd_enum_apollo.go` — flags, `enumApolloCmd`, `runEnumApollo`, `resolveApolloAPIKey`,
   `classifyApolloError`.
6. `cmd/brutus/cmd_enum_apollo_test.go` — `resolveApolloAPIKey`, `classifyApolloError` (no-leak),
   registration, output (`outputApolloHuman`/`outputApolloJSONL`).
7. `cmd/brutus/cmd_enum_lusha.go` — flags, `enumLushaCmd`, `runEnumLusha`, `resolveLushaAPIKey`,
   `classifyLushaError`, identity-validation helper.
8. `cmd/brutus/cmd_enum_lusha_test.go` — `resolveLushaAPIKey`, `classifyLushaError` (no-leak),
   identity validation (mutual exclusion), registration, output.

**Modify (BOTH commands touch these two — conflict-management in plan.md §ordering):**
9. `cmd/brutus/cmd_enum.go` — two `enumCmd.AddCommand(...)` lines in `init()` (after line 111) + two
   `Long`/`Example` lines. **Distinct insertion points per command** (separate lines) so the two
   developers' edits don't collide; serialize if both land simultaneously.
10. `cmd/brutus/cmd_enum_output.go` — append `outputApolloHuman/JSONL` and `outputLushaHuman/JSONL`
    at the bottom (each block independent; append-only avoids line-overlap conflicts).

**File-size note (P0 file-size discipline):** Apollo's client (two phases + structs) may approach
~400 lines. If it exceeds 400, split request/response structs into `apollo_types.go` (the plan's
T-tasks instruct this). Lusha is smaller (single call) — one file. No splitting expected for Lusha.

---

## 14. Adversarial Review (blind-spot pass — `analyzing-with-adversarial-pov`)

**Reality / data-contract risk (Dim 1, 2):** Apollo endpoint paths/fields and Lusha v3 schema are
*unverified* (no live keys). Mitigation: every path/field/header isolated in consts + unexported
structs (§7, §11); a single edit fixes a mismatch without touching control flow. `httptest` tests
use controlled payloads → pass regardless of live correctness. Flagged for the developer to verify
against live docs/key before relying on live calls.

**Negative space — Apollo partial reveal (Dim 5):** `/people/match` may return no email for some
ids. `Person.Revealed=true` + `omitempty` `email` correctly distinguish "requested, none returned"
from "not requested". Without the flag, a consumer misreads a blank as confirmed-absent. Addressed
in §2.5/§2.3.

**Negative space — Apollo person with no `id` (Dim 5):** free search could return a person without
a usable id (e.g. masked record). `RevealEmails` skips ids that are empty (`if p.ID == ""
continue`) rather than firing a match call that 422s. Addressed in §2.5.

**Cost footgun (Dim 5):** `--reveal` on a large domain. Mitigation: `--limit` default 25 bounds
reveal spend; stderr cost notice prints N before spending. The `--limit 0` (uncapped) + `--reveal`
combination is the sharp edge — guarded by the cost notice still printing the (large) N so the user
sees the spend before it happens. Addressed in §8/§9.

**Data contract — Lusha identity mutual-exclusion (Dim 2, 7):** ambiguous/partial identity (name
without company, two groups set) would otherwise produce a 422 or, worse, a silently-wrong match.
Validated at the CLI layer with explicit errors before any spend. Addressed in §9.

**Negative space — Lusha DNC phones (Dim 5):** a returned phone may carry `doNotCall=true`
(compliance-relevant). Output renders the DNC flag explicitly (human marker + JSON `do_not_call`)
so an operator doesn't dial a DNC number. Addressed in §3.3/§9.

**Dependency / sequencing (Dim 6):** Apollo `RevealEmails` strictly depends on `SearchPeople`
output (ids); it takes `*DomainResult`, so it cannot run before a completed search. Single command
guarantees ordering. The two *subcommands* are independent (no cross-package import) → two
developers can build Apollo and Lusha fully in parallel; the only shared files are `cmd_enum.go`
and `cmd_enum_output.go` (append-only, distinct insertion points — see plan.md).

**Architecture justification (Dim 3):** rejected the shared-provider interface (§1) — deleting it
costs nothing because it never existed; the shared helpers already carry the real reuse. Rejected
errgroup/limiter (§6) — a 25-item serial loop doesn't need them.

**Implementability (Dim 7):** every referenced internal helper (`enum.NewEnumHTTPClient`,
`enum.ReadResponseBody`, `setupOutputWriter`, `isColorEnabled`, `logVerbose`, `sanitizeTerminal`,
`truncate`, `dim`, `heading`, `colorIf`, `SymbolInfo`, the six CLI globals) was READ and exists at
the cited lines. A developer can build against them without clarification. The only unknowns are
the external API schemas — explicitly isolated and flagged.

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
    ".worktrees/zoominfo-enum/.feature-development/architecture.md (structural template only)",
    ".worktrees/zoominfo-enum/.feature-development/plan.md (structural template only)"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "integration-developer",
    "context": "Implement per plan.md. Two independent commands buildable in parallel; only cmd_enum.go + cmd_enum_output.go are shared (append-only, distinct insertion points). VERIFY Apollo paths/fields (§7) and Lusha v3 schema (§11) against live docs/key — isolated in consts/structs; httptest tests pass regardless."
  }
}
```
