# Security Review: Apollo.io + Lusha enum subcommands (Phase-7 P0 audit)

**Reviewer:** backend-security
**Date:** 2026-06-26
**Scope:** `pkg/enum/apollo/apollo.go`, `pkg/enum/lusha/lusha.go`, `cmd/brutus/cmd_enum_apollo.go`, `cmd/brutus/cmd_enum_apollo_output.go`, `cmd/brutus/cmd_enum_lusha.go`, `cmd/brutus/cmd_enum_lusha_output.go`, package tests.
**Contract:** `.feature-development/security-assessment.md` (security-lead, P0-1 family / P0-3 / P0-4 / P0-5 / P0-6/7/8 / P0-DNC / P0-ToS).
**Methodology:** Evidence-based — every claim below is anchored to a file:line read this session. Reference: Hunter implementation (`cmd_enum_hunter.go:128-139`), bounded-read primitive (`httpclient.go:58-65`), output writer perms (`flags.go:308-312`).

## Summary

Implementation closely follows the Hunter template and the security-lead's P0 contract. The `do()` choke point in both client packages is correct: bounded read on every call, header-based auth, no request dumping. Output formatting sanitizes every human field. The Apollo error classifier is exemplary (reports status code only, never `%w`-wraps). **One real P0 credential-leak path exists in the Lusha error classifier**, and **the entire command-layer test contract (§4) is missing** (no `cmd_enum_apollo_test.go` / `cmd_enum_lusha_test.go`), so the mandatory P0-1 no-key-leak negative test does not exist for either service.

## Security Findings

### Critical Issues

| Severity | Issue | Location | Remediation |
| -------- | ----- | -------- | ----------- |
| P0 | **P0-1 credential-leak path: `classifyLushaError` default branch `%w`-wraps the `*lusha.APIError`, whose `Error()` embeds vendor `Details`.** If Lusha echoes the API key (or any sensitive request content) into its error envelope `message`, it is mapped to `APIError.Details` (`lusha.go:197-202`) and surfaced verbatim through `err.Error()` to the user/CLI. This is exactly the "vendor-echoes-key-in-body" case the contract forbids (assessment §2.1 P0-1, §3 AVOID: "Do NOT pass the vendor's error Details body straight into a user-facing error"). | `cmd/brutus/cmd_enum_lusha.go:228-230` (`default: return fmt.Errorf("lusha enrichment failed: %w", err)`); leak surface created at `lusha.go:99-101` (`Error()` includes `e.Details`) + `lusha.go:197-202` (`Details = env.Message`). | Mirror the Apollo classifier (`cmd_enum_apollo.go:165-171`): in the default branch, `errors.As` into `*lusha.APIError` and return only the status code — `return fmt.Errorf("lusha enrichment failed (HTTP %d)", apiErr.StatusCode)` — falling back to a generic static message otherwise. Never `%w`-wrap an error whose `Error()` embeds `Details`. |

### High Severity Issues

| Severity | Issue | Location | Remediation |
| -------- | ----- | -------- | ----------- |
| P0 | **Mandatory §4 test contract is entirely absent at the command layer.** No `cmd_enum_apollo_test.go` or `cmd_enum_lusha_test.go` exists (verified via Glob: "No files found"). The contract's enforcement tests are therefore not present: `TestClassifyXError_NoKeyLeak` incl. the vendor-echoes-key-in-body case (§2.1, the canonical P0-1 control), verbose-path no-leak, `TestOutputXHuman` ANSI injection (P0-4), `TestOutputXJSONL`, Apollo default-path-no-spend (P0-6), cost-notice-emitted/suppressed (P0-7), `--limit` spend cap (P0-8), and DNC-surfaced (P0-DNC). The classifier in Finding 1 would have been caught by the required `NoKeyLeak` test. The only no-leak assertion in the repo is Hunter's (`cmd_enum_hunter_test.go:110`). | absent: `cmd/brutus/cmd_enum_apollo_test.go`, `cmd/brutus/cmd_enum_lusha_test.go` | Add both command-layer test files implementing the §4 matrix. The `TestClassifyLushaError_NoKeyLeak` case MUST feed `&lusha.APIError{StatusCode: 500, Details: sentinelKey}` (and a `%w`-wrapped variant) through `classifyLushaError` and `assert.NotContains(out, sentinelKey)` — this is the regression test for Finding 1. Same for Apollo's classifier and the verbose-stderr path. |

### Medium/Low Severity Issues

| Severity | Issue | Location | Remediation |
| -------- | ----- | -------- | ----------- |
| P2 | **Apollo `--reveal` cost notice prints the count but is not a hard pre-spend gate per the P0-7 "before any spend" wording — it is fine, but the notice fires unconditionally inside the `--reveal` branch even when `len(result.People)==0` (no spend will occur).** Minor: emits "will consume Apollo credits for 0 people". Not a security risk; cosmetic accuracy. | `cmd/brutus/cmd_enum_apollo.go:115-119` | Optional: skip the notice when `len(result.People)==0`. Non-blocking. |
| P2 | **Apollo `--limit` default is 100, not the contract's recommended 25 (P0-8 "default 25").** The contract said "conservative default 25"; 100 still bounds spend (no blowout) and is documented, but is 4x the recommended conservative cap. | `cmd/brutus/cmd_enum_apollo.go:73` | Confirm with security-lead whether 100 is an accepted deviation; if the conservative-default intent stands, lower to 25. Non-blocking (a cap exists; this is a tuning choice). |

## P0 Verification Matrix (evidence)

| P0 | Verdict | Evidence |
| -- | ------- | -------- |
| P0-1 (key never in log/print/error sink) | **FAIL (Lusha)** / PASS (Apollo) | Apollo classifier reports status code only, no `%w` (`cmd_enum_apollo.go:165-171`); verbose logs counts only (`apollo.go cmd:126-127`, `lusha.go cmd:142-143`). **Lusha default branch `%w`-wraps `*APIError` whose `Error()` embeds `Details` (`cmd_enum_lusha.go:229`) — see Finding 1.** Key never in URL: header-set inline (`apollo.go:265`, `lusha.go:178`), asserted in pkg tests (`apollo_test.go:272`, `lusha_test.go:119`). |
| P0-1b (unexported field, no tag/getter) | PASS | `apiKey string` unexported, no JSON tag, no getter (`apollo.go:115`, `lusha.go:128`). |
| P0-1c (no httputil.Dump*) | PASS | Grep over all 6 files: only a comment mention at `apollo.go:254`; zero `DumpRequest`/`DumpResponse` calls. |
| P0-3 (bounded read every call) | PASS | `enum.ReadResponseBody(resp, 0)` is the sole read path in both `do()` (`apollo.go:275`, `lusha.go:188`); 1 MB cap at `httpclient.go:60-64`. Grep for `io.ReadAll`/`ioutil.ReadAll` in scope: no matches. |
| P0-4 (sanitize+truncate every human field) | PASS | Apollo: every field `sanitizeTerminal`+`truncate` incl. Email/EmailStatus (`cmd_enum_apollo_output.go:62-78`, name via `personName` :130-135). Lusha: Title/Company/Email/Type/Confidence/Phone/Type sanitized (`cmd_enum_lusha_output.go:37-79`). |
| P0-4b (JSONL not sanitized) | PASS | Both JSONL emitters use `encoding/json` only (`cmd_enum_apollo_output.go:104`, `cmd_enum_lusha_output.go:131`). |
| P0-5 (429 → sentinel, no auto-retry) | PASS | 429→`ErrRateLimited` (`apollo.go:103-104`, `lusha.go:116-117`); no retry loop in `do()`/`SearchPeople`/`Enrich`; classifiers return actionable text (`cmd_enum_apollo.go:162-163`, `cmd_enum_lusha.go:226-227`). pkg tests confirm mid-pagination 429 surfaces (`apollo_test.go:385-395`). |
| P0-6 (Apollo --reveal opt-in, distinct methods) | PASS | `--reveal` default false (`cmd_enum_apollo.go:72`); `SearchPeople` (free) and `RevealEmails` (paid) are distinct methods; reveal only runs in the `if flagApolloReveal` branch (`cmd_enum_apollo.go:115-123`). |
| P0-7 (stderr cost notice before spend) | PASS | Apollo: notice gated by `--reveal` + `!flagQuiet && !flagJSON`, states count, before `RevealEmails` (`cmd_enum_apollo.go:116-119`). Lusha: unconditional notice, same gating, before `Enrich` (`cmd_enum_lusha.go:117-120`). |
| P0-8 (bounded --limit spend cap) | PASS (with P2 note) | Apollo `--limit` truncates accumulated people (`apollo.go:157-160`) and bounds reveals; default 100 (contract suggested 25 — see P2). |
| P0-DNC (surface Lusha DNC) | PASS | `PhoneEntry.DoNotCall` preserved (`lusha.go:240-245`); human DNC marker (`cmd_enum_lusha_output.go:72-79`); JSONL `do_not_call` bool NOT omitempty (`cmd_enum_lusha_output.go:97`). pkg test asserts preservation (`lusha_test.go:74`). |
| P0-ToS (authorized-use note in Long) | PASS | Apollo Long (`cmd_enum_apollo.go:49-50`); Lusha Long incl. DNC warning + ToS line (`cmd_enum_lusha.go:53-56`). |
| Apollo phone correctly NOT implemented | PASS | No `webhook_url`, no `reveal_phone_number`, no inbound listener anywhere in apollo package; match request is `{id, reveal_personal_emails}` only (`apollo.go:341-344`). No SSRF/callback surface. |
| P1-PII (output file perms) | PASS | `setupOutputWriter` opens `0o600` (`flags.go:312`). |
| P1-1 (no credential zeroing) | PASS | No `Zero()` routine — correct per contract (KISS). |

## Verification (automated checks)

Not run (review is read-only; no build/test execution requested). Recommended before merge: `go test ./cmd/brutus/... ./pkg/enum/apollo/... ./pkg/enum/lusha/...` after the §4 command-layer tests are added; `go vet`. The package-level tests (`apollo_test.go`, `lusha_test.go`) exist and cover client behavior, pagination, error mapping, and DNC preservation, but do NOT cover the command-layer classifiers/output (where Finding 1 lives).

## Verdict

**NEEDS_CHANGES**

The client packages and output formatters are well-built and satisfy the bulk of the P0 contract. However, two P0-level items block approval: (1) the `classifyLushaError` default branch creates a real credential-leak path that the contract explicitly forbids, and (2) the mandatory P0-1/P0-4/P0-6/P0-7/P0-8/P0-DNC enforcement tests at the command layer are entirely absent — including the very test that would catch Finding 1. Both are mechanical fixes mirroring the already-correct Apollo classifier and the §4 test matrix.

## Recommendations (priority order for backend-developer)

1. Fix `classifyLushaError` default branch to mirror `classifyApolloError` (status-code-only, no `%w` of `*APIError`). (Finding 1)
2. Add `cmd_enum_lusha_test.go` + `cmd_enum_apollo_test.go` implementing the §4 matrix, with `TestClassifyXError_NoKeyLeak` (including the `Details: sentinelKey` vendor-echo case and the `%w`-wrapped variant) as the regression test for Finding 1, plus the verbose-stderr no-leak, ANSI-injection (P0-4), default-no-spend (P0-6), cost-notice (P0-7), `--limit` cap (P0-8), and DNC-surfaced (P0-DNC) tests.
3. Confirm `--limit` default (100 vs contract's 25) with security-lead; lower if the conservative-default intent stands. (P2)
4. Optional: suppress the Apollo cost notice when 0 people discovered. (P2)

---

## Metadata

```json
{
  "agent": "backend-security",
  "output_type": "security-review",
  "timestamp": "2026-06-26T00:00:00Z",
  "feature_directory": "/Users/engineer/github/brutus/.worktrees/apollo-lusha-enum/.feature-development/agents",
  "skills_invoked": [
    "using-skills",
    "enforcing-evidence-based-analysis",
    "gateway-security",
    "persisting-agent-outputs",
    "verifying-before-completion",
    "using-todowrite"
  ],
  "library_skills_read": [
    "/Users/engineer/.claude/plugins/cache/praetorian-ai-marketplace/engineering/1.38.17/skill-library/security/reviewing-backend-security/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/enum/apollo/apollo.go:1-380",
    "pkg/enum/lusha/lusha.go:1-300",
    "cmd/brutus/cmd_enum_apollo.go:1-187",
    "cmd/brutus/cmd_enum_apollo_output.go:1-136",
    "cmd/brutus/cmd_enum_lusha.go:1-232",
    "cmd/brutus/cmd_enum_lusha_output.go:1-144",
    "cmd/brutus/cmd_enum_hunter.go:125-139",
    "pkg/enum/httpclient.go:55-65",
    "pkg/enum/apollo/apollo_test.go:1-547",
    "pkg/enum/lusha/lusha_test.go:1-327",
    "cmd/brutus/flags.go:308-312"
  ],
  "status": "complete",
  "verdict": "NEEDS_CHANGES",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Two P0 fixes: (1) classifyLushaError default branch %w-wraps *lusha.APIError whose Error() embeds vendor Details — credential leak path (cmd_enum_lusha.go:229); fix to status-code-only like classifyApolloError. (2) No command-layer test files exist — add the §4 matrix incl. TestClassifyXError_NoKeyLeak (vendor-echoes-key-in-body + %w variant). P2: --limit default 100 vs contract 25; cosmetic cost-notice on 0 people."
  }
}
```
