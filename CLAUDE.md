# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Brutus is a multi-protocol credential testing tool and Go library by Praetorian Security. It tests authentication against 23 network protocols (SSH, MySQL, PostgreSQL, Redis, SMB, LDAP, HTTP, etc.). Single static binary, zero external dependencies, CGO always disabled.

**Module:** `github.com/praetorian-inc/brutus`
**Go version:** 1.24.0

## Build & Development Commands

```bash
make build                    # Build static binary (CGO_ENABLED=0)
make test                     # Unit tests only (go test -short ./...)
make test-integration         # Full tests (requires: make demo-up first)
make lint                     # golangci-lint run ./... (falls back to go vet)
make demo-up                  # Start Docker services for integration tests
make demo-down                # Stop Docker services

# Run a single test
CGO_ENABLED=0 go test -short -run TestName ./pkg/brutus/
CGO_ENABLED=0 go test -short -run TestName ./internal/plugins/ssh/

# Run tests for a specific package
CGO_ENABLED=0 go test -short -v ./internal/plugins/ssh/...

# Browser/vision tests (special build tags)
go test -v -tags=e2e ./internal/plugins/browser/...
go test -v -tags=vision_api ./internal/analyzers/vision/...
```

All go commands in this repo must use `CGO_ENABLED=0` and optionally `GOWORK=off`.

## Architecture

### Library-First Design

The public API lives in `pkg/brutus/`. Users call `brutus.Brute(config)` or `brutus.BruteWithContext(ctx, config)`. The CLI (`cmd/brutus/`) is a thin wrapper around the library.

### Plugin Registry Pattern

Protocol plugins register via `init()` side-effects through a three-layer blank import chain:

1. Each plugin package (e.g., `internal/plugins/ssh/`) calls `brutus.Register("ssh", factory)` in `init()`
2. `internal/plugins/init.go` blank-imports all 23 plugin packages
3. `pkg/builtins/builtins.go` blank-imports both plugins and analyzers — library users import this single package

The global registry in `pkg/brutus/registry.go` stores `PluginFactory` functions (not instances) protected by `sync.RWMutex`. `GetPlugin()` returns fresh instances from factories.

### Core Interfaces

- **`Plugin`**: `Name() string` + `Test(ctx, target, username, password, timeout) *Result` — every protocol implements this
- **`KeyPlugin`**: extends `Plugin` with `TestKey()` for SSH key auth
- **`BannerAnalyzer`** / **`CredentialAnalyzer`**: LLM-based credential suggestion from service banners

### Result Error Convention

This is a critical invariant throughout the codebase:
- **Auth failure** (wrong credentials): `Success=false, Error=nil`
- **Connection error** (network problem): `Success=false, Error!=nil`
- **Valid credentials**: `Success=true, Error=nil`

Every plugin uses `brutus.ClassifyAuthError(err, authIndicators)` from `pkg/brutus/errors.go` with protocol-specific indicator strings to enforce this.

### Worker Pool (`pkg/brutus/workers.go`)

Uses `errgroup` with `SetLimit(cfg.Threads)` for bounded concurrency. Features: rate limiting (`x/time/rate`), configurable jitter, max attempts per username, spray mode (password-first iteration), panic recovery per goroutine, atomic stop-on-success with context cancellation.

Credential iteration builds a Cartesian product of usernames × passwords, plus pre-paired `Credential` entries added directly (no product).

### Embedded Resources

- **Default wordlists**: `pkg/brutus/wordlists/*.txt` — 23 protocol-specific credential files, loaded via `//go:embed`
- **Bad SSH keys**: `pkg/badkeys/keys/` — rapid7/ssh-badkeys + Vagrant keys with metadata (username, CVE, product)

### LLM Integration

Optional AI-powered flow in `pkg/brutus/workers.go` (`runWorkersWithLLM`): captures banner → checks if standard → runs analyzer → prepends LLM-suggested credentials. The browser plugin (`internal/plugins/browser/`) adds Claude Vision screenshot analysis. Prompt injection defenses in `pkg/brutus/llm.go`.

## Adding a New Protocol Plugin

1. Create `internal/plugins/yourprotocol/yourprotocol.go`
2. Implement `Plugin` interface (Name + Test)
3. Call `brutus.Register("yourprotocol", factory)` in `init()`
4. Define auth indicators and use `brutus.ClassifyAuthError()` for error classification
5. Add blank import to `internal/plugins/init.go`
6. Create `pkg/brutus/wordlists/yourprotocol_defaults.txt` (format: `username:password` per line)
7. Add tests in `yourprotocol_test.go`

## Adding a New Enum Plugin

1. Create `internal/enumplugins/yourservice/yourservice.go`
2. Implement `enum.Plugin` interface (`Name()` + `Check()`)
3. Call `enum.Register("yourservice", factory)` in `init()`, passing `baseURL: defaultBaseURL` in the factory
4. Use `enum.NewEnumHTTPClient(timeout)` for HTTP clients (safe redirect policy, User-Agent, timeout)
5. Use `enum.ReadResponseBody(resp, 0)` for body reads (1 MB limit)
6. Add blank import to `internal/enumplugins/init.go`
7. Add `httptest`-based tests in `yourservice_test.go`

## Code Style

- **Commits**: conventional format — `type(scope): description` (feat, fix, refactor, test, docs, chore)
- **Imports**: three groups — stdlib, external, internal (`github.com/praetorian-inc/brutus`)
- **Linter**: golangci-lint with errcheck, govet (shadowing), goimports, gocritic, misspell (US), and others — see `.golangci.yml`
- **Testing**: table-driven tests with `stretchr/testify`. Integration tests skip via env vars (e.g., `SSH_TEST_HOST`) or `t.Skip()`
- Plugin types are always named `Plugin` within their package
