# Contributing to Brutus

Thank you for your interest in contributing to Brutus! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Changing the CLI Surface](#changing-the-cli-surface)
- [Adding a New Protocol](#adding-a-new-protocol)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Style Guide](#style-guide)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Use welcoming and inclusive language
- Respect differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what's best for the community

## Getting Started

### Prerequisites

- Go 1.22 or later
- Git
- Docker (for integration tests)
- Make (optional, for convenience commands)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/brutus.git
cd brutus
```

3. Add upstream remote:

```bash
git remote add upstream https://github.com/praetorian-inc/brutus.git
```

## Development Setup

### Install Dependencies

```bash
go mod download
```

### Verify Setup

```bash
# Run unit tests
go test -short ./...

# Run linter
golangci-lint run
```

### Start Test Services (for integration tests)

```bash
docker compose up -d
```

## Making Changes

### Create a Branch

Always create a feature branch for your changes:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(ssh): add support for ed25519 keys
fix(mysql): handle connection timeout correctly
docs(readme): add installation instructions
test(ftp): add integration tests
```

### Keep Commits Focused

- One logical change per commit
- Keep commits small and reviewable
- Squash WIP commits before submitting PR

## Changing the CLI Surface

The documented CLI surface is **generated from the live cobra command tree**, not
maintained by hand. Three files are generated:

| File | Purpose |
|------|---------|
| `docs/cli-surface.json` | Machine-readable surface. Downstream consumers pin this; it is attached to every GitHub release. |
| `docs/CLI.md` | Full human-readable reference: every command, alias and flag. |
| `README.md` | Two generated regions in Quick Start, delimited by `<!-- BEGIN generated: ... -->` markers. |

If you add, remove or rename a command or a flag, regenerate them:

```bash
make cli-docs
```

Then commit the result alongside your code change.

The `CLI Surface Drift` workflow runs the same walk in check mode on every pull
request and fails when the committed copies disagree with what cobra registers,
in either direction:

- a **documented** flag or subcommand that no longer exists, or
- a **registered** flag or subcommand that is not documented.

It also lints prose. Every `brutus` invocation inside a fenced code block, every
backticked flag name in prose, and every flag name mentioned in a Go comment
under `cmd/` and `pkg/` is checked against the real surface. A flag that was
renamed cannot survive in a comment or an example.

If a document must deliberately name a flag that no longer exists — for example
when describing a historical rename — add it to `docs/cli-surface-allow.txt`
with a comment explaining why.

Do not edit the generated files or the generated README regions by hand; the next
`make cli-docs` will overwrite them, and the gate will reject the difference in
the meantime.

## Adding a New Protocol

Adding a new protocol plugin involves these steps:

### 1. Create Plugin Directory

```bash
mkdir -p internal/plugins/yourprotocol
```

### 2. Implement the Plugin Interface

Create `internal/plugins/yourprotocol/yourprotocol.go`:

```go
// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package yourprotocol

import (
    "context"
    "fmt"
    "time"

    "github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
    brutus.Register("yourprotocol", func() brutus.Plugin {
        return &Plugin{}
    })
}

// Plugin implements YourProtocol password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
    return "yourprotocol"
}

// Test attempts authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
    timeout time.Duration) *brutus.Result {

    start := time.Now()

    result := &brutus.Result{
        Protocol: "yourprotocol",
        Target:   target,
        Username: username,
        Password: password,
        Success:  false,
    }

    // Parse target with IPv6 support (uses default port if not specified)
    host, port := brutus.ParseTarget(target, "1234")

    // TODO: Implement authentication logic using host, port, username, password
    // On error: result.Error = classifyError(err)
    // On success: result.Success = true

    _ = host
    _ = port

    result.Duration = time.Since(start)
    return result
}
```

### 3. Implement Error Classification

Use the shared `brutus.ClassifyAuthError` helper to distinguish authentication failures from connection errors. Define your protocol's auth indicators and delegate to the shared classifier:

```go
var yourprotocolAuthIndicators = []string{
    "authentication failed",
    "access denied",
    // Add protocol-specific error patterns that indicate wrong credentials
}

// classifyError classifies protocol-specific errors.
// Uses shared brutus.ClassifyAuthError with protocol auth indicators
// to distinguish authentication failures from connection errors.
func classifyError(err error) error {
    return brutus.ClassifyAuthError(err, yourprotocolAuthIndicators)
}
```

The shared helper handles nil checks, case-insensitive matching, and wraps non-auth errors as `"connection error: ..."`. See existing plugins (e.g., `mysql`, `ssh`, `redis`) for examples of protocol-specific indicators.

### 4. Add Unit Tests

Create `internal/plugins/yourprotocol/yourprotocol_test.go`:

```go
package yourprotocol

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

func TestPlugin_Name(t *testing.T) {
    p := &Plugin{}
    assert.Equal(t, "yourprotocol", p.Name())
}

func TestPlugin_Test_ErrorClassification(t *testing.T) {
    tests := []struct {
        name     string
        errStr   string
        wantAuth bool // true if should be classified as auth error (nil)
    }{
        {
            name:     "authentication failed",
            errStr:   "authentication failed for user",
            wantAuth: true,
        },
        {
            name:     "access denied",
            errStr:   "access denied",
            wantAuth: true,
        },
        {
            name:     "connection error",
            errStr:   "connection refused",
            wantAuth: false,
        },
        {
            name:     "timeout error",
            errStr:   "context deadline exceeded",
            wantAuth: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := &mockError{msg: tt.errStr}
            result := classifyError(err)

            if tt.wantAuth {
                assert.Nil(t, result, "auth errors should return nil")
            } else {
                assert.NotNil(t, result, "connection errors should be wrapped")
                assert.Contains(t, result.Error(), "connection error")
            }
        })
    }
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
    p := &Plugin{}
    ctx := context.Background()

    result := p.Test(ctx, "localhost:9999", "user", "pass", 2*time.Second)

    assert.NotNil(t, result)
    assert.Equal(t, "yourprotocol", result.Protocol)
    assert.False(t, result.Success, "Expected connection failure")
    assert.NotNil(t, result.Error, "Connection error should have non-nil error")
    assert.Contains(t, result.Error.Error(), "connection error")
    assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
    t.Skip("Integration test - requires YourProtocol server")

    // TODO: Add integration test with real server
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
    t.Skip("Integration test - requires YourProtocol server")

    // TODO: Add integration test with real server
}

// mockError is a simple error implementation for testing error classification
type mockError struct {
    msg string
}

func (e *mockError) Error() string {
    return e.msg
}
```

### 5. Add Default Credentials

Create `wordlists/yourprotocol_defaults.txt`:

```
# YourProtocol default credentials
# Format: username:password
admin:admin
admin:password
root:root
```

### 6. Register in Builtins Package

Add import to `pkg/builtins/builtins.go`:

```go
package builtins

import (
    _ "github.com/praetorian-inc/brutus/internal/plugins/ssh"
    _ "github.com/praetorian-inc/brutus/internal/plugins/ftp"
    // ... other plugins
    _ "github.com/praetorian-inc/brutus/internal/plugins/yourprotocol"
)
```

### 7. Update README

Add your protocol to the Supported Protocols table in `README.md`.

## Testing

### Run All Tests

```bash
go test ./... -v
```

### Run Unit Tests Only

```bash
go test -short ./...
```

### Run Integration Tests

```bash
# Start test services
docker compose up -d

# Run integration tests
go test -tags=integration ./... -v

# Cleanup
docker compose down
```

### Check Coverage

```bash
go test -coverprofile=coverage.out ./... -short
go tool cover -func=coverage.out

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
```

### Coverage Requirements

- **Minimum coverage:** 80% for new code
- **Core packages:** 85%+ coverage
- All error paths must be tested

### Run Linter

```bash
golangci-lint run
```

## Pull Request Process

### Before Submitting

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks:**
   ```bash
   go test -short ./...
   golangci-lint run
   ```

   If you touched a command or a flag, also regenerate the CLI documentation
   (see [Changing the CLI Surface](#changing-the-cli-surface)):
   ```bash
   make cli-docs
   ```

3. **Update documentation** if needed

4. **Add tests** for new functionality

### Submitting

1. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request on GitHub

3. Fill out the PR template:
   - Description of changes
   - Related issues
   - Testing performed
   - Breaking changes (if any)

### PR Review Process

1. **Automated checks** must pass:
   - CI build
   - Lint checks
   - Test suite
   - Coverage threshold

2. **Code review** by maintainer

3. **Address feedback** with additional commits

4. **Squash and merge** when approved

### PR Title Format

Use conventional commit format:
```
feat(protocol): add support for XYZ
fix(ssh): handle timeout correctly
```

## Style Guide

### Code Formatting

- Use `gofmt` for formatting
- Use `goimports` for import organization
- Run `golangci-lint` before committing

### Import Organization

Organize imports in three groups:
1. Standard library
2. External packages
3. Internal packages

```go
import (
    "context"
    "fmt"
    "time"

    "github.com/jlaffaye/ftp"

    "github.com/praetorian-inc/brutus/pkg/brutus"
)
```

### Error Handling

- Always handle errors explicitly
- Wrap errors with context:
  ```go
  return fmt.Errorf("connection error: %w", err)
  ```
- Use the error classification pattern for auth vs connection errors

### Comments

- Add package-level documentation
- Document exported functions and types
- Use complete sentences
- Explain "why" not "what"

```go
// Plugin implements FTP password authentication.
// It uses the jlaffaye/ftp library for RFC 959 compliance.
type Plugin struct{}

// Test attempts FTP authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(...) *brutus.Result {
```

### Naming Conventions

- Use descriptive names
- Avoid abbreviations (except common ones like `ctx`, `err`)
- Plugin types should be named `Plugin`
- Test functions should be `Test<Function>_<Scenario>`

### Testing

- Use table-driven tests where appropriate
- Test both success and failure paths
- Mock external services in unit tests
- Use integration tests for real service testing

## Questions?

- Open an issue for questions
- Join discussions on GitHub
- Review existing PRs and issues for context

Thank you for contributing to Brutus!
