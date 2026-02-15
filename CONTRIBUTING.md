# Contributing to Brutus

Thank you for your interest in contributing to Brutus! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
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

    // TODO: Implement authentication logic

    result.Duration = time.Since(start)
    return result
}
```

### 3. Implement Error Classification

Properly classify errors as authentication failures vs connection errors:

```go
// classifyError classifies protocol-specific errors.
//
// Auth failure indicators (return nil):
// - Protocol-specific auth failure messages
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
    if err == nil {
        return nil
    }

    errStr := err.Error()

    // Check for authentication failure indicators
    authFailures := []string{
        "authentication failed",
        "access denied",
        // Add protocol-specific patterns
    }

    for _, indicator := range authFailures {
        if strings.Contains(errStr, indicator) {
            return nil // Auth failure, not connection error
        }
    }

    return fmt.Errorf("connection error: %w", err)
}
```

### 4. Add Unit Tests

Create `internal/plugins/yourprotocol/yourprotocol_test.go`:

```go
package yourprotocol

import (
    "context"
    "testing"
    "time"
)

func TestPlugin_Name(t *testing.T) {
    plugin := &Plugin{}
    if plugin.Name() != "yourprotocol" {
        t.Errorf("expected 'yourprotocol', got %q", plugin.Name())
    }
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
    plugin := &Plugin{}

    ctx := context.Background()
    result := plugin.Test(ctx, "invalid-host:1234", "user", "pass", 1*time.Second)

    if result == nil {
        t.Fatal("expected non-nil result")
    }

    if result.Success {
        t.Error("expected Success=false for connection error")
    }

    if result.Error == nil {
        t.Error("expected Error!=nil for connection error")
    }
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
    plugin := &Plugin{}

    ctx, cancel := context.WithCancel(context.Background())
    cancel() // Pre-cancel

    result := plugin.Test(ctx, "example.com:1234", "user", "pass", 5*time.Second)

    if result.Success {
        t.Error("expected Success=false for canceled context")
    }
}

// Integration test - requires real server
func TestPlugin_Test_Integration(t *testing.T) {
    t.Skip("Integration test requires YourProtocol server")

    // TODO: Add integration test
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

### 6. Register in Plugins Package

Add import to `internal/plugins/all.go`:

```go
package plugins

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
