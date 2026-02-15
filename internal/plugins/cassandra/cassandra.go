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

package cassandra

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gocql/gocql"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("cassandra", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements Cassandra password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "cassandra"
}

// Test attempts Cassandra password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "cassandra",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Create cluster configuration
	cluster := gocql.NewCluster(target)
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: username,
		Password: password,
	}
	cluster.Timeout = timeout
	cluster.ConnectTimeout = timeout
	cluster.ProtoVersion = 4 // CQL binary protocol v4
	// Note: Don't set SslOpts by default - most Cassandra deployments
	// don't enable TLS, and forcing TLS when the server doesn't support
	// it causes "first record does not look like a TLS handshake" errors

	// Create session with context
	session, err := cluster.CreateSession()
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer session.Close()

	// Test connection with a simple query
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Query system.local to verify authentication and connection
	iter := session.Query("SELECT now() FROM system.local").WithContext(queryCtx).Iter()
	if err := iter.Close(); err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Success
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// classifyError classifies Cassandra errors.
//
// Auth failure indicators (return nil):
// - "Bad credentials"
// - "authentication failed"
// - "authentication failure"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for authentication failure indicators
	authFailures := []string{
		"Bad credentials",
		"authentication failed",
		"authentication failure",
	}

	for _, indicator := range authFailures {
		if strings.Contains(errStr, indicator) {
			// This is an authentication failure, not a connection error
			return nil
		}
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
