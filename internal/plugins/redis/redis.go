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

package redis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("redis", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements Redis password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "redis"
}

// Test attempts Redis password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "redis",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Parse target to extract host and port
	host, port := parseTarget(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           0,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	})
	defer client.Close()

	// Create context with timeout
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Test connection with Ping
	err := client.Ping(pingCtx).Err()
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Success
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// parseTarget splits target into host and port.
// If no port is specified, defaults to 6379.
func parseTarget(target string) (host, port string) {
	// Check if target contains port
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		return parts[0], parts[1]
	}
	// Default to port 6379 if not specified
	return target, "6379"
}

// classifyError classifies Redis errors.
//
// Auth failure indicators (return nil):
// - "NOAUTH Authentication required"
// - "WRONGPASS invalid username-password pair"
// - "invalid password"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for authentication failure indicators
	authFailures := []string{
		"noauth",
		"wrongpass",
		"invalid password",
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
