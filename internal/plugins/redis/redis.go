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

var redisAuthIndicators = []string{
	"noauth",
	"wrongpass",
	"invalid password",
	"err invalid password", // Some Redis versions prefix with ERR
	"err client sent auth", // Auth not enabled on server
	"without any password", // No password configured
}

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
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("redis", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Parse target to extract host and port
	host, port := brutus.ParseTarget(target, "6379")
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
	defer func() { _ = client.Close() }()

	// Create context with timeout
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Test connection with Ping
	err := client.Ping(pingCtx).Err()
	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	// Success
	result.Success = true
	return result
}

// CheckUnauth probes for Redis without authentication (no requirepass).
func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("redis", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "6379")
	addr := fmt.Sprintf("%s:%s", host, port)

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     "",
		DB:           0,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	})
	defer func() { _ = client.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := client.Ping(pingCtx).Err(); err != nil {
		return result
	}

	// Capture Redis version via INFO
	bannerText := "[CRITICAL] Redis accessible without authentication"
	info, err := client.Info(pingCtx, "server").Result()
	if err == nil {
		for _, line := range strings.Split(info, "\n") {
			if strings.HasPrefix(line, "redis_version:") {
				version := strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
				bannerText += fmt.Sprintf(" (version %s)", version)
				break
			}
		}
	}

	result.Success = true
	result.Banner = bannerText
	return result
}

var classifyError = brutus.NewClassifier(redisAuthIndicators)
