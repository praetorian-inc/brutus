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

package neo4j

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/config"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var neo4jAuthIndicators = []string{
	"authentication failure",
	"invalid credentials",
	"authentication failed",
}

func init() {
	brutus.Register("neo4j", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements Neo4j password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "neo4j"
}

// Test attempts Neo4j password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("neo4j", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Build Neo4j Bolt URI
	uri := fmt.Sprintf("bolt://%s", target)

	// Create authentication token
	auth := neo4j.BasicAuth(username, password, "")

	// Read TLS mode from context
	tlsMode := pluginCfg.TLSMode

	// Create driver with TLS config
	driver, err := neo4j.NewDriverWithContext(uri, auth, func(c *config.Config) {
		c.TlsConfig = brutus.BuildTLSConfig(tlsMode)
	})
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = driver.Close(ctx) }()

	// Create context with timeout for verification
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Verify connectivity and authentication
	err = driver.VerifyConnectivity(verifyCtx)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	// Success
	result.Success = true
	return result
}

var classifyError = brutus.NewClassifier(neo4jAuthIndicators)
