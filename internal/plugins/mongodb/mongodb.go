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

package mongodb

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("mongodb", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements MongoDB password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "mongodb"
}

// Test attempts MongoDB password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("mongodb", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Read TLS mode from context
	tlsMode := pluginCfg.TLSMode

	// Determine TLS parameter based on mode
	var tlsParam string
	switch tlsMode {
	case "verify":
		tlsParam = "tls=true"
	case "skip-verify":
		tlsParam = "tls=true&tlsInsecure=true"
	default: // "disable"
		tlsParam = "tls=false"
	}

	// Build MongoDB connection string
	// Format: mongodb://username:password@host/
	// URL-encode username and password to handle special characters (@, :, /, %, #)
	connStr := fmt.Sprintf("mongodb://%s:%s@%s/?%s",
		url.QueryEscape(username), url.QueryEscape(password), target, tlsParam)

	// Create client options with timeout
	clientOpts := options.Client().
		ApplyURI(connStr).
		SetConnectTimeout(timeout).
		SetServerSelectionTimeout(timeout)

	// Create context with timeout
	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Connect to MongoDB
	client, err := mongo.Connect(connectCtx, clientOpts)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() {
		_ = client.Disconnect(context.Background())
	}()

	// Test connection with Ping
	pingCtx, pingCancel := context.WithTimeout(ctx, timeout)
	defer pingCancel()

	err = client.Ping(pingCtx, nil)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	// Success
	result.Success = true
	return result
}

// mongodbAuthIndicators defines authentication failure indicators for MongoDB.
var mongodbAuthIndicators = []string{
	"Authentication failed",
	"auth error",
}

var classifyError = brutus.NewClassifier(mongodbAuthIndicators)
