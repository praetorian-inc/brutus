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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var (
	neo4jTestHost = os.Getenv("NEO4J_TEST_HOST")
	neo4jTestUser = os.Getenv("NEO4J_TEST_USER")
	neo4jTestPass = os.Getenv("NEO4J_TEST_PASS")
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "neo4j", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	if neo4jTestHost == "" {
		t.Skip("Integration test - requires Neo4j server (set NEO4J_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, neo4jTestHost, neo4jTestUser, neo4jTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "neo4j", result.Protocol)
	assert.Equal(t, neo4jTestHost, result.Target)
	assert.Equal(t, neo4jTestUser, result.Username)
	assert.Equal(t, neo4jTestPass, result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	if neo4jTestHost == "" {
		t.Skip("Integration test - requires Neo4j server (set NEO4J_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, neo4jTestHost, neo4jTestUser, "definitely-wrong-password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "neo4j", result.Protocol)
	assert.Equal(t, neo4jTestHost, result.Target)
	assert.Equal(t, neo4jTestUser, result.Username)
	assert.Equal(t, "definitely-wrong-password", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "neo4j", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "neo4j", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	if neo4jTestHost == "" {
		t.Skip("Integration test - requires Neo4j server (set NEO4J_TEST_HOST)")
	}

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, neo4jTestHost, neo4jTestUser, neo4jTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:7687", "neo4j", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}
