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

package smb

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "smb", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no SMB server available
	// In real tests, use Docker container with known credentials
	t.Skip("Integration test - requires SMB server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:445", "Administrator", "password", 5*time.Second)

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, "localhost:445", result.Target)
	assert.Equal(t, "Administrator", result.Username)
	assert.Equal(t, "password", result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no SMB server available
	t.Skip("Integration test - requires SMB server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:445", "Administrator", "wrongpassword", 5*time.Second)

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, "localhost:445", result.Target)
	assert.Equal(t, "Administrator", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "invalid-host:445", "Administrator", "password", 2*time.Second)

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, "invalid-host:445", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	t.Skip("Integration test - requires SMB server")

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, "localhost:445", "Administrator", "password", 5*time.Second)

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "192.0.2.1:445", "Administrator", "password", 1*time.Second)

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_DomainUsername(t *testing.T) {
	// Skip if no SMB server available
	t.Skip("Integration test - requires SMB server with domain")

	p := &Plugin{}
	ctx := context.Background()

	// Test with DOMAIN\username format
	result := p.Test(ctx, "localhost:445", "DOMAIN\\Administrator", "password", 5*time.Second)

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, "localhost:445", result.Target)
	assert.Equal(t, "DOMAIN\\Administrator", result.Username)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}
