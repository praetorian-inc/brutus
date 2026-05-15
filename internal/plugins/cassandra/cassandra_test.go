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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "cassandra", p.Name())
}

func TestPlugin_Test_ErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool // true if should be classified as auth error (nil)
	}{
		{
			name:     "bad credentials",
			errStr:   "Bad credentials",
			wantAuth: true,
		},
		{
			name:     "authentication failure",
			errStr:   "authentication failure",
			wantAuth: true,
		},
		{
			name:     "authentication failed",
			errStr:   "authentication failed",
			wantAuth: true,
		},
		{
			name:     "connection error",
			errStr:   "connection refused",
			wantAuth: false,
		},
		{
			name:     "network error",
			errStr:   "no route to host",
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

func TestPlugin_Test_InvalidTarget(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "invalid:target:format", "user", "pass", time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Equal(t, "cassandra", result.Protocol)
	assert.Equal(t, "invalid:target:format", result.Target)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ResultStructure(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Test with unreachable target to verify result structure
	result := p.Test(ctx, "localhost:99999", "user", "pass", 100*time.Millisecond, brutus.PluginConfig{})

	// Verify result fields are populated
	assert.Equal(t, "cassandra", result.Protocol)
	assert.Equal(t, "localhost:99999", result.Target)
	assert.Equal(t, "user", result.Username)
	assert.Equal(t, "pass", result.Password)
	assert.False(t, result.Success)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := p.Test(ctx, "localhost:9042", "user", "pass", time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

// mockError is a simple error implementation for testing error classification
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
