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

package rdp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDetectStickyKeys_ConnectionError(t *testing.T) {
	ctx := context.Background()
	result := DetectStickyKeys(ctx, "invalid-host:3389", 2*time.Second, "(sticky-keys)")

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "invalid-host:3389", result.Target)
	assert.Equal(t, "(sticky-keys)", result.Username)
	assert.False(t, result.Success)
	assert.Contains(t, result.Banner, "skipped")
}

func TestDetectStickyKeys_ResultFields(t *testing.T) {
	ctx := context.Background()
	result := DetectStickyKeys(ctx, "192.0.2.1:3389", 1*time.Second, "(sticky-keys)")

	assert.NotNil(t, result)
	assert.Equal(t, "(sticky-keys)", result.Username)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "192.0.2.1:3389", result.Target)
}
