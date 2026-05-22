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

package google

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckAccountChooser_WithSAMLHeader tests that accounts with Google-Accounts-SAML header are detected
func TestCheckAccountChooser_WithSAMLHeader(t *testing.T) {
	ctx := context.Background()
	exists, err := checkAccountChooser(ctx, "adam.crosser@praetorian.com", 5*time.Second)

	require.NoError(t, err)
	assert.True(t, exists, "Account with Google-Accounts-SAML header should exist")
}

// TestCheckAccountChooser_InvalidAccount tests that invalid accounts are detected
func TestCheckAccountChooser_InvalidAccount(t *testing.T) {
	ctx := context.Background()
	exists, err := checkAccountChooser(ctx, "invalid-nonexistent-user-12345@praetorian.com", 5*time.Second)

	require.NoError(t, err)
	assert.False(t, exists, "Invalid account should not exist")
}
