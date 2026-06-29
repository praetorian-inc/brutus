// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hunter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tenure: Hunter always returns unavailable (no employment dates in source)
// ---------------------------------------------------------------------------

// TestToPerson_TenureUnavailable verifies that a Person built from a Hunter API
// email entry always carries an unavailable tenure — Hunter provides no
// employment start/end dates so current-role tenure cannot be derived (no
// fabrication).
func TestToPerson_TenureUnavailable(t *testing.T) {
	t.Parallel()
	src := &apiEmail{
		Value:      "alice@example.com",
		FirstName:  "Alice",
		LastName:   "Smith",
		Position:   "Engineer",
		Confidence: 85,
	}
	got := toPerson(src)

	assert.False(t, got.Tenure.Available, "Hunter tenure must always be unavailable (no employment dates)")
	assert.Equal(t, "hunter", got.Tenure.Source, "Source must be 'hunter'")
	assert.Equal(t, "no employment dates from source", got.Tenure.Reason,
		"Reason must explain why tenure is unavailable")
	assert.Equal(t, 0, got.Tenure.Months, "Months must be zero for unavailable tenure")
	assert.False(t, got.Tenure.Current, "Current must be false for unavailable tenure")
	assert.Empty(t, got.Tenure.Precision, "Precision must be empty for unavailable tenure")
}
