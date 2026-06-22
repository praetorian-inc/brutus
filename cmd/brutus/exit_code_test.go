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

package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// TestScanExitError tests the precedence rules for the scan exit error helper:
//   - hasSuccess=true (even with an indeterminate result present) → nil
//   - hasSuccess=false + at least one Indeterminate==true → errIndeterminate
//   - hasSuccess=false + none indeterminate → errNoSuccess
func TestScanExitError(t *testing.T) {
	tests := []struct {
		name       string
		results    []brutus.Result
		hasSuccess bool
		wantErr    error // nil means no error expected
	}{
		{
			name: "success true with no indeterminate results",
			results: []brutus.Result{
				{Success: true, Indeterminate: false},
			},
			hasSuccess: true,
			wantErr:    nil,
		},
		{
			name: "success true even when an indeterminate result is present",
			results: []brutus.Result{
				{Success: true, Indeterminate: false},
				{Success: false, Indeterminate: true},
			},
			hasSuccess: true,
			wantErr:    nil,
		},
		{
			name: "success false with one indeterminate result",
			results: []brutus.Result{
				{Success: false, Indeterminate: true},
			},
			hasSuccess: false,
			wantErr:    errIndeterminate,
		},
		{
			name: "success false with multiple results one of which is indeterminate",
			results: []brutus.Result{
				{Success: false, Indeterminate: false},
				{Success: false, Indeterminate: true},
				{Success: false, Indeterminate: false},
			},
			hasSuccess: false,
			wantErr:    errIndeterminate,
		},
		{
			name: "success false with no indeterminate results",
			results: []brutus.Result{
				{Success: false, Indeterminate: false},
				{Success: false, Indeterminate: false},
			},
			hasSuccess: false,
			wantErr:    errNoSuccess,
		},
		{
			name:       "success false with empty results slice",
			results:    []brutus.Result{},
			hasSuccess: false,
			wantErr:    errNoSuccess,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := scanExitError(tc.results, tc.hasSuccess)
			if tc.wantErr == nil {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr),
					"expected errors.Is(err, %v) but got %v", tc.wantErr, err)
			}
		})
	}
}
