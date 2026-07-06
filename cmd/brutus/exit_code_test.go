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
//   - any Indeterminate==true result → errIndeterminate (exit 2, takes precedence)
//   - all results clean (no Indeterminate) → nil (exit 0, clean scan is success)
//   - empty results → nil (exit 0)
func TestScanExitError(t *testing.T) {
	tests := []struct {
		name    string
		results []brutus.Result
		wantErr error // nil means no error expected
	}{
		{
			name: "all clean no indeterminate none successful",
			results: []brutus.Result{
				{Success: false, Indeterminate: false},
				{Success: false, Indeterminate: false},
			},
			wantErr: nil,
		},
		{
			name: "at least one success no indeterminate",
			results: []brutus.Result{
				{Success: true, Indeterminate: false},
				{Success: false, Indeterminate: false},
			},
			wantErr: nil,
		},
		{
			name: "one indeterminate none successful",
			results: []brutus.Result{
				{Success: false, Indeterminate: true},
			},
			wantErr: errIndeterminate,
		},
		{
			name: "success present but indeterminate takes precedence",
			results: []brutus.Result{
				{Success: true, Indeterminate: false},
				{Success: false, Indeterminate: true},
			},
			wantErr: errIndeterminate,
		},
		{
			name:    "empty results",
			results: []brutus.Result{},
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := scanExitError(tc.results)
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

// TestScanExitError_UnreachableIsExitZero locks in the cardinal-rule behavior:
// an unreachable result is terminal & non-retryable (Indeterminate=false), so
// scanExitError must return nil (exit 0), NOT errIndeterminate (exit 2).
//
// This is a characterisation test — it passes immediately because scanExitError
// already inspects only Indeterminate and unreachable results have
// Indeterminate=false. If a future change accidentally marks unreachable
// indeterminate, this test will catch the regression.
func TestScanExitError_UnreachableIsExitZero(t *testing.T) {
	// An unreachable result is terminal & non-retryable: Indeterminate=false.
	results := []brutus.Result{
		{Success: false, Indeterminate: false, Banner: "[INFO] unreachable (...)", ScanType: "sticky_keys"},
		{Success: false, Indeterminate: false, Banner: "[INFO] unreachable (...)", ScanType: "utilman"},
	}
	assert.NoError(t, scanExitError(results),
		"unreachable must NOT trigger errIndeterminate (exit 2); it is a completed-scan terminal state")
}
