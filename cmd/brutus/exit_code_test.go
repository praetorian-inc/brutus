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

	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

// TestScanExitError tests the precedence rules for the scan exit error helper:
//   - any rerun-eligible verdict → errIndeterminate (exit 2, takes precedence)
//   - every verdict final → nil (exit 0; a clean scan is a successful scan)
//   - no findings → nil (exit 0)
func TestScanExitError(t *testing.T) {
	tests := []struct {
		name     string
		findings []logon.Finding
		wantErr  error // nil means no error expected
	}{
		{
			name: "all clean, nothing found",
			findings: []logon.Finding{
				{Verdict: logon.VerdictClean},
				{Verdict: logon.VerdictClean},
			},
			wantErr: nil,
		},
		{
			name: "a backdoor found is still a completed scan",
			findings: []logon.Finding{
				{Verdict: logon.VerdictBackdoorConfirmed},
				{Verdict: logon.VerdictClean},
			},
			wantErr: nil,
		},
		{
			name: "no_backdoor is a completed scan, not a rerun",
			findings: []logon.Finding{
				{Verdict: logon.VerdictNoBackdoor},
				{Verdict: logon.VerdictNoBackdoor},
			},
			wantErr: nil,
		},
		{
			name:     "one indeterminate",
			findings: []logon.Finding{{Verdict: logon.VerdictIndeterminate}},
			wantErr:  errIndeterminate,
		},
		{
			name:     "canceled is a rerun candidate too",
			findings: []logon.Finding{{Verdict: logon.VerdictCanceled}},
			wantErr:  errIndeterminate,
		},
		{
			name: "a positive does not suppress a rerun elsewhere",
			findings: []logon.Finding{
				{Verdict: logon.VerdictBackdoorConfirmed},
				{Verdict: logon.VerdictIndeterminate},
			},
			wantErr: errIndeterminate,
		},
		{
			name:     "no findings",
			findings: []logon.Finding{},
			wantErr:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := scanExitError(tc.findings)
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

// TestScanExitError_TerminalStatesAreExitZero locks in the cardinal-rule
// behavior: nla_required and unreachable are terminal and non-retryable, so
// they must exit 0, not errIndeterminate (exit 2). Rerunning them cannot change
// the answer, so telling the operator to rerun would be wrong.
func TestScanExitError_TerminalStatesAreExitZero(t *testing.T) {
	for _, v := range []logon.Verdict{logon.VerdictNLARequired, logon.VerdictUnreachable} {
		findings := []logon.Finding{
			{Check: logon.BackdoorStickyKeys, Verdict: v},
			{Check: logon.BackdoorUtilman, Verdict: v},
		}
		assert.NoError(t, scanExitError(findings),
			"%s is a completed-scan terminal state; it must not trigger exit 2", v)
	}
}
