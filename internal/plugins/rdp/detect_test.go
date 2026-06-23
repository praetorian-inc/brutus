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
	result := DetectStickyKeys(ctx, "127.0.0.1:1", 2*time.Second, "(sticky-keys)", false)

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.Equal(t, "(sticky-keys)", result.Username)
	assert.False(t, result.Success)
	assert.Contains(t, result.Banner, "INDETERMINATE")
	assert.True(t, result.Indeterminate)
}

func TestDetectStickyKeys_ResultFields(t *testing.T) {
	ctx := context.Background()
	result := DetectStickyKeys(ctx, "198.51.100.1:3389", 500*time.Millisecond, "(sticky-keys)", false)

	assert.NotNil(t, result)
	assert.Equal(t, "(sticky-keys)", result.Username)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "198.51.100.1:3389", result.Target)
}

func TestDetectUtilman_ConnectionError(t *testing.T) {
	ctx := context.Background()
	result := DetectUtilman(ctx, "127.0.0.1:1", 2*time.Second, "(utilman)", false)

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.Equal(t, "(utilman)", result.Username)
	assert.False(t, result.Success)
	assert.Contains(t, result.Banner, "INDETERMINATE")
	assert.True(t, result.Indeterminate)
}

func TestDetectUtilman_ResultFields(t *testing.T) {
	ctx := context.Background()
	result := DetectUtilman(ctx, "198.51.100.1:3389", 500*time.Millisecond, "(utilman)", false)

	assert.NotNil(t, result)
	assert.Equal(t, "(utilman)", result.Username)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "198.51.100.1:3389", result.Target)
}

// TestMapStickyResult tests the mapping from StickyKeysResult to brutus.Result,
// covering the indeterminate, not-performed, clean, and confirmed cases.
func TestMapStickyResult(t *testing.T) {
	tests := []struct {
		name              string
		input             *StickyKeysResult
		username          string
		wantIndeterminate bool
		wantSuccess       bool
		wantBannerContain string
		wantBannerExclude string
	}{
		{
			name: "performed indeterminate verdict",
			input: &StickyKeysResult{
				Performed:      true,
				OverallVerdict: "indeterminate",
			},
			username:          "testuser",
			wantIndeterminate: true,
			wantSuccess:       false,
			wantBannerContain: "INDETERMINATE",
		},
		{
			name: "not performed (dial fail with skip reason)",
			input: &StickyKeysResult{
				Performed:  false,
				SkipReason: "connection refused",
			},
			username:          "testuser",
			wantIndeterminate: true,
			wantSuccess:       false,
			wantBannerContain: "INDETERMINATE",
			wantBannerExclude: "skipped",
		},
		{
			name: "clean verdict",
			input: &StickyKeysResult{
				Performed:      true,
				OverallVerdict: "clean",
			},
			username:          "testuser",
			wantIndeterminate: false,
			wantSuccess:       false,
		},
		{
			name: "backdoor_confirmed verdict",
			input: &StickyKeysResult{
				Performed:      true,
				OverallVerdict: "backdoor_confirmed",
				Confidence:     0.99,
			},
			username:          "testuser",
			wantIndeterminate: false,
			wantSuccess:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := mapStickyResult(tc.input, tc.username)
			assert.NotNil(t, result)
			assert.Equal(t, tc.wantIndeterminate, result.Indeterminate, "Indeterminate mismatch")
			assert.Equal(t, tc.wantSuccess, result.Success, "Success mismatch")
			if tc.wantBannerContain != "" {
				assert.Contains(t, result.Banner, tc.wantBannerContain)
			}
			if tc.wantBannerExclude != "" {
				assert.NotContains(t, result.Banner, tc.wantBannerExclude)
			}
		})
	}
}

// TestMapUtilmanResult mirrors TestMapStickyResult for the utilman mapper.
func TestMapUtilmanResult(t *testing.T) {
	tests := []struct {
		name              string
		input             *UtilmanResult
		username          string
		wantIndeterminate bool
		wantSuccess       bool
		wantBannerContain string
		wantBannerExclude string
	}{
		{
			name: "performed indeterminate verdict",
			input: &UtilmanResult{
				Performed:      true,
				OverallVerdict: "indeterminate",
			},
			username:          "testuser",
			wantIndeterminate: true,
			wantSuccess:       false,
			wantBannerContain: "INDETERMINATE",
		},
		{
			name: "not performed (dial fail with skip reason)",
			input: &UtilmanResult{
				Performed:  false,
				SkipReason: "connection refused",
			},
			username:          "testuser",
			wantIndeterminate: true,
			wantSuccess:       false,
			wantBannerContain: "INDETERMINATE",
			wantBannerExclude: "skipped",
		},
		{
			name: "clean verdict",
			input: &UtilmanResult{
				Performed:      true,
				OverallVerdict: "clean",
			},
			username:          "testuser",
			wantIndeterminate: false,
			wantSuccess:       false,
		},
		{
			name: "backdoor_confirmed verdict",
			input: &UtilmanResult{
				Performed:      true,
				OverallVerdict: "backdoor_confirmed",
				Confidence:     0.99,
			},
			username:          "testuser",
			wantIndeterminate: false,
			wantSuccess:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := mapUtilmanResult(tc.input, tc.username)
			assert.NotNil(t, result)
			assert.Equal(t, tc.wantIndeterminate, result.Indeterminate, "Indeterminate mismatch")
			assert.Equal(t, tc.wantSuccess, result.Success, "Success mismatch")
			if tc.wantBannerContain != "" {
				assert.Contains(t, result.Banner, tc.wantBannerContain)
			}
			if tc.wantBannerExclude != "" {
				assert.NotContains(t, result.Banner, tc.wantBannerExclude)
			}
		})
	}
}

// TestStabilizedVerdict verifies the cardinal false-negative guard (I2): only a
// "clean" verdict on an unstabilized render is downgraded to "indeterminate".
// Positive verdicts (backdoor_confirmed, backdoor_likely, vulnerable) must never
// be downgraded regardless of stabilization, and "indeterminate" input is left
// unchanged.
//
// This test is RED until the developer extracts the inline guard at
// detect.go:272-274 / 330-332 into:
//
//	func stabilizedVerdict(verdict string, stabilized bool) string
func TestStabilizedVerdict(t *testing.T) {
	tests := []struct {
		name       string
		verdict    string
		stabilized bool
		want       string
	}{
		{
			name:       "clean unstabilized -> indeterminate (cardinal flip)",
			verdict:    "clean",
			stabilized: false,
			want:       verdictIndeterminate,
		},
		{
			name:       "clean stabilized -> clean (no flip)",
			verdict:    "clean",
			stabilized: true,
			want:       "clean",
		},
		{
			name:       "backdoor_confirmed unstabilized -> unchanged (positive never downgraded)",
			verdict:    "backdoor_confirmed",
			stabilized: false,
			want:       "backdoor_confirmed",
		},
		{
			name:       "backdoor_likely unstabilized -> unchanged (positive never downgraded)",
			verdict:    "backdoor_likely",
			stabilized: false,
			want:       "backdoor_likely",
		},
		{
			name:       "vulnerable unstabilized -> unchanged (positive never downgraded)",
			verdict:    "vulnerable",
			stabilized: false,
			want:       "vulnerable",
		},
		{
			name:       "indeterminate unstabilized -> unchanged (already indeterminate)",
			verdict:    verdictIndeterminate,
			stabilized: false,
			want:       verdictIndeterminate,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stabilizedVerdict(tc.verdict, tc.stabilized)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSettled verifies the wall-clock settle decision used by pumpSession:
// a framebuffer counts as settled only once BOTH a minimum pump time
// (minPumpTime) has elapsed since the pump started AND the framebuffer has
// been unchanged for at least the quiet window (settleQuietWindow). A brief
// mid-paint pause that is shorter than the quiet window must NOT be treated as
// settled, which is the root cause of the half-painted-frame capture bug.
func TestSettled(t *testing.T) {
	start := time.Time{}

	tests := []struct {
		name       string
		now        time.Duration // since start
		lastChange time.Duration // since start
		want       bool
	}{
		{
			name:       "before minPumpTime never settles even if quiet",
			now:        minPumpTime - 100*time.Millisecond,
			lastChange: 0, // quiet the whole time
			want:       false,
		},
		{
			name:       "after minPumpTime but quiet window not yet elapsed (mid-paint pause)",
			now:        minPumpTime + 500*time.Millisecond,
			lastChange: minPumpTime + 500*time.Millisecond - (settleQuietWindow - 100*time.Millisecond),
			want:       false,
		},
		{
			name:       "after minPumpTime and quiet window elapsed -> settled",
			now:        minPumpTime + settleQuietWindow + 100*time.Millisecond,
			lastChange: 0,
			want:       true,
		},
		{
			name:       "quiet window satisfied but minPumpTime not -> not settled",
			now:        settleQuietWindow + 100*time.Millisecond,
			lastChange: 0,
			want:       settleQuietWindow+100*time.Millisecond >= minPumpTime,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := settled(start, start.Add(tc.lastChange), start.Add(tc.now))
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestScanTypeLabeling verifies that StickyKeys and Utilman scans
// are labeled with distinct scan_type values for JSONL output.
func TestScanTypeLabeling(t *testing.T) {
	ctx := context.Background()

	stickyResult := DetectStickyKeys(ctx, "198.51.100.1:3389", 500*time.Millisecond, "(sticky-keys)", false)
	assert.NotNil(t, stickyResult)
	assert.Equal(t, "sticky_keys", stickyResult.ScanType, "DetectStickyKeys should set ScanType to 'sticky_keys'")

	utilmanResult := DetectUtilman(ctx, "198.51.100.1:3389", 500*time.Millisecond, "(utilman)", false)
	assert.NotNil(t, utilmanResult)
	assert.Equal(t, "utilman", utilmanResult.ScanType, "DetectUtilman should set ScanType to 'utilman'")
}
