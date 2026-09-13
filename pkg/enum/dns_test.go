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

package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentifyServices(t *testing.T) {
	tests := []struct {
		name      string
		record    string
		wantNames []string
		wantInd   string
	}{
		{
			name:      "microsoft365 MS=ms",
			record:    "MS=ms123456",
			wantNames: []string{"microsoft365"},
			wantInd:   "MS=ms",
		},
		{
			name:      "google site verification",
			record:    "google-site-verification=abc",
			wantNames: []string{"google"},
			wantInd:   "google-site-verification=",
		},
		{
			name:      "atlassian",
			record:    "atlassian-domain-verification=xyz",
			wantNames: []string{"atlassian"},
		},
		{
			name:      "spf outlook",
			record:    "v=spf1 include:spf.protection.outlook.com -all",
			wantNames: []string{"microsoft365"},
			wantInd:   "include:spf.protection.outlook.com",
		},
		{
			name:      "spf google",
			record:    "v=spf1 include:_spf.google.com ~all",
			wantNames: []string{"google"},
			wantInd:   "include:_spf.google.com",
		},
		{
			name:      "spf multiple includes",
			record:    "v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all",
			wantNames: []string{"google", "microsoft365"},
		},
		{
			name:      "pardot digits",
			record:    "pardot9.example",
			wantNames: []string{"pardot"},
			wantInd:   "pardot[digits]",
		},
		{
			name:      "pardot without digits is ignored",
			record:    "pardotX",
			wantNames: nil,
		},
		{
			name:      "unknown record",
			record:    "v=DMARC1; p=none",
			wantNames: nil,
		},
		{
			name:      "empty",
			record:    "",
			wantNames: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identifyServices(tt.record)
			var names []string
			for _, s := range got {
				names = append(names, s.Name)
				assert.Equal(t, tt.record, s.TXTRecord)
			}
			assert.ElementsMatch(t, tt.wantNames, names)
			if tt.wantInd != "" {
				require.NotEmpty(t, got)
				found := false
				for _, s := range got {
					if s.Indicator == tt.wantInd {
						found = true
					}
				}
				assert.True(t, found, "expected indicator %q in %+v", tt.wantInd, got)
			}
		})
	}
}
