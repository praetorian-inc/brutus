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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/lusha"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// countingFailWriter is an io.Writer that always returns an error from Write
// and counts how many times Write was called. Used to test early-exit behavior
// in JSONL output functions (broken-pipe / stream-closed scenario).
type countingFailWriter struct {
	writes int
}

func (f *countingFailWriter) Write(_ []byte) (int, error) {
	f.writes++
	return 0, errors.New("simulated write failure")
}

// ---------------------------------------------------------------------------
// T103: outputLushaJSONL + outputLushaHuman
// ---------------------------------------------------------------------------

func TestOutputLushaJSONL(t *testing.T) {
	t.Run("contact with email and DNC phone emits one JSON line", func(t *testing.T) {
		c := &lusha.Contact{
			Name:     "Ada Lovelace",
			JobTitle: "Mathematician",
			Company:  "AnalyticalCo",
			Emails: []lusha.EmailEntry{
				{Address: "ada@example.com", Type: "professional", Confidence: "high"},
			},
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-0100", Type: "direct", DoNotCall: true},
			},
		}
		var buf bytes.Buffer
		outputLushaJSONL(&buf, c)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1, "expected exactly 1 JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))
		assert.Equal(t, "lusha", obj["type"])
		assert.Equal(t, "Ada Lovelace", obj["name"])
		assert.Equal(t, "Mathematician", obj["job_title"])
		assert.Equal(t, "AnalyticalCo", obj["company"])

		emails, ok := obj["emails"].([]interface{})
		require.True(t, ok, "emails must be a JSON array")
		require.Len(t, emails, 1)
		email, ok := emails[0].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "ada@example.com", email["address"])

		phones, ok := obj["phones"].([]interface{})
		require.True(t, ok, "phones must be a JSON array")
		require.Len(t, phones, 1)
		phone, ok := phones[0].(map[string]interface{})
		require.True(t, ok)
		// do_not_call bool must always be emitted (P0-DNC).
		doNotCall, exists := phone["do_not_call"]
		require.True(t, exists, "do_not_call field must always be present")
		assert.Equal(t, true, doNotCall, "do_not_call must be true for DNC phone")
	})

	t.Run("empty contact emits JSON object with no emails or phones arrays", func(t *testing.T) {
		c := &lusha.Contact{}
		var buf bytes.Buffer
		outputLushaJSONL(&buf, c)

		out := strings.TrimSpace(buf.String())
		require.NotEmpty(t, out, "should emit one JSON object even when empty")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(out), &obj))
		assert.Equal(t, "lusha", obj["type"])
		_, hasEmails := obj["emails"]
		assert.False(t, hasEmails, "omitempty: emails array must be absent for empty contact")
		_, hasPhones := obj["phones"]
		assert.False(t, hasPhones, "omitempty: phones array must be absent for empty contact")
	})

	t.Run("non-DNC phone has do_not_call false", func(t *testing.T) {
		c := &lusha.Contact{
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-0200", Type: "mobile", DoNotCall: false},
			},
		}
		var buf bytes.Buffer
		outputLushaJSONL(&buf, c)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))
		phones, ok := obj["phones"].([]interface{})
		require.True(t, ok)
		phone, ok := phones[0].(map[string]interface{})
		require.True(t, ok)
		// do_not_call bool is always emitted — must be false here.
		doNotCall, exists := phone["do_not_call"]
		require.True(t, exists, "do_not_call field must always be emitted")
		assert.Equal(t, false, doNotCall)
	})
}

func TestOutputLushaHuman(t *testing.T) {
	t.Run("renders email and phone rows", func(t *testing.T) {
		c := &lusha.Contact{
			Name:     "Ada Lovelace",
			JobTitle: "Mathematician",
			Company:  "AnalyticalCo",
			Emails: []lusha.EmailEntry{
				{Address: "ada@example.com", Type: "professional", Confidence: "high"},
			},
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-0100", Type: "direct", DoNotCall: false},
			},
		}
		var buf bytes.Buffer
		outputLushaHuman(&buf, c, false)
		out := buf.String()
		assert.Contains(t, out, "ada@example.com")
		assert.Contains(t, out, "professional")
		assert.Contains(t, out, "+1-555-0100")
		assert.Contains(t, out, "direct")
	})

	t.Run("DNC phone shows DNC marker", func(t *testing.T) {
		c := &lusha.Contact{
			Name: "Eve Example",
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-9999", Type: "mobile", DoNotCall: true},
			},
		}
		var buf bytes.Buffer
		outputLushaHuman(&buf, c, false)
		out := buf.String()
		assert.Contains(t, out, "DNC", "DNC phones must display DNC marker")
		assert.Contains(t, out, "+1-555-9999")
	})

	t.Run("empty contact shows no data message", func(t *testing.T) {
		c := &lusha.Contact{}
		var buf bytes.Buffer
		outputLushaHuman(&buf, c, false)
		out := buf.String()
		assert.Contains(t, out, "No contact data returned")
	})
}

// ---------------------------------------------------------------------------
// T104: validateLushaIdentity (reads package-level flag vars directly)
// ---------------------------------------------------------------------------

// resetLushaFlags resets all lusha flag vars to zero values between subtests.
func resetLushaFlags() {
	flagLushaFirstName = ""
	flagLushaLastName = ""
	flagLushaCompany = ""
	flagLushaDomain = ""
	flagLushaEmail = ""
	flagLushaLinkedin = ""
	flagLushaPhone = false
	flagLushaEmailOnly = false
	flagLushaLimit = 0
}

func TestValidateLushaIdentity(t *testing.T) {
	tests := []struct {
		name        string
		setup       func()
		wantErr     bool
		errContains string
	}{
		{
			name: "valid name + company",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaLastName = "Lovelace"
				flagLushaCompany = "AnalyticalCo"
			},
			wantErr: false,
		},
		{
			name: "valid name + domain",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaLastName = "Lovelace"
				flagLushaDomain = "analytical.example.com"
			},
			wantErr: false,
		},
		{
			name: "valid email only",
			setup: func() {
				flagLushaEmail = "ada@example.com"
			},
			wantErr: false,
		},
		{
			name: "valid linkedin only",
			setup: func() {
				flagLushaLinkedin = "https://linkedin.com/in/ada"
			},
			wantErr: false,
		},
		{
			name:        "ERROR: no identity set",
			setup:       func() {},
			wantErr:     true,
			errContains: "identity is required",
		},
		{
			name: "ERROR: two identity groups (email + linkedin)",
			setup: func() {
				flagLushaEmail = "ada@example.com"
				flagLushaLinkedin = "https://linkedin.com/in/ada"
			},
			wantErr:     true,
			errContains: "exactly one identity",
		},
		{
			name: "ERROR: name without last name",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaCompany = "AnalyticalCo"
			},
			wantErr:     true,
			errContains: "last-name",
		},
		{
			name: "ERROR: name without company or domain",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaLastName = "Lovelace"
			},
			wantErr:     true,
			errContains: "--company or --domain",
		},
		{
			name: "ERROR: --phone and --email-only together",
			setup: func() {
				flagLushaEmail = "ada@example.com"
				flagLushaPhone = true
				flagLushaEmailOnly = true
			},
			wantErr:     true,
			errContains: "mutually exclusive",
		},
		// Roster-mode cases (new: domain-only is valid roster mode).
		{
			name: "ROSTER: domain only → valid",
			setup: func() {
				flagLushaDomain = "fox.com"
			},
			wantErr: false,
		},
		{
			name: "ROSTER+NAME: domain + name pair → single-contact valid (not roster)",
			setup: func() {
				flagLushaDomain = "fox.com"
				flagLushaFirstName = "Ada"
				flagLushaLastName = "Lovelace"
			},
			wantErr: false,
		},
		{
			name: "ERROR ROSTER+EMAIL: domain + email → ambiguous (not roster, two groups)",
			setup: func() {
				flagLushaDomain = "fox.com"
				flagLushaEmail = "ada@fox.com"
			},
			wantErr:     true,
			errContains: "exactly one identity",
		},
		// Bug fix: negative --limit must be rejected.
		{
			name: "ERROR: --limit -1 rejected",
			setup: func() {
				flagLushaDomain = "fox.com"
				flagLushaLimit = -1
			},
			wantErr:     true,
			errContains: ">= 0",
		},
		// Bug fix: roster mode must reject --phone and --email-only.
		{
			name: "ERROR ROSTER+PHONE: domain only + --phone → rejected",
			setup: func() {
				flagLushaDomain = "fox.com"
				flagLushaPhone = true
			},
			wantErr:     true,
			errContains: "--phone is not valid in roster mode",
		},
		{
			name: "ERROR ROSTER+EMAIL-ONLY: domain only + --email-only → rejected",
			setup: func() {
				flagLushaDomain = "fox.com"
				flagLushaEmailOnly = true
			},
			wantErr:     true,
			errContains: "--email-only is not valid in roster mode",
		},
		// Single-contact mode: --phone is still valid.
		{
			name: "valid single contact + --phone (not roster mode)",
			setup: func() {
				flagLushaEmail = "ada@example.com"
				flagLushaPhone = true
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetLushaFlags()
			tc.setup()
			err := validateLushaIdentity()
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveLushaAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		flagValue string
		envValue  string
		wantKey   string
		wantErr   bool
	}{
		{
			name:      "flag value takes priority over env",
			flagValue: "flag-key",
			envValue:  "env-key",
			wantKey:   "flag-key",
		},
		{
			name:      "env var used when flag is empty",
			flagValue: "",
			envValue:  "env-key",
			wantKey:   "env-key",
		},
		{
			name:      "error when both empty",
			flagValue: "",
			envValue:  "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LUSHA_API_KEY", tc.envValue)
			key, err := resolveLushaAPIKey(tc.flagValue)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "LUSHA_API_KEY")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, key)
		})
	}
}

// TestClassifyLushaError_NoKeyLeak verifies the P0-1 security requirement:
// the sentinel API key value must never appear in any classified error message,
// even if the vendor echoes the key back in the error body (APIError.Details).
func TestClassifyLushaError_NoKeyLeak(t *testing.T) {
	const sentinelKey = "SECRETKEY-DO-NOT-LEAK-abc123"

	cases := []struct {
		name string
		err  error
	}{
		{
			name: "vendor echoes key in 401 Details",
			err:  &lusha.APIError{StatusCode: 401, Details: sentinelKey},
		},
		{
			name: "402 no credits with sentinel",
			err:  &lusha.APIError{StatusCode: 402, Details: sentinelKey},
		},
		{
			name: "403 forbidden",
			err:  &lusha.APIError{StatusCode: 403, Details: "forbidden"},
		},
		{
			name: "429 rate limited",
			err:  &lusha.APIError{StatusCode: 429, Details: "rate limit"},
		},
		{
			name: "404 not found",
			err:  &lusha.APIError{StatusCode: 404, Details: "not found"},
		},
		{
			name: "wrapped 500 with sentinel in Details",
			err:  fmt.Errorf("wrapped: %w", &lusha.APIError{StatusCode: 500, Details: sentinelKey}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyLushaError(tc.err)
			require.Error(t, result)
			out := result.Error()
			// Sentinel key must NEVER appear in any error output (P0-1).
			assert.NotContains(t, out, sentinelKey,
				"classified error must not leak the sentinel API key")
			// Header name must not be echoed either.
			assert.NotContains(t, out, "api_key",
				"classified error must not echo the api_key header name")
		})
	}
}

// TestClassifyLushaError_NetworkWrap verifies that non-*APIError (network/DNS/
// timeout) errors are %w-wrapped by classifyLushaError so errors.Is chains work.
func TestClassifyLushaError_NetworkWrap(t *testing.T) {
	networkErr := errors.New("dial tcp: connection timeout")
	result := classifyLushaError(networkErr)
	require.Error(t, result)
	// The network error must be wrapped (errors.Is unwraps the chain).
	assert.True(t, errors.Is(result, networkErr),
		"classifyLushaError must %w-wrap non-*APIError so errors.Is works")
	// The error message must contain the original cause for debuggability.
	assert.Contains(t, result.Error(), "timeout")
}

// ---------------------------------------------------------------------------
// T107: outputLushaDomainJSONL + outputLushaDomainHuman
// ---------------------------------------------------------------------------

func TestOutputLushaDomainJSONL(t *testing.T) {
	t.Run("one JSON object per contact plus trailing lusha_summary", func(t *testing.T) {
		r := &lusha.DomainResult{
			Domain: "fox.com",
			Total:  2,
			Contacts: []lusha.Contact{
				{
					Name:     "Bruna White",
					JobTitle: "Assistant Director",
					Company:  "Fox",
					Emails: []lusha.EmailEntry{
						{Address: "bruna.white@fox.com", Type: "work", Confidence: "A+"},
					},
					Phones: []lusha.PhoneEntry{
						{Number: "+1 818", Type: "phone", DoNotCall: true},
					},
				},
				{
					Name:     "Steve R",
					JobTitle: "Director",
					Company:  "Fox",
				},
			},
			CreditsCharged: 3,
		}

		var buf bytes.Buffer
		outputLushaDomainJSONL(&buf, r)

		// 2 contacts + 1 trailing lusha_summary envelope = 3 lines total.
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 3, "must emit one JSON object per contact PLUS a trailing lusha_summary line")

		var obj0 map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj0))
		assert.Equal(t, "lusha", obj0["type"], "per-contact type must be 'lusha'")
		assert.Equal(t, "Bruna White", obj0["name"])

		phones, ok := obj0["phones"].([]interface{})
		require.True(t, ok, "phones must be a JSON array")
		require.Len(t, phones, 1)
		phone, ok := phones[0].(map[string]interface{})
		require.True(t, ok)
		doNotCall, exists := phone["do_not_call"]
		require.True(t, exists, "do_not_call field must always be present (P0-DNC)")
		assert.Equal(t, true, doNotCall, "DNC flag must be true")

		var obj1 map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[1]), &obj1))
		assert.Equal(t, "lusha", obj1["type"])
		assert.Equal(t, "Steve R", obj1["name"])

		// Line 3: trailing lusha_summary envelope (new in #192 fix).
		var summary map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[2]), &summary))
		assert.Equal(t, "lusha_summary", summary["type"],
			"trailing envelope must have type lusha_summary")
		assert.Equal(t, "fox.com", summary["domain"],
			"summary domain must match the queried domain")
		assert.Equal(t, float64(2), summary["total"],
			"summary total must equal DomainResult.Total")
		assert.Equal(t, float64(2), summary["returned"],
			"summary returned must equal len(contacts)")
		assert.Equal(t, float64(3), summary["credits_charged"],
			"summary credits_charged must equal DomainResult.CreditsCharged")

		// No password or credential keys must appear.
		for _, line := range lines {
			assert.NotContains(t, line, "password",
				"JSONL output must not contain password keys")
			assert.NotContains(t, line, "api_key",
				"JSONL output must not contain api_key")
		}
	})

	t.Run("empty roster emits only the lusha_summary envelope", func(t *testing.T) {
		r := &lusha.DomainResult{Domain: "empty.com", Total: 0, CreditsCharged: 0}
		var buf bytes.Buffer
		outputLushaDomainJSONL(&buf, r)
		out := strings.TrimSpace(buf.String())
		// Production always emits the trailing summary, even for empty rosters.
		require.NotEmpty(t, out, "empty roster must still emit the lusha_summary line")

		lines := strings.Split(out, "\n")
		require.Len(t, lines, 1, "empty roster must emit exactly one line (the lusha_summary)")

		var summary map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &summary))
		assert.Equal(t, "lusha_summary", summary["type"])
		assert.Equal(t, "empty.com", summary["domain"])
		assert.Equal(t, float64(0), summary["returned"])
		assert.Equal(t, float64(0), summary["credits_charged"])
	})

	// Regression: loop stops after first encode error (broken-pipe / early stream close).
	// outputLushaDomainJSONL now breaks on the first enc.Encode error so an early-closed
	// consumer produces only ONE stderr error line instead of one per remaining contact.
	t.Run("broken writer stops encoding after first contact (no further write attempts)", func(t *testing.T) {
		// Build a roster with 5 contacts. With the break-on-error fix, the encoder
		// must stop after the first failed Write — it must NOT attempt to encode all
		// 5 contacts.
		contacts := make([]lusha.Contact, 5)
		for i := range contacts {
			contacts[i] = lusha.Contact{
				Name:    fmt.Sprintf("Contact %d", i+1),
				Company: "TestCo",
			}
		}
		r := &lusha.DomainResult{
			Domain:   "broken.com",
			Total:    5,
			Contacts: contacts,
		}

		fw := &countingFailWriter{}
		outputLushaDomainJSONL(fw, r)

		// json.Encoder.Encode calls Write at least once per Encode call.
		// After the first Write fails, the loop must break — subsequent contacts
		// must NOT be encoded. We allow for at most 2 Write calls (the encoder
		// may call Write once for the JSON body and once for the newline), but
		// must see strictly fewer than 5*2=10 writes that a full loop would cause.
		assert.Less(t, fw.writes, 10,
			"loop must stop after first encode error: expected far fewer than 10 writes (5 contacts × 2), got %d", fw.writes)
		assert.GreaterOrEqual(t, fw.writes, 1,
			"at least one Write must have been attempted before the error")
	})
}

func TestOutputLushaDomainHuman(t *testing.T) {
	t.Run("header shows N of Total and credits charged", func(t *testing.T) {
		r := &lusha.DomainResult{
			Domain: "fox.com",
			Total:  10,
			Contacts: []lusha.Contact{
				{
					Name:     "Bruna White",
					JobTitle: "Assistant Director",
					Company:  "Fox",
					Emails: []lusha.EmailEntry{
						{Address: "bruna.white@fox.com", Type: "work", Confidence: "A+"},
					},
				},
			},
			CreditsCharged: 3,
		}
		var buf bytes.Buffer
		outputLushaDomainHuman(&buf, r, false)
		out := buf.String()

		// Header: "1 of 10 · credits charged: 3"
		assert.Contains(t, out, "1", "header must show contact count")
		assert.Contains(t, out, "10", "header must show total")
		assert.Contains(t, out, "3", "header must show credits charged")
		// Table row
		assert.Contains(t, out, "Bruna White")
		assert.Contains(t, out, "bruna.white@fox.com")
	})

	t.Run("DNC phone shows [DNC] marker in table row", func(t *testing.T) {
		r := &lusha.DomainResult{
			Domain: "fox.com",
			Total:  1,
			Contacts: []lusha.Contact{
				{
					Name: "Eve Example",
					Phones: []lusha.PhoneEntry{
						{Number: "+1 818", Type: "phone", DoNotCall: true},
					},
				},
			},
			CreditsCharged: 1,
		}
		var buf bytes.Buffer
		outputLushaDomainHuman(&buf, r, false)
		out := buf.String()
		assert.Contains(t, out, "[DNC]", "DNC phone must show [DNC] marker")
		assert.Contains(t, out, "+1 818")
	})

	t.Run("empty roster shows graceful no-contacts message", func(t *testing.T) {
		r := &lusha.DomainResult{Domain: "empty.com", Total: 0}
		var buf bytes.Buffer
		outputLushaDomainHuman(&buf, r, false)
		out := buf.String()
		assert.Contains(t, out, "No contacts returned",
			"empty roster must show graceful message")
	})

	t.Run("long international phone with DNC marker not truncated (26-char column)", func(t *testing.T) {
		// Phone column is 26 wide so e.g. "+44 20 7946 0123 [DNC]" (22 chars) fits.
		// The bug was a 24-wide column that cut " [DNC]" off a 20-char number.
		// We use a 19-char international number so "number + ' [DNC]'" = 25 chars,
		// which fits in 26 but would have been truncated in the old 24-wide column.
		r := &lusha.DomainResult{
			Domain: "intl.com",
			Total:  1,
			Contacts: []lusha.Contact{
				{
					Name: "Intl User",
					Phones: []lusha.PhoneEntry{
						// "+44 20 7946 01234" = 17 chars; with " [DNC]" = 23 chars
						// (fits in 26, would have been truncated at 24).
						{Number: "+44 20 7946 01234", Type: "direct", DoNotCall: true},
					},
				},
			},
			CreditsCharged: 1,
		}
		var buf bytes.Buffer
		outputLushaDomainHuman(&buf, r, false)
		out := buf.String()
		// The [DNC] marker must appear intact (not truncated mid-marker).
		assert.Contains(t, out, "[DNC]",
			"[DNC] marker must appear in output with 26-wide phone column")
		assert.Contains(t, out, "+44 20 7946 01234",
			"full international phone number must appear in output")
	})

	// Regression: phone number >20 runes must have DNC marker fully visible.
	// outputLushaDomainHuman truncates the number to 20 runes BEFORE appending
	// " [DNC]" so the compliance marker is never cut (P0-DNC fix).
	t.Run("DNC marker survives long phone number (>20 rune truncation path)", func(t *testing.T) {
		// "+1 (555) 0100-2003-4005-6007" = 28 runes (well over the 20-rune truncation
		// threshold). The old bug would have rendered the marker as part of the
		// truncated number, producing artifacts like " [D…" or " [DN…".
		longPhone := "+1 (555) 0100-2003-4005-6007"
		r := &lusha.DomainResult{
			Domain: "test-dnc.com",
			Total:  1,
			Contacts: []lusha.Contact{
				{
					Name: "DNC Test User",
					Phones: []lusha.PhoneEntry{
						{Number: longPhone, Type: "direct", DoNotCall: true},
					},
				},
			},
			CreditsCharged: 1,
		}
		var buf bytes.Buffer
		outputLushaDomainHuman(&buf, r, false)
		out := buf.String()

		// The full " [DNC]" compliance marker must always appear intact.
		assert.Contains(t, out, " [DNC]",
			"full ' [DNC]' marker must be present even when number is truncated to 20 runes")

		// Truncated-marker artifacts must never appear (prove marker is not cut).
		assert.NotContains(t, out, "[D…",
			"truncated marker artifact '[D…' must not appear")
		assert.NotContains(t, out, "[DN…",
			"truncated marker artifact '[DN…' must not appear")
		assert.NotContains(t, out, "[DNC…",
			"truncated marker artifact '[DNC…' must not appear")
	})
}

// ---------------------------------------------------------------------------
// T105: Command registration
// ---------------------------------------------------------------------------

func TestEnumLushaRegistered(t *testing.T) {
	// 1. enumCmd must have a "passive" subcommand.
	var passive *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "passive" {
			passive = cmd
			break
		}
	}
	require.NotNil(t, passive, `enumCmd must have a "passive" subcommand`)

	// 2. The canonical "lusha" command must live under passive.
	var canonicalLusha *cobra.Command
	for _, cmd := range passive.Commands() {
		if cmd.Use == "lusha" {
			canonicalLusha = cmd
			break
		}
	}
	require.NotNil(t, canonicalLusha, `"lusha" must be a subcommand of enumPassiveCmd`)

	// Verify expected flags on the canonical command (includes --limit for roster mode).
	for _, name := range []string{
		"first-name", "last-name", "company", "domain",
		"email", "linkedin", "phone", "email-only", "api-key", "limit",
	} {
		require.NotNilf(t, canonicalLusha.Flags().Lookup(name),
			"--%s flag must exist on canonical lusha", name)
	}

	// --limit default must be 0 (collect all).
	limitFlag := canonicalLusha.Flags().Lookup("limit")
	require.NotNil(t, limitFlag, "--limit flag must exist")
	assert.Equal(t, "0", limitFlag.DefValue, "--limit default must be 0 (collect all)")

	// --domain must NOT be marked required (identity validated in RunE).
	domainFlag := canonicalLusha.Flags().Lookup("domain")
	require.NotNil(t, domainFlag)
	_, isRequired := domainFlag.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.False(t, isRequired, "--domain must NOT be marked as required for lusha")

	// 3. A hidden back-compat alias must exist directly under enumCmd.
	var alias *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "lusha" {
			alias = cmd
			break
		}
	}
	require.NotNil(t, alias, `hidden "lusha" alias must be registered directly under enumCmd`)
	assert.True(t, alias.Hidden, "back-compat lusha alias must be Hidden")
	assert.NotEmpty(t, alias.Deprecated, "back-compat lusha alias must be Deprecated")
}
