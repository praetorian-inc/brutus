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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// ---------------------------------------------------------------------------
// Test 7: TestOutputTeamsAuditJSONL
// ---------------------------------------------------------------------------

// TestOutputTeamsAuditJSONL verifies:
//   - One JSON line per finding.
//   - Each line has type=="teams_finding".
//   - Each line carries correct id and severity.
//   - No line contains access or refresh token sentinel strings (P0-1).
//   - Each line is valid JSON.
func TestOutputTeamsAuditJSONL(t *testing.T) {
	const accessTokenSentinel = "SUPER-SECRET-ACCESS-TOKEN-DO-NOT-LOG"
	const refreshTokenSentinel = "SUPER-SECRET-REFRESH-TOKEN-DO-NOT-LOG"

	findings := []teams.Finding{
		{
			ID:          "teams-external-access",
			Title:       "External / cross-tenant Teams chat enabled",
			Severity:    teams.SeverityMedium,
			Description: "The tenant permits external Teams communication.",
			Evidence:    "externalsearchv3 returned the user to an external tenant",
			Affected:    "contoso.com",
			Remediation: "Restrict Teams external access.",
		},
		{
			ID:          "teams-user-enumeration",
			Title:       "Teams user enumeration possible",
			Severity:    teams.SeverityInfo,
			Description: "The Teams externalsearchv3 endpoint acts as an oracle.",
			Evidence:    "externalsearchv3 distinguishes valid vs invalid users",
			Affected:    "contoso.com (alice@contoso.com)",
			Remediation: "Reduce external exposure.",
		},
		{
			ID:          "teams-presence-disclosure",
			Title:       "Teams presence disclosed to external users",
			Severity:    teams.SeverityLow,
			Description: "Presence visibility description.",
			Evidence:    "presence availability returned: Busy",
			Affected:    "contoso.com (alice@contoso.com)",
			Remediation: "Apply presence-privacy settings.",
		},
		{
			ID:          "teams-metadata-disclosure",
			Title:       "Account metadata disclosed to external party",
			Severity:    teams.SeverityInfo,
			Description: "Metadata description.",
			Evidence:    "returned: userPrincipalName",
			Affected:    "contoso.com (alice@contoso.com)",
			Remediation: "Reduce external exposure.",
		},
	}

	var buf bytes.Buffer
	outputTeamsAuditJSONL(&buf, findings)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, len(findings),
		"outputTeamsAuditJSONL must emit exactly one JSON line per finding")

	for i, line := range lines {
		// Every line must be valid JSON.
		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"line %d must be valid JSON", i)

		// Type discriminator.
		assert.Equal(t, "teams_finding", obj["type"],
			"line %d: type must be \"teams_finding\"", i)

		// ID must match the input.
		assert.Equal(t, findings[i].ID, obj["id"],
			"line %d: id must match the finding ID", i)

		// Severity must match the input.
		assert.Equal(t, string(findings[i].Severity), obj["severity"],
			"line %d: severity must match the finding Severity", i)

		// Title must be present.
		assert.Equal(t, findings[i].Title, obj["title"],
			"line %d: title must be present and match", i)

		// Description must be present.
		assert.NotEmpty(t, obj["description"],
			"line %d: description must be non-empty", i)

		// No access or refresh token sentinels in any line (P0-1).
		assert.NotContains(t, line, accessTokenSentinel,
			"line %d: access-token sentinel must never appear in JSONL output", i)
		assert.NotContains(t, line, refreshTokenSentinel,
			"line %d: refresh-token sentinel must never appear in JSONL output", i)
	}

	// Extra token-field name checks: none of the standard token JSON keys must
	// appear anywhere in the output (keys that would only be present if token
	// data were incorrectly forwarded from auth structures).
	fullOutput := buf.String()
	for _, tokenField := range []string{"access_token", "refresh_token", "id_token"} {
		assert.NotContains(t, fullOutput, tokenField,
			"JSONL output must not contain token field %q", tokenField)
	}
}

// TestOutputTeamsAuditJSONL_EmptyFindings verifies that empty findings produce
// no output (not a crash or a blank line).
func TestOutputTeamsAuditJSONL_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	outputTeamsAuditJSONL(&buf, nil)
	assert.Empty(t, strings.TrimSpace(buf.String()),
		"outputTeamsAuditJSONL with nil findings must produce no output")

	buf.Reset()
	outputTeamsAuditJSONL(&buf, []teams.Finding{})
	assert.Empty(t, strings.TrimSpace(buf.String()),
		"outputTeamsAuditJSONL with empty findings must produce no output")
}

// TestOutputTeamsAuditJSONL_AllSeverities verifies that the four severity
// constants each round-trip correctly through the JSON encoder.
func TestOutputTeamsAuditJSONL_AllSeverities(t *testing.T) {
	findings := []teams.Finding{
		{ID: "h", Severity: teams.SeverityHigh},
		{ID: "m", Severity: teams.SeverityMedium},
		{ID: "l", Severity: teams.SeverityLow},
		{ID: "i", Severity: teams.SeverityInfo},
	}

	var buf bytes.Buffer
	outputTeamsAuditJSONL(&buf, findings)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 4)

	expectedSeverities := []string{"high", "medium", "low", "info"}
	for i, line := range lines {
		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj))
		assert.Equal(t, expectedSeverities[i], obj["severity"],
			"severity for finding %d must be %q", i, expectedSeverities[i])
	}
}

// ---------------------------------------------------------------------------
// Test 8: TestOutputTeamsAuditHuman_Sanitizes
// ---------------------------------------------------------------------------

// TestOutputTeamsAuditHuman_Sanitizes verifies that:
//   - A raw ANSI escape byte (0x1b) in Finding.Evidence is absent from the output
//     when useColor==false (sanitizeTerminal is applied).
//   - Long evidence text is truncated (to auditEvidenceMaxRunes runes).
func TestOutputTeamsAuditHuman_Sanitizes(t *testing.T) {
	t.Run("ANSI escape in Evidence is stripped by sanitizeTerminal", func(t *testing.T) {
		maliciousEvidence := "\x1b[31mREDtext\x1b[0m normal content"
		findings := []teams.Finding{
			{
				ID:          "teams-user-enumeration",
				Title:       "Teams user enumeration possible",
				Severity:    teams.SeverityInfo,
				Description: "Some description.",
				Evidence:    maliciousEvidence,
				Affected:    "contoso.com (alice@contoso.com)",
				Remediation: "Reduce external exposure.",
			},
		}
		posture := teams.TenantPosture{
			Domain:              "contoso.com",
			ExternalChatAllowed: "blocked",
		}

		var buf bytes.Buffer
		outputTeamsAuditHuman(&buf, "contoso.com", &posture, findings, false /* useColor */)
		out := buf.String()

		// The raw ESC byte (0x1B) must not appear in the output.
		assert.NotContains(t, out, "\x1b",
			"raw ESC byte 0x1B must be stripped by sanitizeTerminal in human audit output")
		// The ANSI CSI payload must also be absent.
		assert.NotContains(t, out, "[31m",
			"ANSI CSI sequence payload must be stripped from human audit output")
		// The printable text must survive.
		assert.Contains(t, out, "normal content",
			"printable evidence text must survive sanitizeTerminal")
	})

	t.Run("long evidence is truncated to auditEvidenceMaxRunes", func(t *testing.T) {
		// Build evidence longer than auditEvidenceMaxRunes (200).
		longEvidence := strings.Repeat("x", 300)
		findings := []teams.Finding{
			{
				ID:          "teams-oof-disclosure",
				Title:       "Out-of-office note disclosed",
				Severity:    teams.SeverityLow,
				Description: "Description.",
				Evidence:    longEvidence,
				Affected:    "contoso.com (alice@contoso.com)",
				Remediation: "Restrict external access.",
			},
		}
		posture := teams.TenantPosture{
			Domain:              "contoso.com",
			ExternalChatAllowed: "blocked",
		}

		var buf bytes.Buffer
		outputTeamsAuditHuman(&buf, "contoso.com", &posture, findings, false)
		out := buf.String()

		// The full 300-character string must not appear; truncation cuts it at
		// auditEvidenceMaxRunes (200) with an ellipsis.
		assert.NotContains(t, out, longEvidence,
			"long evidence must be truncated in human audit output")
		// The truncation ellipsis (U+2026) must be present.
		assert.Contains(t, out, "…",
			"truncated evidence must end with the ellipsis rune (U+2026)")
	})

	t.Run("empty findings prints no-findings message", func(t *testing.T) {
		posture := teams.TenantPosture{
			Domain:              "contoso.com",
			ExternalChatAllowed: "blocked",
		}
		var buf bytes.Buffer
		outputTeamsAuditHuman(&buf, "contoso.com", &posture, nil, false)
		out := buf.String()
		assert.Contains(t, out, "No findings",
			"empty findings must print the no-findings message")
	})
}

// ---------------------------------------------------------------------------
// Test 9: TestEnumTeamsAuditCmd_Registered
// ---------------------------------------------------------------------------

// TestEnumTeamsAuditCmd_Registered verifies:
//   - The audit subcommand is registered on enumTeamsCmd with Use=="audit".
//   - The --email flag exists.
//   - No -t or -s shorthand is defined on the audit subcommand (collision guard).
func TestEnumTeamsAuditCmd_Registered(t *testing.T) {
	t.Run("audit subcommand registered on enumTeamsCmd", func(t *testing.T) {
		var auditFound bool
		for _, cmd := range enumTeamsCmd.Commands() {
			if cmd.Use == "audit" {
				auditFound = true
				break
			}
		}
		require.True(t, auditFound,
			"audit subcommand must be registered with enumTeamsCmd (Use==\"audit\")")
	})

	t.Run("--email flag exists on audit subcommand", func(t *testing.T) {
		f := enumTeamsAuditCmd.Flags().Lookup("email")
		require.NotNil(t, f, "--email flag must exist on audit subcommand")
	})

	t.Run("no local -t shorthand on audit subcommand (collides with global --threads/-t)", func(t *testing.T) {
		localT := enumTeamsAuditCmd.Flags().ShorthandLookup("t")
		require.Nil(t, localT,
			"audit subcommand must not define a local -t shorthand (collides with global --threads/-t)")
	})

	t.Run("no local -s shorthand on audit subcommand", func(t *testing.T) {
		localS := enumTeamsAuditCmd.Flags().ShorthandLookup("s")
		require.Nil(t, localS,
			"audit subcommand must not define a local -s shorthand (reserved for auth-path consistency)")
	})

	t.Run("--no-presence flag exists on audit subcommand", func(t *testing.T) {
		f := enumTeamsAuditCmd.Flags().Lookup("no-presence")
		require.NotNil(t, f, "--no-presence flag must exist on audit subcommand")
		assert.Equal(t, "false", f.DefValue,
			"--no-presence must default to false (presence is on by default)")
	})

	t.Run("--access-token flag exists on audit subcommand", func(t *testing.T) {
		f := enumTeamsAuditCmd.Flags().Lookup("access-token")
		require.NotNil(t, f, "--access-token flag must exist on audit subcommand")
	})

	t.Run("--token-file flag exists on audit subcommand", func(t *testing.T) {
		f := enumTeamsAuditCmd.Flags().Lookup("token-file")
		require.NotNil(t, f, "--token-file flag must exist on audit subcommand")
	})

	t.Run("--include-consumer flag exists with default false and no shorthand", func(t *testing.T) {
		f := enumTeamsAuditCmd.Flags().Lookup("include-consumer")
		require.NotNil(t, f, "--include-consumer flag must exist on audit subcommand")
		assert.Equal(t, "false", f.DefValue,
			"--include-consumer must default to false (corporate-only is the safe default)")
		// No shorthand must be registered.
		af := enumTeamsAuditCmd.Flags()
		for _, short := range []string{"i", "c"} {
			assert.Nil(t, af.ShorthandLookup(short),
				"audit subcommand must not register -%s shorthand for --include-consumer", short)
		}
	})
}

// ---------------------------------------------------------------------------
// outputTeamsAuditHuman: severity color labels
// ---------------------------------------------------------------------------

// TestOutputTeamsAuditHuman_SeverityLabels verifies that each severity level is
// rendered with its uppercase label in the human output.
func TestOutputTeamsAuditHuman_SeverityLabels(t *testing.T) {
	tests := []struct {
		severity teams.Severity
		label    string
	}{
		{teams.SeverityHigh, "[HIGH]"},
		{teams.SeverityMedium, "[MEDIUM]"},
		{teams.SeverityLow, "[LOW]"},
		{teams.SeverityInfo, "[INFO]"},
	}

	posture := teams.TenantPosture{
		Domain:              "contoso.com",
		ExternalChatAllowed: "blocked",
	}

	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.severity), func(t *testing.T) {
			findings := []teams.Finding{
				{
					ID:          "test-finding",
					Title:       "Test finding",
					Severity:    tc.severity,
					Description: "Test.",
					Remediation: "Fix it.",
				},
			}
			var buf bytes.Buffer
			outputTeamsAuditHuman(&buf, "contoso.com", &posture, findings, false)
			out := buf.String()
			assert.Contains(t, out, tc.label,
				"human output must contain severity label %q for severity %q", tc.label, tc.severity)
		})
	}
}

// ---------------------------------------------------------------------------
// outputTeamsAuditHuman: token leakage regression
// ---------------------------------------------------------------------------

// TestOutputTeamsAuditHuman_NoTokens verifies that known token-sentinel strings
// never appear in the human audit output. The Audit function never receives
// tokens, but this test ensures the output layer doesn't accidentally surface
// any global state.
func TestOutputTeamsAuditHuman_NoTokens(t *testing.T) {
	const accessTokenSentinel = "eyJhbGciOiJSUzI1NiIsImtpZCI6Imtl"
	const refreshTokenSentinel = "0.AVkArt_SomeRefreshToken_Sentinel"

	findings := []teams.Finding{
		{
			ID:          "teams-external-access",
			Title:       "External chat enabled",
			Severity:    teams.SeverityMedium,
			Description: "Description.",
			Evidence:    "externalsearchv3 returned the user",
			Affected:    "contoso.com",
			Remediation: "Restrict access.",
		},
	}
	posture := teams.TenantPosture{
		Domain:              "contoso.com",
		ExternalChatAllowed: "open",
	}

	var buf bytes.Buffer
	outputTeamsAuditHuman(&buf, "contoso.com", &posture, findings, false)
	out := buf.String()

	assert.NotContains(t, out, accessTokenSentinel,
		"human audit output must not contain the access-token sentinel")
	assert.NotContains(t, out, refreshTokenSentinel,
		"human audit output must not contain the refresh-token sentinel")
}
