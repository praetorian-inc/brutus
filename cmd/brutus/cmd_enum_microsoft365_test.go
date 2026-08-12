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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
	m365 "github.com/praetorian-inc/brutus/pkg/enum/microsoft365"
)

// ---------------------------------------------------------------------------
// TestEnumMicrosoft365Cmd_Flags
// Verifies that all documented flags exist on enumMicrosoft365Cmd and that
// no shorthand collides with the global --threads/-t flag.
// ---------------------------------------------------------------------------

func TestEnumMicrosoft365Cmd_Flags(t *testing.T) {
	// --emails / -e
	f := enumMicrosoft365Cmd.Flags().Lookup("emails")
	require.NotNil(t, f, "--emails flag must exist on enumMicrosoft365Cmd")
	sh := enumMicrosoft365Cmd.Flags().ShorthandLookup("e")
	require.NotNil(t, sh, "-e shorthand must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "emails", sh.Name, "-e must map to --emails")

	// --email-file / -E
	f = enumMicrosoft365Cmd.Flags().Lookup("email-file")
	require.NotNil(t, f, "--email-file flag must exist on enumMicrosoft365Cmd")
	sh = enumMicrosoft365Cmd.Flags().ShorthandLookup("E")
	require.NotNil(t, sh, "-E shorthand must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "email-file", sh.Name, "-E must map to --email-file")

	// --domain / -d
	f = enumMicrosoft365Cmd.Flags().Lookup("domain")
	require.NotNil(t, f, "--domain flag must exist on enumMicrosoft365Cmd")
	sh = enumMicrosoft365Cmd.Flags().ShorthandLookup("d")
	require.NotNil(t, sh, "-d shorthand must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "domain", sh.Name, "-d must map to --domain")

	// --format (no shorthand required; default is first.last)
	f = enumMicrosoft365Cmd.Flags().Lookup("format")
	require.NotNil(t, f, "--format flag must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "first.last", f.DefValue, "--format default must be \"first.last\"")

	// --limit (no shorthand required)
	f = enumMicrosoft365Cmd.Flags().Lookup("limit")
	require.NotNil(t, f, "--limit flag must exist on enumMicrosoft365Cmd")

	// No -t shorthand: collides with global persistent --threads/-t.
	noT := enumMicrosoft365Cmd.Flags().ShorthandLookup("t")
	require.Nil(t, noT,
		"enumMicrosoft365Cmd must not define a local -t shorthand (collides with global --threads/-t)")

	// No -s shorthand (consistent with the pattern used by other enum subcommands).
	noS := enumMicrosoft365Cmd.Flags().ShorthandLookup("s")
	require.Nil(t, noS,
		"enumMicrosoft365Cmd must not define a local -s shorthand (reserved)")
}

// TestEnumMicrosoft365Cmd_RegisteredUnderActiveCmd verifies that
// enumMicrosoft365Cmd has Use=="microsoft365" and is a child of enumActiveCmd.
func TestEnumMicrosoft365Cmd_RegisteredUnderActiveCmd(t *testing.T) {
	assert.Equal(t, "microsoft365", enumMicrosoft365Cmd.Use,
		"enumMicrosoft365Cmd.Use must be \"microsoft365\"")

	var found bool
	for _, cmd := range enumActiveCmd.Commands() {
		if cmd.Use == "microsoft365" {
			found = true
			break
		}
	}
	assert.True(t, found, "enumMicrosoft365Cmd must be registered as a subcommand of enumActiveCmd")
}

// ---------------------------------------------------------------------------
// TestEncodeMicrosoft365EnumResult
// Feeds m365.Result values and asserts the type/if_exists_result/federation
// fields, including omitempty behavior.
// ---------------------------------------------------------------------------

func TestEncodeMicrosoft365EnumResult(t *testing.T) {
	tests := []struct {
		name              string
		result            m365.Result
		wantType          string
		wantExists        bool
		wantIfExists      int
		wantFederated     bool   // false means key must be absent (omitempty)
		wantFederationURL string // empty means key must be absent (omitempty)
	}{
		{
			name: "managed exists",
			result: m365.Result{
				Email:          "managed@example.com",
				Exists:         true,
				IfExistsResult: m365.IfExistsResultExists,
				Federated:      false,
			},
			wantType:          "microsoft365_account",
			wantExists:        true,
			wantIfExists:      0,
			wantFederated:     false, // absent (omitempty)
			wantFederationURL: "",    // absent (omitempty)
		},
		{
			name: "federated different tenant",
			result: m365.Result{
				Email:          "fed@example.com",
				Exists:         true,
				IfExistsResult: m365.IfExistsResultDifferentTenant,
				Federated:      true,
				FederationURL:  "https://login.okta.com/x",
			},
			wantType:          "microsoft365_account",
			wantExists:        true,
			wantIfExists:      5,
			wantFederated:     true,
			wantFederationURL: "https://login.okta.com/x",
		},
		{
			name: "not found",
			result: m365.Result{
				Email:          "nobody@example.com",
				Exists:         false,
				IfExistsResult: m365.IfExistsResultNotExists,
			},
			wantType:          "microsoft365_account",
			wantExists:        false,
			wantIfExists:      1,
			wantFederated:     false,
			wantFederationURL: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			encodeMicrosoft365EnumResult(enc, tc.result)

			line := strings.TrimSpace(buf.String())
			require.NotEmpty(t, line, "encodeMicrosoft365EnumResult must produce a JSONL line")

			var obj map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(line), &obj),
				"JSONL output must be valid JSON: %q", line)

			assert.Equal(t, tc.wantType, obj["type"],
				"type field must be %q", tc.wantType)

			assert.Equal(t, tc.result.Email, obj["email"],
				"email field must match result.Email")

			wantExists, _ := obj["exists"].(bool)
			assert.Equal(t, tc.wantExists, wantExists,
				"exists field must match result.Exists")

			// if_exists_result is NOT omitempty — 0 is a valid, common value and
			// must always be present.
			require.Contains(t, obj, "if_exists_result",
				"if_exists_result must always be present (not omitempty)")
			gotIfExists, ok := obj["if_exists_result"].(float64)
			require.True(t, ok, "if_exists_result must be numeric")
			assert.Equal(t, tc.wantIfExists, int(gotIfExists),
				"if_exists_result must be %d", tc.wantIfExists)

			// federated is omitempty — absent when false.
			if tc.wantFederated {
				assert.Equal(t, true, obj["federated"],
					"federated field must be true")
			} else {
				assert.NotContains(t, obj, "federated",
					"federated key must be absent when false (omitempty)")
			}

			// federation_url is omitempty — absent when empty.
			if tc.wantFederationURL != "" {
				assert.Equal(t, tc.wantFederationURL, obj["federation_url"],
					"federation_url field must be %q", tc.wantFederationURL)
			} else {
				assert.NotContains(t, obj, "federation_url",
					"federation_url key must be absent when empty (omitempty)")
			}

			// error must be absent when result.Error is nil.
			assert.NotContains(t, obj, "error",
				"error key must be absent when result.Error is nil")
		})
	}

	// Error row: if_exists_result must be omitted (no API code was decoded),
	// and the error key must be present with the error text.
	t.Run("error omits if_exists_result", func(t *testing.T) {
		result := m365.Result{
			Email:  "boom@example.com",
			Error:  errors.New("throttled"),
			Exists: false,
		}

		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		encodeMicrosoft365EnumResult(enc, result)

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "encodeMicrosoft365EnumResult must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		wantExists, _ := obj["exists"].(bool)
		assert.False(t, wantExists, "exists field must be false")

		assert.Contains(t, obj, "error", "error key must be present on an error row")
		assert.Equal(t, "throttled", obj["error"], "error field must contain the error message")

		assert.NotContains(t, obj, "if_exists_result",
			"if_exists_result must be omitted on an error row (no API code was decoded)")
	})
}

// ---------------------------------------------------------------------------
// TestOutputMicrosoft365EnumResultLine
// Verifies human-readable line output for EXISTS, federation, and ANSI safety.
// ---------------------------------------------------------------------------

func TestOutputMicrosoft365EnumResultLine(t *testing.T) {
	t.Run("managed exists shows EXISTS and managed", func(t *testing.T) {
		r := m365.Result{
			Email:          "managed@example.com",
			Exists:         true,
			IfExistsResult: m365.IfExistsResultExists,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false /* useColor */)
		out := buf.String()

		assert.Contains(t, out, "EXISTS",
			"managed EXISTS result must contain \"EXISTS\"")
		assert.Contains(t, out, "managed",
			"managed result must mention the tenant relationship")
	})

	t.Run("different-tenant federated shows EXISTS, tenant, IdP host", func(t *testing.T) {
		r := m365.Result{
			Email:          "fed@example.com",
			Exists:         true,
			IfExistsResult: m365.IfExistsResultDifferentTenant,
			Federated:      true,
			FederationURL:  "https://login.okta.com/x",
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "EXISTS",
			"federated EXISTS result must contain \"EXISTS\"")
		assert.Contains(t, out, "different tenant",
			"result must mention the different-tenant relationship")
		assert.Contains(t, out, "federated",
			"result must mention federation")
		assert.Contains(t, out, "login.okta.com",
			"result must contain the federation IdP host")
	})

	t.Run("not found shows not found label", func(t *testing.T) {
		r := m365.Result{
			Email:          "nobody@example.com",
			Exists:         false,
			IfExistsResult: m365.IfExistsResultNotExists,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "not found",
			"not-found result must contain \"not found\"")
		assert.NotContains(t, out, "EXISTS",
			"not-found result must not contain \"EXISTS\"")
	})

	t.Run("error row renders as an error, not not-found", func(t *testing.T) {
		r := m365.Result{
			Email:          "boom@example.com",
			Error:          errors.New("request failed: timeout"),
			Exists:         false,
			IfExistsResult: 0,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "error",
			"error result must contain \"error\"")
		assert.Contains(t, out, "timeout",
			"error result must contain the underlying error message")
		assert.NotContains(t, out, "not found",
			"error result must not be rendered as \"not found\"")
		assert.NotContains(t, out, "EXISTS",
			"error result must not be rendered as \"EXISTS\"")
	})

	t.Run("error message with ANSI escape is sanitized", func(t *testing.T) {
		// The error message may embed server-controlled or otherwise unsafe
		// text; a raw ESC (0x1B) byte must be stripped before rendering
		// (sanitizeTerminal, P0-4 requirement).
		r := m365.Result{
			Email:  "boom@example.com",
			Error:  errors.New("bad \x1b[31mX\x1b[0m"),
			Exists: false,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.NotContains(t, out, "\x1b",
			"raw ESC byte (0x1B) in an error message must be absent from the rendered line")
	})

	t.Run("malicious FederationURL with ANSI escape is sanitized", func(t *testing.T) {
		// A server-controlled FederationURL that injects a raw ESC (0x1B) byte.
		// The output layer must strip it before rendering (P0-4 requirement).
		maliciousURL := "https://okta.com\x1b[31mX\x1b[0m"
		r := m365.Result{
			Email:          "user@example.com",
			Exists:         true,
			IfExistsResult: m365.IfExistsResultDifferentTenant,
			Federated:      true,
			FederationURL:  maliciousURL,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		// Raw ESC byte must not appear in the output.
		assert.NotContains(t, out, "\x1b",
			"raw ESC byte (0x1B) must be absent from the rendered line (sanitizeTerminal must strip it)")
	})
}

// ---------------------------------------------------------------------------
// microsoft365EnumTargetList / microsoft365EnumGenerate
//
// 10T-535 (6/8): microsoft365EnumTargets() ([]string, error) is retargeted
// onto microsoft365EnumTargetList() ([]enum.Target, error) — the
// Target-returning function that carries each generated address's name
// (mirrors googleEnumTargetList / githubEnumTargetList /
// gravatarEnumTargetList). microsoft365EnumGenerate() is retargeted from
// ([]string, error) to ([]enum.Target, error) for the same reason. Every
// prior assertion (trim, case-insensitive dedup, first-seen casing
// preserved, "provide" error, --limit capping, invalid-format error) is
// preserved; there is no dead adapter left behind pinning the old []string
// signatures.
// ---------------------------------------------------------------------------

func resetMicrosoft365EnumFlags() (restore func()) {
	origEmails := flagM365EnumEmails
	origEmailFile := flagM365EnumEmailFile
	origDomain := flagM365EnumDomain
	origFormat := flagM365EnumFormat
	origLimit := flagM365EnumLimit
	return func() {
		flagM365EnumEmails = origEmails
		flagM365EnumEmailFile = origEmailFile
		flagM365EnumDomain = origDomain
		flagM365EnumFormat = origFormat
		flagM365EnumLimit = origLimit
	}
}

// TestMicrosoft365EnumTargetList_InlineEmails verifies that --emails CSV is
// parsed, trimmed, and deduplicated (case-insensitively) while preserving the
// ORIGINAL casing of the first-seen address, and that every CLI-supplied
// target carries no name (a supplied address says nothing about whose it is)
// — mirrors TestGravatarEnumTargetList_InlineEmails, except microsoft365 must
// NOT lower-case the stored address (see the trap test below for why).
func TestMicrosoft365EnumTargetList_InlineEmails(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumEmails = "alice@example.com,bob@example.com,alice@example.com"
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = ""

	got, err := microsoft365EnumTargetList()
	require.NoError(t, err)

	emails := enumTargetEmails(got)
	// Deduplication: alice@example.com appears twice but must appear once.
	assert.Len(t, emails, 2, "deduplication must collapse duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")

	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): CLI-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): CLI-supplied address must have empty Last", i, target.Email)
	}
}

// TestMicrosoft365EnumTargetList_NoSource verifies that an error is returned
// (and mentions "provide") when no --emails, --email-file, or --domain is
// given.
func TestMicrosoft365EnumTargetList_NoSource(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumEmails = ""
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = ""

	_, err := microsoft365EnumTargetList()
	require.Error(t, err, "microsoft365EnumTargetList must fail when no source is supplied")
	assert.Contains(t, err.Error(), "provide",
		"error message must guide the user to supply a target source")
}

// TestMicrosoft365EnumTargetList_CaseInsensitiveDedup verifies that dedup
// keys on the lowercased email (the GetCredentialType API is
// case-insensitive) while preserving the first-seen casing on the returned
// Target.Email — this is the existing, pre-PR6 behavior
// (TestMicrosoft365EnumTargets_CaseInsensitiveDedup) retargeted onto
// microsoft365EnumTargetList.
func TestMicrosoft365EnumTargetList_CaseInsensitiveDedup(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumEmails = "Alice@Example.com,alice@example.com,BOB@example.com"
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = ""

	got, err := microsoft365EnumTargetList()
	require.NoError(t, err)

	emails := enumTargetEmails(got)
	// Case-variant duplicates collapse: "Alice@Example.com" and
	// "alice@example.com" are the same target.
	assert.Len(t, emails, 2, "case-variant duplicates must collapse")

	// The first-seen original casing must be preserved, not a lowercased form.
	assert.Contains(t, emails, "Alice@Example.com",
		"first-seen casing must be preserved")
	assert.NotContains(t, emails, "alice@example.com",
		"the later-seen lowercase duplicate must not also appear")
	assert.Contains(t, emails, "BOB@example.com")

	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): CLI-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): CLI-supplied address must have empty Last", i, target.Email)
	}
}

// TestMicrosoft365EnumTargetList_DomainGeneratedCarriesName verifies that
// --domain-generated targets carry the non-empty First/Last the username was
// built from, unlike CLI-supplied addresses, and that --limit caps the
// count — mirrors TestGravatarEnumTargetList_DomainGeneratedCarriesName.
func TestMicrosoft365EnumTargetList_DomainGeneratedCarriesName(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumEmails = ""
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = "target.com"
	flagM365EnumFormat = "first.last"
	flagM365EnumLimit = 5

	got, err := microsoft365EnumTargetList()
	require.NoError(t, err)
	require.Len(t, got, 5, "--limit must cap the number of generated targets")

	for i, target := range got {
		assert.Contains(t, target.Email, "@target.com", "target %d must be for the requested domain", i)
		assert.NotEmpty(t, target.First, "target %d (%q): a --domain-generated target must carry a non-empty First", i, target.Email)
		assert.NotEmpty(t, target.Last, "target %d (%q): a --domain-generated target must carry a non-empty Last", i, target.Email)
	}
}

// ---------------------------------------------------------------------------
// THE CRITICAL TRAP (10T-535, 6/8) — INVERSE of gravatar's (5/8) trap.
//
// gravatar.CheckAccount lower-cases a COPY of the address it is given (only
// for HashEmail's MD5 digest) but microsoft365.CheckAccount does NOT: it sets
// Result{Email: email} verbatim from whatever address it is handed, and never
// re-cases it (see pkg/enum/microsoft365/microsoft365.go CheckAccount:
// `result := &Result{Email: email}`, with no strings.ToLower anywhere in that
// function or in EnumerateWith's per-email loop).
//
// cmd_enum_microsoft365.go's PRE-PR6 target-building/dedup loop (formerly
// line ~209 of microsoft365EnumTargets) already gets this right for
// CLI-supplied addresses: it keys the dedup "seen" set on
// strings.ToLower(e) but appends the ORIGINAL-CASED e to the result. That
// existing behavior must carry over unchanged into
// microsoft365EnumTargetList's Target-based loop, and it must ALSO apply to
// --domain-generated addresses (enum.Candidate.Email concatenates the
// (lower-cased) username with the domain AS SUPPLIED, so a mixed-case
// --domain lands mixed-case in the generated Target.Email).
//
// If someone "fixes" the loop by copying gravatar's normalization —
// `t.Email = strings.ToLower(strings.TrimSpace(t.Email))` applied to the
// Target field itself — every generated (and CLI-supplied) address is
// lower-cased. That contradicts what microsoft365.CheckAccount actually
// echoes back on Result.Email for an address that was never lower-cased to
// begin with, and it silently discards the operator-supplied --domain
// casing.
//
// This test generates with a MIXED-CASE --domain ("Example.COM") and
// asserts:
//  1. Every returned Target's Email retains that exact mixed-case domain
//     (the domain's casing must NOT be lower-cased away).
//  2. Every generated target's name is recoverable via enumNamesByEmail +
//     enumNameFor, keyed on the address microsoft365.CheckAccount will
//     actually receive and echo back (target.Email itself, original casing
//     intact).
//  3. A lookup keyed on the independently lower-cased form of that same
//     address must NOT recover a name — proving the index is keyed on the
//     original-cased address the checker echoes, not a normalized one.
// ---------------------------------------------------------------------------

func TestMicrosoft365EnumTargetList_GeneratedAddressesRetainOriginalCasingForNameLookup(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumEmails = ""
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = "Example.COM" // mixed-case domain: the trap.
	flagM365EnumFormat = "first.last"
	flagM365EnumLimit = 10

	got, err := microsoft365EnumTargetList()
	require.NoError(t, err)
	require.Len(t, got, 10, "--limit must cap the number of generated targets")

	for i, target := range got {
		// The address stored on the Target must retain the EXACT mixed-case
		// domain the operator supplied via --domain: this is the exact
		// address enumTargetEmails() will hand to
		// microsoft365.Checker.EnumerateWith, and CheckAccount echoes back
		// the address it is given verbatim (unlike gravatar, it never
		// re-cases it) on Result.Email.
		require.Contains(t, target.Email, "@Example.COM",
			"target %d (%q): Target.Email must retain the mixed-case --domain exactly as supplied — microsoft365.CheckAccount echoes the address verbatim on Result.Email, so lower-casing Target.Email here (copying gravatar's normalization) would desync the stored address from what the checker actually receives and echoes back", i, target.Email)

		lowered := strings.ToLower(target.Email)
		require.NotEqual(t, lowered, target.Email,
			"target %d (%q): Target.Email must NOT be lower-cased — the mixed-case --domain casing must survive into the Target field itself, not just be discarded by a throwaway local variable", i, target.Email)
	}

	// enumNamesByEmail/enumNameFor are the shared framework helpers
	// (unmodified, reused from cmd_enum.go) that runEnumMicrosoft365 wires up
	// exactly like runEnumGoogle/runEnumGithub/runEnumGravatar: names :=
	// enumNamesByEmail(targets), then each onResult callback does
	// res.First, res.Last = enumNameFor(names, res.Email). Building the
	// index from the SAME already-original-cased targets slice that
	// microsoft365EnumTargetList returned is what keeps the lookup key
	// byte-identical to the address the checker echoes back.
	names := enumNamesByEmail(got)
	require.Len(t, names, len(got), "every generated target must be indexed by enumNamesByEmail")

	for i, target := range got {
		// Simulate the checker echoing the address back on a Result:
		// microsoft365.CheckAccount sets Result{Email: email} verbatim from
		// the email parameter it is given, which is target.Email itself —
		// original casing intact.
		echoedByChecker := target.Email

		first, last := enumNameFor(names, echoedByChecker)
		assert.NotEmpty(t, first,
			"target %d (%q): name lookup keyed on the checker-echoed (original-cased) address must recover a non-empty First — an empty result here means the index was built on a re-cased address and the name silently vanished", i, target.Email)
		assert.NotEmpty(t, last,
			"target %d (%q): name lookup keyed on the checker-echoed (original-cased) address must recover a non-empty Last — an empty result here means the index was built on a re-cased address and the name silently vanished", i, target.Email)
		assert.Equal(t, target.First, first, "target %d: recovered First must match the target's own First", i)
		assert.Equal(t, target.Last, last, "target %d: recovered Last must match the target's own Last", i)

		// A lookup keyed on the independently LOWER-CASED form of the same
		// address must fail to recover the name: this proves the index is
		// keyed on the exact original-cased address, not a normalized one.
		loweredKey := strings.ToLower(echoedByChecker)
		require.NotEqual(t, echoedByChecker, loweredKey,
			"target %d: sanity check — the mixed-case domain must make the lower-cased key differ from the original, or this assertion is vacuous", i)
		firstLowered, lastLowered := enumNameFor(names, loweredKey)
		assert.Empty(t, firstLowered,
			"target %d: a lookup keyed on the lower-cased address must NOT recover a name — the index must be keyed on the original-cased (checker-echoed) address, not a lower-cased one", i)
		assert.Empty(t, lastLowered,
			"target %d: a lookup keyed on the lower-cased address must NOT recover a name — the index must be keyed on the original-cased (checker-echoed) address, not a lower-cased one", i)
	}
}

// ---------------------------------------------------------------------------
// microsoft365EnumGenerate
// ---------------------------------------------------------------------------

func TestMicrosoft365EnumGenerate_ProducesCandidatesForDomain(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumDomain = "target.com"
	flagM365EnumFormat = "first.last"
	flagM365EnumLimit = 0

	generated, err := microsoft365EnumGenerate()
	require.NoError(t, err)

	candidates, err := enum.GenerateCandidates("first.last")
	require.NoError(t, err)

	want := make([]enum.Target, len(candidates))
	for i, c := range candidates {
		want[i] = c.Target("target.com")
	}

	assert.Equal(t, want, generated,
		"microsoft365EnumGenerate must reuse enum.GenerateCandidates (via capResults and Candidate.Target), matching the google/gravatar/github generate pattern")
	for i, target := range generated {
		assert.Contains(t, target.Email, "@target.com", "target %d must be for the requested domain", i)
		assert.NotEmpty(t, target.First, "target %d: generated target must carry a non-empty First", i)
		assert.NotEmpty(t, target.Last, "target %d: generated target must carry a non-empty Last", i)
	}
}

func TestMicrosoft365EnumGenerate_RespectsLimit(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumDomain = "target.com"
	flagM365EnumFormat = "first.last"
	flagM365EnumLimit = 3

	generated, err := microsoft365EnumGenerate()
	require.NoError(t, err)

	assert.Len(t, generated, 3, "--limit must cap the number of generated candidates")

	candidates, err := enum.GenerateCandidates("first.last")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(candidates), 3, "full generated list must have at least 3 candidates for this assertion to be meaningful")

	want := make([]enum.Target, 3)
	for i := 0; i < 3; i++ {
		want[i] = candidates[i].Target("target.com")
	}
	assert.Equal(t, want, generated, "--limit must keep the first (most-likely) N candidates")
}

func TestMicrosoft365EnumGenerate_InvalidFormatRejected(t *testing.T) {
	defer resetMicrosoft365EnumFlags()()

	flagM365EnumDomain = "target.com"
	flagM365EnumFormat = "not-a-real-format"
	flagM365EnumLimit = 0

	_, err := microsoft365EnumGenerate()
	require.Error(t, err, "an invalid --format must be rejected")
	assert.Contains(t, err.Error(), "invalid --format")
}

// ---------------------------------------------------------------------------
// encodeMicrosoft365EnumResult — First/Last name propagation (10T-535, 6/8)
// ---------------------------------------------------------------------------

// TestEncodeMicrosoft365EnumResult_NameFields pins the never-invent-a-name
// rule: a Result carrying First/Last (from --domain generation) must emit
// "first"/"last" in the JSONL row, while a Result with empty First/Last
// (supplied via --emails or --email-file) must OMIT both keys entirely
// rather than emit them as "". Pre-existing fields (type/email/exists/
// if_exists_result/federated/federation_url) must be unaffected by the
// addition — mirrors TestOutputGoogleEnumJSONL_NameFields /
// TestOutputGravatarEnumJSONL_NameFields, adapted for
// encodeMicrosoft365EnumResult's one-result-at-a-time signature.
func TestEncodeMicrosoft365EnumResult_NameFields(t *testing.T) {
	named := m365.Result{
		Email:          "john.smith@example.com",
		Exists:         true,
		IfExistsResult: m365.IfExistsResultExists,
		First:          "john",
		Last:           "smith",
	}
	unnamed := m365.Result{
		Email:          "supplied@example.com",
		Exists:         true,
		IfExistsResult: m365.IfExistsResultDifferentTenant,
		Federated:      true,
		FederationURL:  "https://login.okta.com/x",
	}

	t.Run("named result emits first and last", func(t *testing.T) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		encodeMicrosoft365EnumResult(enc, named)

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "encodeMicrosoft365EnumResult must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.Equal(t, "john", obj["first"], `first field must be "john"`)
		assert.Equal(t, "smith", obj["last"], `last field must be "smith"`)

		// Pre-existing fields must remain unaffected by the new ones.
		assert.Equal(t, "microsoft365_account", obj["type"])
		assert.Equal(t, named.Email, obj["email"])
		assert.Equal(t, true, obj["exists"])
		require.Contains(t, obj, "if_exists_result",
			"if_exists_result must always be present (not omitempty)")
		gotIfExists, ok := obj["if_exists_result"].(float64)
		require.True(t, ok, "if_exists_result must be numeric")
		assert.Equal(t, m365.IfExistsResultExists, int(gotIfExists))
		assert.NotContains(t, obj, "federated",
			"federated key must be absent when false (omitempty)")
	})

	t.Run("unnamed result omits first and last keys", func(t *testing.T) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		encodeMicrosoft365EnumResult(enc, unnamed)

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "encodeMicrosoft365EnumResult must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.NotContains(t, obj, "first",
			`first key must be absent (omitempty), not emitted as ""`)
		assert.NotContains(t, obj, "last",
			`last key must be absent (omitempty), not emitted as ""`)

		// Pre-existing fields must remain unaffected.
		assert.Equal(t, "microsoft365_account", obj["type"])
		assert.Equal(t, unnamed.Email, obj["email"])
		assert.Equal(t, true, obj["exists"])
		assert.Equal(t, true, obj["federated"])
		assert.Equal(t, unnamed.FederationURL, obj["federation_url"])
		gotIfExists, ok := obj["if_exists_result"].(float64)
		require.True(t, ok, "if_exists_result must be numeric")
		assert.Equal(t, m365.IfExistsResultDifferentTenant, int(gotIfExists))
	})

	t.Run("mixed batch: one named, one unnamed", func(t *testing.T) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		encodeMicrosoft365EnumResult(enc, named)
		encodeMicrosoft365EnumResult(enc, unnamed)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 2, "must emit exactly one JSONL line per result")

		var first map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
		assert.Equal(t, "john", first["first"])
		assert.Equal(t, "smith", first["last"])

		var second map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
		assert.NotContains(t, second, "first",
			`second (unnamed) line must not carry a "first" key`)
		assert.NotContains(t, second, "last",
			`second (unnamed) line must not carry a "last" key`)
	})
}
