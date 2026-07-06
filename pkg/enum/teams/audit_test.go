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

package teams

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findFinding returns the first Finding with the given id, or a zero Finding
// and false when no match exists.
func findFinding(findings []Finding, id string) (Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// hasFinding reports whether any finding in the slice has the given id.
func hasFinding(findings []Finding, id string) bool {
	_, ok := findFinding(findings, id)
	return ok
}

// ---------------------------------------------------------------------------
// Test 1: TestAudit_ExternalAccessOpen
// ---------------------------------------------------------------------------

func TestAudit_ExternalAccessOpen(t *testing.T) {
	baseResult := EnumResult{
		Email:  "alice@contoso.com",
		Exists: ExistenceYes,
	}

	t.Run("posture open emits teams-external-access Medium", func(t *testing.T) {
		posture := TenantPosture{ExternalChatAllowed: "open"}
		findings := Audit("contoso.com", "alice@contoso.com", &baseResult, &posture, false)

		f, ok := findFinding(findings, "teams-external-access")
		require.True(t, ok, "teams-external-access finding must be present when ExternalChatAllowed==\"open\"")
		assert.Equal(t, SeverityMedium, f.Severity,
			"teams-external-access severity must be SeverityMedium")
	})

	t.Run("posture blocked omits teams-external-access", func(t *testing.T) {
		posture := TenantPosture{ExternalChatAllowed: "blocked"}
		findings := Audit("contoso.com", "alice@contoso.com", &baseResult, &posture, false)
		assert.False(t, hasFinding(findings, "teams-external-access"),
			"teams-external-access must be absent when ExternalChatAllowed==\"blocked\"")
	})

	t.Run("posture unknown omits teams-external-access", func(t *testing.T) {
		posture := TenantPosture{ExternalChatAllowed: "unknown"}
		findings := Audit("contoso.com", "alice@contoso.com", &baseResult, &posture, false)
		assert.False(t, hasFinding(findings, "teams-external-access"),
			"teams-external-access must be absent when ExternalChatAllowed==\"unknown\"")
	})
}

// ---------------------------------------------------------------------------
// Test 2: TestAudit_UserEnumeration
// ---------------------------------------------------------------------------

func TestAudit_UserEnumeration(t *testing.T) {
	posture := TenantPosture{ExternalChatAllowed: "open"}

	t.Run("ExistenceYes emits teams-user-enumeration Info", func(t *testing.T) {
		result := EnumResult{Exists: ExistenceYes}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)

		f, ok := findFinding(findings, "teams-user-enumeration")
		require.True(t, ok, "teams-user-enumeration must be present when Exists==ExistenceYes")
		assert.Equal(t, SeverityInfo, f.Severity,
			"teams-user-enumeration severity must be SeverityInfo")
	})

	t.Run("ExistenceBlocked emits teams-user-enumeration Info", func(t *testing.T) {
		result := EnumResult{Exists: ExistenceBlocked}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)

		f, ok := findFinding(findings, "teams-user-enumeration")
		require.True(t, ok, "teams-user-enumeration must be present when Exists==ExistenceBlocked")
		assert.Equal(t, SeverityInfo, f.Severity,
			"teams-user-enumeration severity must be SeverityInfo for Blocked")
	})

	t.Run("ExistenceNo omits teams-user-enumeration", func(t *testing.T) {
		result := EnumResult{Exists: ExistenceNo}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)
		assert.False(t, hasFinding(findings, "teams-user-enumeration"),
			"teams-user-enumeration must be absent when Exists==ExistenceNo")
	})

	t.Run("ExistenceUnknown omits teams-user-enumeration", func(t *testing.T) {
		result := EnumResult{Exists: ExistenceUnknown}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)
		assert.False(t, hasFinding(findings, "teams-user-enumeration"),
			"teams-user-enumeration must be absent when Exists==ExistenceUnknown")
	})
}

// ---------------------------------------------------------------------------
// Test 3: TestAudit_PresenceAndOOF_GatedByPresenceChecked
// ---------------------------------------------------------------------------

func TestAudit_PresenceAndOOF_GatedByPresenceChecked(t *testing.T) {
	posture := TenantPosture{ExternalChatAllowed: "blocked"}

	t.Run("presenceChecked false with Availability and OOO set — neither finding emitted", func(t *testing.T) {
		result := EnumResult{
			Exists:          ExistenceBlocked,
			Availability:    "Busy",
			OutOfOfficeNote: "Back Monday call Jane",
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false /* presenceChecked */)

		assert.False(t, hasFinding(findings, "teams-presence-disclosure"),
			"teams-presence-disclosure must be absent when presenceChecked==false")
		assert.False(t, hasFinding(findings, "teams-oof-disclosure"),
			"teams-oof-disclosure must be absent when presenceChecked==false")
	})

	t.Run("presenceChecked true with Availability emits teams-presence-disclosure Low", func(t *testing.T) {
		result := EnumResult{
			Exists:       ExistenceYes,
			Availability: "Busy",
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true /* presenceChecked */)

		f, ok := findFinding(findings, "teams-presence-disclosure")
		require.True(t, ok, "teams-presence-disclosure must be present when presenceChecked==true and Availability is set")
		assert.Equal(t, SeverityLow, f.Severity,
			"teams-presence-disclosure severity must be SeverityLow")
	})

	t.Run("presenceChecked true with OutOfOfficeNote emits teams-oof-disclosure Low with note in Evidence", func(t *testing.T) {
		const oooNote = "Back Monday call Jane 555-1234"
		result := EnumResult{
			Exists:          ExistenceYes,
			OutOfOfficeNote: oooNote,
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true /* presenceChecked */)

		f, ok := findFinding(findings, "teams-oof-disclosure")
		require.True(t, ok, "teams-oof-disclosure must be present when presenceChecked==true and OutOfOfficeNote is set")
		assert.Equal(t, SeverityLow, f.Severity,
			"teams-oof-disclosure severity must be SeverityLow")
		assert.Contains(t, f.Evidence, oooNote,
			"teams-oof-disclosure Evidence must contain the raw out-of-office note text")
	})

	t.Run("presenceChecked true with empty Availability omits teams-presence-disclosure", func(t *testing.T) {
		result := EnumResult{
			Exists:       ExistenceYes,
			Availability: "", // empty
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true)
		assert.False(t, hasFinding(findings, "teams-presence-disclosure"),
			"teams-presence-disclosure must be absent when Availability is empty even if presenceChecked==true")
	})

	t.Run("presenceChecked true with empty OutOfOfficeNote omits teams-oof-disclosure", func(t *testing.T) {
		result := EnumResult{
			Exists:          ExistenceYes,
			OutOfOfficeNote: "", // empty
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true)
		assert.False(t, hasFinding(findings, "teams-oof-disclosure"),
			"teams-oof-disclosure must be absent when OutOfOfficeNote is empty even if presenceChecked==true")
	})
}

// ---------------------------------------------------------------------------
// Test 4: TestAudit_MetadataDisclosure
// ---------------------------------------------------------------------------

func TestAudit_MetadataDisclosure(t *testing.T) {
	posture := TenantPosture{ExternalChatAllowed: "open"}

	t.Run("ExistenceYes with UserPrincipalName emits teams-metadata-disclosure Info", func(t *testing.T) {
		result := EnumResult{
			Exists:            ExistenceYes,
			UserPrincipalName: "alice@contoso.com",
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)

		f, ok := findFinding(findings, "teams-metadata-disclosure")
		require.True(t, ok, "teams-metadata-disclosure must be present when UserPrincipalName is set")
		assert.Equal(t, SeverityInfo, f.Severity,
			"teams-metadata-disclosure severity must be SeverityInfo")
	})

	t.Run("ExistenceYes with ObjectID emits teams-metadata-disclosure Info", func(t *testing.T) {
		result := EnumResult{
			Exists:   ExistenceYes,
			ObjectID: "o-456",
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)

		_, ok := findFinding(findings, "teams-metadata-disclosure")
		require.True(t, ok, "teams-metadata-disclosure must be present when ObjectID is set")
	})

	t.Run("ExistenceYes with TenantID emits teams-metadata-disclosure Info", func(t *testing.T) {
		result := EnumResult{
			Exists:   ExistenceYes,
			TenantID: "t-123",
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)

		_, ok := findFinding(findings, "teams-metadata-disclosure")
		require.True(t, ok, "teams-metadata-disclosure must be present when TenantID is set")
	})

	t.Run("ExistenceYes with no metadata fields omits teams-metadata-disclosure", func(t *testing.T) {
		result := EnumResult{
			Exists:            ExistenceYes,
			UserPrincipalName: "",
			ObjectID:          "",
			TenantID:          "",
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)
		assert.False(t, hasFinding(findings, "teams-metadata-disclosure"),
			"teams-metadata-disclosure must be absent when all metadata fields are empty")
	})

	t.Run("ExistenceBlocked with metadata fields omits teams-metadata-disclosure", func(t *testing.T) {
		// Metadata finding only fires when Exists==ExistenceYes.
		result := EnumResult{
			Exists:            ExistenceBlocked,
			UserPrincipalName: "alice@contoso.com",
		}
		findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)
		assert.False(t, hasFinding(findings, "teams-metadata-disclosure"),
			"teams-metadata-disclosure must be absent when Exists!=ExistenceYes")
	})
}

// ---------------------------------------------------------------------------
// Test 5: TestAudit_Ordering
// ---------------------------------------------------------------------------

func TestAudit_Ordering(t *testing.T) {
	// Craft a result+posture that triggers Medium + Low + Info findings.
	// ExternalChatAllowed=="open" → teams-external-access (Medium)
	// presenceChecked==true + Availability set → teams-presence-disclosure (Low)
	// Exists==ExistenceYes → teams-user-enumeration (Info)
	result := EnumResult{
		Exists:       ExistenceYes,
		Availability: "Busy",
	}
	posture := TenantPosture{ExternalChatAllowed: "open"}

	findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true /* presenceChecked */)

	require.GreaterOrEqual(t, len(findings), 3,
		"expected at least 3 findings for ordering test: Medium + Low + Info")

	// Verify severity ordering: each finding's severity rank must be >= the previous.
	for i := 1; i < len(findings); i++ {
		prev := severityRank(findings[i-1].Severity)
		curr := severityRank(findings[i].Severity)
		assert.LessOrEqual(t, prev, curr,
			"findings must be ordered high→info: findings[%d] (%s) comes before findings[%d] (%s)",
			i-1, findings[i-1].Severity, i, findings[i].Severity)
	}

	// Explicitly verify the cross-severity boundaries we know exist.
	// Medium (rank 1) must come before Low (rank 2) which must come before Info (rank 3).
	mediumIdx := -1
	lowIdx := -1
	infoIdx := -1
	for i, f := range findings {
		switch f.Severity {
		case SeverityMedium:
			if mediumIdx == -1 {
				mediumIdx = i
			}
		case SeverityLow:
			if lowIdx == -1 {
				lowIdx = i
			}
		case SeverityInfo:
			if infoIdx == -1 {
				infoIdx = i
			}
		}
	}

	if mediumIdx != -1 && lowIdx != -1 {
		assert.Less(t, mediumIdx, lowIdx, "Medium finding must appear before Low finding")
	}
	if lowIdx != -1 && infoIdx != -1 {
		assert.Less(t, lowIdx, infoIdx, "Low finding must appear before Info finding")
	}
	if mediumIdx != -1 && infoIdx != -1 {
		assert.Less(t, mediumIdx, infoIdx, "Medium finding must appear before Info finding")
	}
}

// TestAudit_Ordering_WithinSeverityByID verifies that when two findings share
// the same severity they are sorted by ID (ascending).
func TestAudit_Ordering_WithinSeverityByID(t *testing.T) {
	// Trigger the two Low findings and verify alphabetic ordering within Low:
	// - teams-oof-disclosure       (Low)
	// - teams-presence-disclosure  (Low)
	// Alphabetically: oof < presence
	//
	// teams-user-enumeration is now Info (not Low), so it must appear in the Info
	// group and must not appear among Low findings.
	result := EnumResult{
		Exists:          ExistenceYes,
		Availability:    "Busy",
		OutOfOfficeNote: "Out until Friday",
	}
	posture := TenantPosture{ExternalChatAllowed: "blocked"}

	findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true /* presenceChecked */)

	var lowFindings []Finding
	var infoFindings []Finding
	for _, f := range findings {
		switch f.Severity {
		case SeverityLow:
			lowFindings = append(lowFindings, f)
		case SeverityInfo:
			infoFindings = append(infoFindings, f)
		}
	}

	require.Len(t, lowFindings, 2, "expected 2 Low findings in this scenario (oof + presence)")

	// Verify alphabetic ID ordering within the Low tier.
	assert.Equal(t, "teams-oof-disclosure", lowFindings[0].ID,
		"first Low finding must be teams-oof-disclosure (alphabetically first)")
	assert.Equal(t, "teams-presence-disclosure", lowFindings[1].ID,
		"second Low finding must be teams-presence-disclosure")

	// teams-user-enumeration must appear among the Info findings.
	var userEnumFound bool
	for _, f := range infoFindings {
		if f.ID == "teams-user-enumeration" {
			userEnumFound = true
			break
		}
	}
	assert.True(t, userEnumFound,
		"teams-user-enumeration must appear among Info-severity findings (severity changed from Low to Info)")
}

// ---------------------------------------------------------------------------
// Test 6: TestAudit_NoTokensInFindings
// ---------------------------------------------------------------------------

// TestAudit_NoTokensInFindings verifies that token-sentinel strings never
// appear in any Finding field. The Audit function receives no tokens, so this
// is primarily a structural guard: if caller code ever accidentally routes token
// values through result fields that Audit reads, this test will catch it.
func TestAudit_NoTokensInFindings(t *testing.T) {
	// Plant a token-sentinel string in the OutOfOfficeNote (a server-provided
	// field). The OOO note legitimately ends up in Finding.Evidence; we verify
	// that planting it there is intentional (the note IS the evidence) and does
	// NOT cause token values to appear in any other Finding field.
	const accessTokenSentinel = "SUPER_SECRET_ACCESS_TOKEN_SENTINEL"
	const refreshTokenSentinel = "SUPER_SECRET_REFRESH_TOKEN_SENTINEL"

	// The OOO note looks like a token sentinel — a realistic red-team scenario.
	result := EnumResult{
		Exists:            ExistenceYes,
		UserPrincipalName: "alice@contoso.com",
		TenantID:          "t-123",
		Availability:      "Busy",
		OutOfOfficeNote:   "Back Monday — ref: " + accessTokenSentinel,
	}
	posture := TenantPosture{ExternalChatAllowed: "open"}

	findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true)
	require.NotEmpty(t, findings, "expect at least one finding")

	// The refresh token sentinel must NEVER appear in any field.
	// The access token sentinel appears only in the OOF Evidence field (that is
	// correct behavior — it came from the server-provided OOO note). It must NOT
	// appear in any other field (Title, Description, Remediation, Affected, ID).
	for _, f := range findings {
		assert.NotContains(t, f.ID, refreshTokenSentinel,
			"ID must not contain the refresh-token sentinel")
		assert.NotContains(t, f.Title, refreshTokenSentinel,
			"Title must not contain the refresh-token sentinel")
		assert.NotContains(t, f.Description, refreshTokenSentinel,
			"Description must not contain the refresh-token sentinel")
		assert.NotContains(t, f.Affected, refreshTokenSentinel,
			"Affected must not contain the refresh-token sentinel")
		assert.NotContains(t, f.Remediation, refreshTokenSentinel,
			"Remediation must not contain the refresh-token sentinel")
		assert.NotContains(t, f.Evidence, refreshTokenSentinel,
			"Evidence must not contain the refresh-token sentinel")

		// The access token sentinel appears only as the OOF evidence text, which
		// is intentional. It must not appear in any structural field.
		if f.ID != "teams-oof-disclosure" {
			assert.NotContains(t, f.Evidence, accessTokenSentinel,
				"Evidence for non-OOF finding %q must not contain the access-token sentinel", f.ID)
		}
		assert.NotContains(t, f.ID, accessTokenSentinel,
			"ID must not contain the access-token sentinel")
		assert.NotContains(t, f.Title, accessTokenSentinel,
			"Title must not contain the access-token sentinel")
		assert.NotContains(t, f.Description, accessTokenSentinel,
			"Description must not contain the access-token sentinel")
		assert.NotContains(t, f.Affected, accessTokenSentinel,
			"Affected must not contain the access-token sentinel")
		assert.NotContains(t, f.Remediation, accessTokenSentinel,
			"Remediation must not contain the access-token sentinel")
	}
}

// ---------------------------------------------------------------------------
// Helpers used across multiple tests
// ---------------------------------------------------------------------------

// TestAudit_EmptyResult verifies that Audit never panics on a zero-value result
// and returns an empty (non-nil) slice.
func TestAudit_EmptyResult(t *testing.T) {
	result := EnumResult{}
	posture := TenantPosture{}

	var findings []Finding
	require.NotPanics(t, func() {
		findings = Audit("contoso.com", "", &result, &posture, false)
	}, "Audit must not panic on zero-value inputs")

	// Audit returns nil (not an initialized empty slice) when no rules fire — this
	// is idiomatic Go. The caller must treat nil and empty the same way (len==0).
	assert.Equal(t, 0, len(findings),
		"Audit on zero-value inputs must return a slice with length 0 (may be nil)")
}

// TestAudit_FindingFieldsNonEmpty verifies that every emitted finding has
// non-empty required fields (ID, Title, Severity, Description, Remediation).
func TestAudit_FindingFieldsNonEmpty(t *testing.T) {
	// Use a result that triggers all five finding types.
	result := EnumResult{
		Exists:            ExistenceYes,
		UserPrincipalName: "alice@contoso.com",
		Availability:      "Busy",
		OutOfOfficeNote:   "Out until Friday",
	}
	posture := TenantPosture{ExternalChatAllowed: "open"}

	findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true)
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.NotEmpty(t, f.ID, "finding ID must not be empty")
		assert.NotEmpty(t, f.Title, "finding Title must not be empty")
		assert.NotEmpty(t, string(f.Severity), "finding Severity must not be empty")
		assert.NotEmpty(t, f.Description, "finding Description must not be empty")
		assert.NotEmpty(t, f.Remediation, "finding Remediation must not be empty")
		// Severity must be one of the four declared constants.
		assert.True(t,
			f.Severity == SeverityHigh || f.Severity == SeverityMedium ||
				f.Severity == SeverityLow || f.Severity == SeverityInfo,
			"finding Severity must be a known constant, got %q", f.Severity)
	}
}

// TestAudit_AffectedContainsDomain verifies the affected field contains the
// domain (and, when a seed email is supplied, also the email).
func TestAudit_AffectedContainsDomain(t *testing.T) {
	result := EnumResult{Exists: ExistenceYes, UserPrincipalName: "alice@contoso.com"}
	posture := TenantPosture{ExternalChatAllowed: "open"}

	findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Contains(t, f.Affected, "contoso.com",
			"Affected for finding %q must contain the domain", f.ID)
	}

	// The user-enumeration finding has a seed email in Affected.
	f, ok := findFinding(findings, "teams-user-enumeration")
	require.True(t, ok)
	assert.Contains(t, f.Affected, "alice@contoso.com",
		"teams-user-enumeration Affected must include the seed email")
}

// TestAudit_PresenceEvidenceContainsAvailability verifies that the presence
// finding's Evidence string contains the Availability value.
func TestAudit_PresenceEvidenceContainsAvailability(t *testing.T) {
	result := EnumResult{
		Exists:       ExistenceYes,
		Availability: "DoNotDisturb",
	}
	posture := TenantPosture{ExternalChatAllowed: "blocked"}
	findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, true)

	f, ok := findFinding(findings, "teams-presence-disclosure")
	require.True(t, ok, "teams-presence-disclosure must be present")
	assert.Contains(t, f.Evidence, "DoNotDisturb",
		"presence finding Evidence must include the Availability value")
}

// TestAudit_MetadataEvidenceListsFields verifies that metadataFinding's
// Evidence string lists the specific field names that were set.
func TestAudit_MetadataEvidenceListsFields(t *testing.T) {
	result := EnumResult{
		Exists:            ExistenceYes,
		UserPrincipalName: "alice@contoso.com",
		ObjectID:          "o-456",
		TenantID:          "",
	}
	posture := TenantPosture{ExternalChatAllowed: "open"}
	findings := Audit("contoso.com", "alice@contoso.com", &result, &posture, false)

	f, ok := findFinding(findings, "teams-metadata-disclosure")
	require.True(t, ok)

	// Fields that were set must appear in Evidence.
	assert.True(t,
		strings.Contains(f.Evidence, "userPrincipalName") || strings.Contains(f.Evidence, "objectId"),
		"metadata Evidence must reference the disclosed field names")

	// TenantID was empty — tenantId must not appear in Evidence.
	assert.NotContains(t, f.Evidence, "tenantId",
		"tenantId must not appear in Evidence when TenantID was empty")
}
