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
	"fmt"
	"sort"
	"strings"
)

// Severity is the graded impact of a Finding.
type Severity string

const (
	// SeverityInfo is informational: an observation with little direct risk.
	SeverityInfo Severity = "info"
	// SeverityLow is a low-severity issue.
	SeverityLow Severity = "low"
	// SeverityMedium is a medium-severity issue.
	SeverityMedium Severity = "medium"
	// SeverityHigh is a high-severity issue.
	SeverityHigh Severity = "high"
)

// Finding is a single graded security observation about a Teams tenant's
// external-exposure posture. Evidence and Affected may contain server-provided
// data (e.g. an out-of-office note); the caller is responsible for sanitizing
// these strings before rendering them to a terminal. Token values never appear
// in any field.
type Finding struct {
	ID          string   // stable slug, e.g. "teams-external-access"
	Title       string   //
	Severity    Severity //
	Description string   //
	Evidence    string   // observed signal (may contain server data -> caller sanitizes for terminal)
	Affected    string   // domain (and seed email where relevant)
	Remediation string   // how to fix or mitigate the finding
}

// Audit derives findings for a tenant from one seed user's enumeration result
// plus the derived posture. presenceChecked indicates whether the presence
// lookup ran (presence is gathered by default; --no-presence disables it), so
// presence/out-of-office findings are only emitted when that evidence was
// actually gathered. Findings are returned ordered by
// severity (high -> info) then by ID, for stable output. Token values never
// appear in any field.
func Audit(domain, seedEmail string, result *EnumResult, posture *TenantPosture, presenceChecked bool) []Finding {
	var findings []Finding

	if posture.ExternalChatAllowed == "open" {
		findings = append(findings, externalAccessFinding(domain, result))
	}

	if result.Exists == ExistenceYes || result.Exists == ExistenceBlocked {
		findings = append(findings, userEnumerationFinding(domain, seedEmail))
	}

	if presenceChecked && result.Availability != "" {
		findings = append(findings, presenceFinding(domain, seedEmail, result))
	}

	if presenceChecked && result.OutOfOfficeNote != "" {
		findings = append(findings, oofFinding(domain, seedEmail, result))
	}

	if result.Exists == ExistenceYes &&
		(result.UserPrincipalName != "" || result.ObjectID != "" || result.TenantID != "") {
		findings = append(findings, metadataFinding(domain, seedEmail, result))
	}

	sortFindings(findings)
	return findings
}

// ---------------------------------------------------------------------------
// Rule builders (one per finding type)
// ---------------------------------------------------------------------------

// externalAccessFinding reports that external / cross-tenant Teams chat is
// enabled: the externalsearchv3 endpoint resolved the seed user to this tenant
// from an external context.
func externalAccessFinding(domain string, result *EnumResult) Finding {
	evidence := "externalsearchv3 returned the user to an external tenant"
	if posture := externalAccessSignals(result); posture != "" {
		evidence += " (" + posture + ")"
	}
	return Finding{
		ID:          "teams-external-access",
		Title:       "External / cross-tenant Teams chat enabled",
		Severity:    SeverityMedium,
		Description: "The tenant permits external (cross-tenant) Microsoft Teams communication: an unauthenticated/external lookup resolved a user in this tenant, which lets outside parties initiate chat and gather directory metadata.",
		Evidence:    evidence,
		Affected:    domain,
		Remediation: "Restrict Teams external access / federation to an allow-list of trusted domains. For example: Set-CsTenantFederationConfiguration -AllowFederatedUsers $false (or configure an allowed-domains list) and tighten Set-CsExternalAccessPolicy.",
	}
}

// userEnumerationFinding reports that valid vs. invalid users can be
// distinguished via the externalsearchv3 oracle, even when external search is
// blocked with a 403.
func userEnumerationFinding(domain, seedEmail string) Finding {
	return Finding{
		ID:          "teams-user-enumeration",
		Title:       "Teams user enumeration possible",
		Severity:    SeverityInfo,
		Description: "Microsoft Teams distinguishes valid from invalid users via the externalsearchv3 endpoint (a 200 with data vs an empty 200 vs a 403), enabling email/user enumeration.",
		Evidence:    "externalsearchv3 distinguishes valid vs invalid users (200 with data vs empty 200 vs 403)",
		Affected:    affected(domain, seedEmail),
		Remediation: "Informational: this is inherent to Microsoft Teams and cannot be disabled by the tenant. It is noted for awareness; monitor for bulk-enumeration patterns and minimize external exposure overall.",
	}
}

// presenceFinding reports that the seed user's Teams presence (availability /
// device type) was disclosed to an external requester.
func presenceFinding(domain, seedEmail string, result *EnumResult) Finding {
	evidence := "presence availability returned: " + result.Availability
	if result.DeviceType != "" {
		evidence += " (device: " + result.DeviceType + ")"
	}
	return Finding{
		ID:          "teams-presence-disclosure",
		Title:       "Teams presence disclosed to external users",
		Severity:    SeverityLow,
		Description: "The user's Teams presence (availability, and possibly device type) is visible to external parties, leaking real-time activity information useful for social engineering and targeting.",
		Evidence:    evidence,
		Affected:    affected(domain, seedEmail),
		Remediation: "Apply presence-privacy settings and restrict external access so presence is not exposed to untrusted tenants.",
	}
}

// oofFinding reports that the seed user's out-of-office note was disclosed to an
// external requester. The raw note is stored in Evidence; the caller sanitizes
// and truncates it for terminal output.
func oofFinding(domain, seedEmail string, result *EnumResult) Finding {
	return Finding{
		ID:          "teams-oof-disclosure",
		Title:       "Out-of-office note disclosed to external users",
		Severity:    SeverityLow,
		Description: "The user's out-of-office note is readable by external parties. Such notes frequently contain travel plans, internal contacts, or other sensitive details useful to an attacker.",
		Evidence:    "out-of-office note returned: " + result.OutOfOfficeNote,
		Affected:    affected(domain, seedEmail),
		Remediation: "Avoid placing sensitive information in out-of-office messages, and restrict external access so these notes are not exposed to untrusted tenants.",
	}
}

// metadataFinding reports that account metadata (UPN, objectId, tenantId,
// coexistence mode) was disclosed to an external party via externalsearchv3.
func metadataFinding(domain, seedEmail string, result *EnumResult) Finding {
	var fields []string
	if result.UserPrincipalName != "" {
		fields = append(fields, "userPrincipalName")
	}
	if result.ObjectID != "" {
		fields = append(fields, "objectId")
	}
	if result.TenantID != "" {
		fields = append(fields, "tenantId")
	}
	if result.CoExistenceMode != "" {
		fields = append(fields, "coExistenceMode")
	}
	return Finding{
		ID:          "teams-metadata-disclosure",
		Title:       "Account metadata disclosed to external party",
		Severity:    SeverityInfo,
		Description: "The externalsearchv3 lookup returned account metadata to an external requester. These identifiers aid reconnaissance and tenant mapping.",
		Evidence:    "returned: " + strings.Join(fields, ", "),
		Affected:    affected(domain, seedEmail),
		Remediation: "This disclosure is inherent to Teams external resolution. Reduce external exposure by restricting federation/external access.",
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// externalAccessSignals describes any federation/type signal observed on the
// seed result, for inclusion in the external-access evidence string. It returns
// "" when no such signal is present.
func externalAccessSignals(result *EnumResult) string {
	var parts []string
	if result.Type != "" {
		parts = append(parts, "type="+result.Type)
	}
	if strings.EqualFold(result.Type, "Federated") || result.SourceNetwork == "Federated" {
		parts = append(parts, "federation observed")
	}
	return strings.Join(parts, ", ")
}

// affected formats the affected scope: the domain alone, or "domain (email)"
// when a seed email is supplied.
func affected(domain, seedEmail string) string {
	if seedEmail == "" {
		return domain
	}
	return fmt.Sprintf("%s (%s)", domain, seedEmail)
}

// severityRank orders severities for stable, highest-first sorting.
func severityRank(s Severity) int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	default: // SeverityInfo and anything unrecognized
		return 3
	}
}

// sortFindings orders findings by severity (high -> info) then by ID.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return findings[i].ID < findings[j].ID
	})
}
