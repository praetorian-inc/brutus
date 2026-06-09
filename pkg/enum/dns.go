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
	"context"
	"net"
	"strings"
)

// SaaSService represents a service identified from DNS TXT records.
type SaaSService struct {
	Name      string // e.g., "microsoft365", "google", "atlassian"
	TXTRecord string // the raw TXT record that matched
	Indicator string // the specific pattern that matched
}

// DNSReconResult holds all DNS TXT findings for a domain.
type DNSReconResult struct {
	Domain   string
	Records  []string      // all raw TXT records
	Services []SaaSService // identified SaaS services
	Error    error
}

// txtPrefixPatterns maps DNS TXT record prefixes to SaaS service names.
var txtPrefixPatterns = []struct {
	prefix  string
	service string
}{
	{"atlassian-domain-verification=", "atlassian"},
	{"atlassian-sending-domain-verification=", "atlassian"},
	{"google-site-verification=", "google"},
	{"slack-domain-verification=", "slack"},
	{"ZOOM_verify_", "zoom"},
	{"docusign=", "docusign"},
	{"adobe-idp-site-verification=", "adobe"},
	{"apple-domain-verification=", "apple"},
	{"miro-verification=", "miro"},
	{"openai-domain-verification=", "openai"},
	{"cursor-domain-verification-", "cursor"},
	{"wiz-domain-verification=", "wiz"},
	{"hcp-domain-verification=", "hashicorp"},
	{"have-i-been-pwned-verification=", "hibp"},
	{"keybase-site-verification=", "keybase"},
	{"rippling-domain-verification=", "rippling"},
	{"spycloud-domain-verification=", "spycloud"},
	{"pylon-domain-verification-", "pylon"},
	{"canva-site-verification=", "canva"},
	{"notion-domain-verification=", "notion"},
	{"mongodb-site-verification=", "mongodb"},
	{"airtable-verification=", "airtable"},
	{"browserstack-domain-verification=", "browserstack"},
	{"linear-domain-verification=", "linear"},
	{"stripe-verification=", "stripe"},
	{"launchdarkly-domain-verification=", "launchdarkly"},
	{"docker-verification=", "docker"},
	{"gitkraken-domain-verification=", "gitkraken"},
	{"perplexity-ai-domain-verification-", "perplexity"},
	{"anthropic-domain-verification-", "anthropic"},
	{"elevenlabs=", "elevenlabs"},
	{"extensis-domain-verification=", "extensis"}, //nolint:misspell // Extensis is a company name, not "extensions"
	{"jamf-site-verification=", "jamf"},
	{"gamma-domain-verification-", "gamma"},
	{"postman-domain-verification=", "postman"},
	{"cisco-ci-domain-verification=", "cisco"},
	{"segment-site-verification=", "segment"},
	{"status-page-domain-verification=", "statuspage"},
	{"h1-domain-verification=", "hackerone"},
	{"traction-guest=", "traction_guest"},
	{"globalsign-domain-verification=", "globalsign"},
	{"vmware-cloud-verification-", "vmware"},
	{"skedda-domain-verification=", "skedda"},
	{"mandrill_verify.", "mandrill"},
	{"fastly-domain-delegation-", "fastly"},
	{"chariot=", "chariot"},
	{"MS=ms", "microsoft365"},
}

// spfIncludePatterns maps SPF include directives to SaaS service names.
var spfIncludePatterns = []struct {
	include string
	service string
}{
	{"spf.protection.outlook.com", "microsoft365"},
	{"_spf.google.com", "google"},
	{"_spf.salesforce.com", "salesforce"},
	{"amazonses.com", "amazon_ses"},
	{"sendgrid.net", "sendgrid"},
	{"mail.zendesk.com", "zendesk"},
	{"spf.service-now.com", "servicenow"},
}

// LookupDomainTXT queries DNS TXT records and identifies SaaS services.
func LookupDomainTXT(ctx context.Context, domain string) *DNSReconResult {
	result := &DNSReconResult{Domain: domain}

	records, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		result.Error = err
		return result
	}
	result.Records = records

	seen := make(map[string]bool)

	for _, record := range records {
		for _, svc := range identifyServices(record) {
			if !seen[svc.Name] {
				result.Services = append(result.Services, svc)
				seen[svc.Name] = true
			}
		}
	}

	return result
}

// identifyServices extracts SaaS service identifiers from a single TXT record.
func identifyServices(record string) []SaaSService {
	var services []SaaSService

	// Check prefix patterns
	for _, p := range txtPrefixPatterns {
		if strings.HasPrefix(record, p.prefix) {
			services = append(services, SaaSService{
				Name:      p.service,
				TXTRecord: record,
				Indicator: p.prefix,
			})
		}
	}

	// Pardot pattern: "pardot" followed by digits
	if strings.HasPrefix(record, "pardot") && len(record) > 6 && record[6] >= '0' && record[6] <= '9' {
		services = append(services, SaaSService{
			Name:      "pardot",
			TXTRecord: record,
			Indicator: "pardot[digits]",
		})
	}

	// Parse SPF records for include directives
	if strings.HasPrefix(record, "v=spf1") {
		for _, p := range spfIncludePatterns {
			if strings.Contains(record, "include:"+p.include) {
				services = append(services, SaaSService{
					Name:      p.service,
					TXTRecord: record,
					Indicator: "include:" + p.include,
				})
			}
		}
	}

	return services
}
