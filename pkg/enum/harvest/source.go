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

// Package harvest provides passive, free, no-API-key email harvesting for a
// domain. Sources self-register into a registry; the engine fans out across
// them, normalizes and domain-anchors every address through a single extractor,
// and scores each email by the number of distinct sources that corroborate it.
package harvest

import (
	"context"
	"net/http"
)

// Source is a passive, free, no-API-key email source for a domain.
// Implementations MUST be safe for concurrent use and MUST honor ctx cancellation.
type Source interface {
	Name() string
	Search(ctx context.Context, domain string) ([]string, error) // raw emails; engine normalizes
}

// SourceFactory builds a Source bound to an *http.Client so the engine can
// inject the proxy/timeout client and tests can inject an endpoint-overridden client.
type SourceFactory func(client *http.Client) Source

// EmailHit is one aggregated address with corroboration metadata.
type EmailHit struct {
	Email   string   // normalized, lowercased, domain-anchored
	Sources []string // distinct source names that returned it (sorted)
	Count   int      // len(Sources) — the corroboration / fidelity signal
}

// Report is the harvest result for a domain.
type Report struct {
	Domain string
	Hits   []EmailHit // sorted: Count desc, then Email asc
}
