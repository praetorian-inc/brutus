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

package custom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// placeholderNames are the substitution tokens exposed to a spec author (D5).
var placeholderNames = []string{"username", "email", "localpart", "domain"}

// buildRequest assembles the *http.Request for one subject, performing
// per-channel (encoding-aware) substitution and re-validating the
// post-substitution URL scheme (security-lead R1/R2/R3/R4). It NEVER applies a
// single global replacer over the assembled request string.
func buildRequest(spec *Spec, ctx context.Context, subject string) (*http.Request, error) {
	vals := derivePlaceholders(subject)
	req := &spec.Oracle.Request

	finalURL, err := buildRequestURL(req.URL, vals)
	if err != nil {
		return nil, err
	}

	bodyReader, err := buildRequestBody(req.Body, req.BodyEncoding, vals)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, finalURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	for name, tmpl := range req.Headers {
		value := substitute(tmpl, identityEscape, vals)
		if err := sanitizeHeaderValue(value); err != nil {
			return nil, fmt.Errorf("header %q: %w", name, err)
		}
		httpReq.Header.Set(name, value)
	}

	return httpReq, nil
}

// derivePlaceholders maps a subject (a bare username OR an email) to the four
// substitution values.
func derivePlaceholders(subject string) map[string]string {
	localpart, domain, _ := strings.Cut(subject, "@")
	return map[string]string{
		"username":  subject,
		"email":     subject,
		"localpart": localpart,
		"domain":    domain,
	}
}

// buildRequestURL substitutes placeholders into the URL template using
// path/query-appropriate escaping, then re-parses and re-validates the scheme.
func buildRequestURL(template string, vals map[string]string) (*url.URL, error) {
	// Split off the query so query values can be QueryEscape'd and the rest
	// PathEscape'd, each in its own channel.
	rawPath, rawQuery, _ := strings.Cut(template, "?")

	substitutedPath := substitute(rawPath, url.PathEscape, vals)
	finalURLStr := substitutedPath
	if rawQuery != "" {
		substitutedQuery := substitute(rawQuery, url.QueryEscape, vals)
		finalURLStr = substitutedPath + "?" + substitutedQuery
	}

	u, err := url.Parse(finalURLStr)
	if err != nil {
		return nil, fmt.Errorf("post-substitution URL is invalid: %w", err)
	}
	if err := validateURLScheme(u); err != nil {
		return nil, fmt.Errorf("post-substitution URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("post-substitution URL has no host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("post-substitution URL contains userinfo authority")
	}
	if hasDotDotSegment(u.Path) {
		return nil, fmt.Errorf("post-substitution URL path contains traversal segment")
	}
	return u, nil
}

// hasDotDotSegment reports whether the decoded path contains a ".." segment
// (path traversal). The on-wire path keeps placeholder slashes percent-encoded,
// but a decoded ".." indicates the substituted value attempted traversal.
func hasDotDotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// buildRequestBody substitutes placeholders into the body template using the
// escaper appropriate to the body encoding, returning a nil io.Reader for an
// empty body (so http.NewRequestWithContext sees a genuine nil, not a typed-nil
// interface).
func buildRequestBody(template, encoding string, vals map[string]string) (io.Reader, error) {
	if template == "" {
		return nil, nil
	}

	switch encoding {
	case "json":
		return strings.NewReader(substitute(template, jsonStringEscape, vals)), nil
	case "form":
		return strings.NewReader(substitute(template, url.QueryEscape, vals)), nil
	default: // "" or "raw": the author takes responsibility, but a substituted
		// subject value must not inject control bytes (security-lead R2).
		if err := sanitizeRawValues(template, vals); err != nil {
			return nil, err
		}
		return strings.NewReader(substitute(template, identityEscape, vals)), nil
	}
}

// substitute replaces each {{name}} token in template with esc(vals[name]).
// Unknown {{...}} tokens are left untouched (only known placeholders are
// substituted; an unknown token simply stays literal).
func substitute(template string, esc func(string) string, vals map[string]string) string {
	out := template
	for _, name := range placeholderNames {
		out = strings.ReplaceAll(out, "{{"+name+"}}", esc(vals[name]))
	}
	return out
}

// identityEscape returns the value unchanged (used for raw bodies and header
// values, which are validated separately).
func identityEscape(v string) string { return v }

// jsonStringEscape JSON-encodes v as a string and strips the surrounding
// quotes, yielding a value safe to splice inside an existing quoted JSON string
// (security-lead R2/P0-2).
func jsonStringEscape(v string) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

// sanitizeHeaderValue rejects (does not strip) any value containing CR, LF, a
// control byte < 0x20, or 0x7F (security-lead R1/P0-1).
func sanitizeHeaderValue(v string) error {
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b < 0x20 || b == 0x7F {
			return fmt.Errorf("illegal control byte 0x%02x in header value", b)
		}
	}
	return nil
}

// sanitizeRawValues rejects a substituted subject value containing control
// bytes when it is spliced into a raw body (security-lead R2). It only checks
// placeholder values that actually appear in the template, leaving the
// author-written template bytes untouched.
func sanitizeRawValues(template string, vals map[string]string) error {
	for _, name := range placeholderNames {
		if !strings.Contains(template, "{{"+name+"}}") {
			continue
		}
		v := vals[name]
		for i := 0; i < len(v); i++ {
			b := v[i]
			if b < 0x20 || b == 0x7F {
				return fmt.Errorf("illegal control byte 0x%02x in raw body placeholder %q", b, name)
			}
		}
	}
	return nil
}
