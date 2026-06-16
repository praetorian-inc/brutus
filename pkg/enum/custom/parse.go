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
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Structural bounds (security-lead R5/R9).
const (
	maxRules      = 100
	maxStatuses   = 64
	maxHeaders    = 64
	maxRegexBytes = 1024
)

// headerNameRe is the allowed header-name character set (security-lead R1).
var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// SpecError is a typed validation error identifying the offending field.
type SpecError struct {
	Field  string
	Reason string
}

// Error formats the spec error as "oracle spec invalid: <field>: <reason>".
func (e *SpecError) Error() string {
	return fmt.Sprintf("oracle spec invalid: %s: %s", e.Field, e.Reason)
}

// Parse decodes a schema v1 spec from JSON or YAML bytes into a typed *Spec.
//
// It uses a yaml.v3 Decoder with KnownFields(true) so unknown/typo'd keys fail
// loudly (security-lead R8/P0-7). JSON is a subset of YAML, so the same decoder
// accepts both. The caller is responsible for capping the input size (the CLI
// enforces a 1 MB cap before calling Parse).
func Parse(data []byte) (*Spec, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var spec Spec
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("parsing oracle spec: %w", err)
	}
	return &spec, nil
}

// Validate performs structural and security validation, applies defaults, and
// compiles each body_regex into s.compiledRe (index-aligned with the rules).
// It returns a *SpecError on the first failure.
func (s *Spec) Validate() error {
	if s.Version != "1" {
		return &SpecError{Field: "version", Reason: fmt.Sprintf("unsupported schema version %q (want \"1\")", s.Version)}
	}
	if s.Oracle.Name == "" {
		return &SpecError{Field: "oracle.name", Reason: "must not be empty"}
	}
	if err := s.validateRequest(); err != nil {
		return err
	}
	if err := s.validateMatch(); err != nil {
		return err
	}
	return nil
}

// validateRequest validates the method, URL (scheme allowlist), body_encoding,
// and header names/count.
func (s *Spec) validateRequest() error {
	req := &s.Oracle.Request

	if strings.TrimSpace(req.Method) == "" {
		return &SpecError{Field: "oracle.request.method", Reason: "must not be empty"}
	}

	if req.URL == "" {
		return &SpecError{Field: "oracle.request.url", Reason: "must not be empty"}
	}
	// The URL template may contain {{placeholder}} tokens (e.g. in the host
	// position). Replace them with a benign token so the scheme/structure can be
	// validated at load time; the on-wire URL is re-validated after substitution
	// in buildRequest (security-lead R3/R4).
	u, err := url.Parse(neutralizePlaceholders(req.URL))
	if err != nil {
		return &SpecError{Field: "oracle.request.url", Reason: fmt.Sprintf("invalid URL: %v", err)}
	}
	if err := validateURLScheme(u); err != nil {
		return &SpecError{Field: "oracle.request.url", Reason: err.Error()}
	}

	switch req.BodyEncoding {
	case "", "raw", "json", "form":
	default:
		return &SpecError{Field: "oracle.request.body_encoding", Reason: fmt.Sprintf("unknown body_encoding %q (want raw|json|form)", req.BodyEncoding)}
	}

	if len(req.Headers) > maxHeaders {
		return &SpecError{Field: "oracle.request.headers", Reason: fmt.Sprintf("too many headers: %d (max %d)", len(req.Headers), maxHeaders)}
	}
	for name := range req.Headers {
		if !headerNameRe.MatchString(name) {
			return &SpecError{Field: "oracle.request.headers", Reason: fmt.Sprintf("illegal header name %q (allowed: A-Za-z0-9-)", name)}
		}
	}
	return nil
}

// validateMatch validates rules, compiles regexes, and applies the default verdict.
func (s *Spec) validateMatch() error {
	m := &s.Oracle.Match

	if len(m.Rules) == 0 {
		return &SpecError{Field: "oracle.match.rules", Reason: "must contain at least one rule"}
	}
	if len(m.Rules) > maxRules {
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("too many rules: %d (max %d)", len(m.Rules), maxRules)}
	}

	switch m.Default {
	case "", "error":
		m.Default = "error"
	case "exists", "absent":
	default:
		return &SpecError{Field: "oracle.match.default", Reason: fmt.Sprintf("invalid default verdict %q (want exists|absent|error)", m.Default)}
	}

	s.compiledRe = make([]*regexp.Regexp, len(m.Rules))
	for i := range m.Rules {
		if err := s.validateRule(i); err != nil {
			return err
		}
	}
	return nil
}

// validateRule validates a single rule's verdict, confidence, and conditions,
// compiling its body_regex into s.compiledRe[i] if present.
func (s *Spec) validateRule(i int) error {
	r := &s.Oracle.Match.Rules[i]

	switch r.Verdict {
	case "exists", "absent", "error":
	default:
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: invalid verdict %q (want exists|absent|error)", i, r.Verdict)}
	}

	switch r.Confidence {
	case "", "high", "medium", "low":
	default:
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: invalid confidence %q (want high|medium|low)", i, r.Confidence)}
	}

	if !whenHasActiveCondition(&r.When) {
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: when must have at least one active condition", i)}
	}

	if r.When.Status != nil {
		vals := r.When.Status.Values()
		if len(vals) > maxStatuses {
			return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: too many status codes: %d (max %d)", i, len(vals), maxStatuses)}
		}
		for _, code := range vals {
			if code < 100 || code > 599 {
				return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: invalid status code %d (want 100-599)", i, code)}
			}
		}
	}

	if r.When.BodyRegex != "" {
		if len(r.When.BodyRegex) > maxRegexBytes {
			return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: body_regex too long: %d bytes (max %d)", i, len(r.When.BodyRegex), maxRegexBytes)}
		}
		re, err := regexp.Compile(r.When.BodyRegex)
		if err != nil {
			return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: invalid body_regex: %v", i, err)}
		}
		s.compiledRe[i] = re
	}

	if r.When.JSONField != nil {
		if err := validateJSONField(i, r.When.JSONField); err != nil {
			return err
		}
	}

	if r.When.Header != nil {
		if err := validateHeaderMatch(i, r.When.Header); err != nil {
			return err
		}
	}
	return nil
}

// whenHasActiveCondition reports whether at least one condition is set.
func whenHasActiveCondition(w *When) bool {
	if w.Status != nil && len(w.Status.Values()) > 0 {
		return true
	}
	if w.BodyContains != "" {
		return true
	}
	if w.BodyRegex != "" {
		return true
	}
	if w.JSONField != nil {
		return true
	}
	if w.Header != nil {
		return true
	}
	return false
}

// validateJSONField enforces the dot-path-only constraint (no JSONPath, R11) and
// the exactly-one-of equals/in rule.
func validateJSONField(ruleIdx int, jf *JSONFieldMatch) error {
	if jf.Path == "" {
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: json_field.path must not be empty", ruleIdx)}
	}
	if !isPlainPath(jf.Path) {
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: json_field.path %q must be a dot-path with numeric indices only (no JSONPath)", ruleIdx, jf.Path)}
	}
	hasEquals := jf.Equals != nil
	hasIn := len(jf.In) > 0
	if hasEquals == hasIn {
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: json_field must set exactly one of equals/in", ruleIdx)}
	}
	return nil
}

// validateHeaderMatch enforces a valid header name and exactly-one-of present/equals.
func validateHeaderMatch(ruleIdx int, hm *HeaderMatch) error {
	if !headerNameRe.MatchString(hm.Name) {
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: illegal header name %q (allowed: A-Za-z0-9-)", ruleIdx, hm.Name)}
	}
	hasPresent := hm.Present != nil
	hasEquals := hm.Equals != nil
	if hasPresent == hasEquals {
		return &SpecError{Field: "oracle.match.rules", Reason: fmt.Sprintf("rule %d: header must set exactly one of present/equals", ruleIdx)}
	}
	return nil
}

// isPlainPath reports whether path consists only of dot-separated segments of
// allowed characters (letters, digits, underscore, hyphen) — no JSONPath
// operators ($, *, [, ], filters, recursion).
func isPlainPath(path string) bool {
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			return false
		}
		for _, c := range seg {
			isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			isDigit := c >= '0' && c <= '9'
			if !isLetter && !isDigit && c != '_' && c != '-' {
				return false
			}
		}
	}
	return true
}

// neutralizePlaceholders replaces every {{token}} (any name) with a benign
// host-safe token so a URL template can be parsed/scheme-checked at load time.
func neutralizePlaceholders(s string) string {
	for {
		open := strings.Index(s, "{{")
		if open < 0 {
			break
		}
		closeIdx := strings.Index(s[open:], "}}")
		if closeIdx < 0 {
			break
		}
		s = s[:open] + "x" + s[open+closeIdx+2:]
	}
	return s
}

// validateURLScheme enforces the http/https allowlist (security-lead R4).
// Shared by Validate (load time) and buildRequest (post-substitution).
func validateURLScheme(u *url.URL) error {
	switch u.Scheme {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("unsupported URL scheme %q (only http and https are allowed)", u.Scheme)
	}
}
