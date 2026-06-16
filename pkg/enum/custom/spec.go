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

// Package custom implements a declaratively-described enumeration oracle
// (schema v1) that runs as an enum.Plugin. A spec file (JSON or YAML) describes
// the HTTP request to send for each subject and an ordered set of match rules
// that map the response to an exists/absent/error verdict.
package custom

import (
	"encoding/json"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Spec is the top-level schema v1 document.
type Spec struct {
	Version     string       `json:"version"      yaml:"version"`
	Oracle      Oracle       `json:"oracle"       yaml:"oracle"`
	Constraints *Constraints `json:"constraints,omitempty" yaml:"constraints,omitempty"`

	// compiledRe holds compiled body_regex per rule, populated by Validate() and
	// index-aligned with Oracle.Match.Rules (nil where a rule has no body_regex).
	// Never serialized.
	compiledRe []*regexp.Regexp `json:"-" yaml:"-"`
}

// Oracle describes the request to send and how to interpret the response.
type Oracle struct {
	Name    string  `json:"name"    yaml:"name"`
	Request Request `json:"request" yaml:"request"`
	Match   Match   `json:"match"   yaml:"match"`
}

// Request is the HTTP request template (placeholders substituted per-subject).
type Request struct {
	Method       string            `json:"method"        yaml:"method"`
	URL          string            `json:"url"           yaml:"url"`
	Headers      map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body         string            `json:"body,omitempty"    yaml:"body,omitempty"`
	BodyEncoding string            `json:"body_encoding,omitempty" yaml:"body_encoding,omitempty"` // raw|json|form
}

// Match is the ordered rule set plus a default verdict.
type Match struct {
	Rules   []Rule `json:"rules"   yaml:"rules"`
	Default string `json:"default,omitempty" yaml:"default,omitempty"` // exists|absent|error (default: error)
}

// Rule is a single match rule: when its conditions hold, its verdict wins.
type Rule struct {
	When       When   `json:"when"       yaml:"when"`
	Verdict    string `json:"verdict"    yaml:"verdict"`                        // exists|absent|error
	Confidence string `json:"confidence,omitempty" yaml:"confidence,omitempty"` // high|medium|low
}

// When holds AND-ed conditions. A condition is active only when its field is
// non-zero/non-nil.
type When struct {
	Status       *StatusMatch    `json:"status,omitempty"        yaml:"status,omitempty"`
	BodyContains string          `json:"body_contains,omitempty" yaml:"body_contains,omitempty"`
	BodyRegex    string          `json:"body_regex,omitempty"    yaml:"body_regex,omitempty"`
	JSONField    *JSONFieldMatch `json:"json_field,omitempty"    yaml:"json_field,omitempty"`
	Header       *HeaderMatch    `json:"header,omitempty"        yaml:"header,omitempty"`
}

// JSONFieldMatch tests a value reached by a dot-path (+ numeric indices) in a
// JSON response body. Exactly one of Equals/In must be set.
type JSONFieldMatch struct {
	Path   string   `json:"path"           yaml:"path"`               // dot-path + numeric indices ONLY (no JSONPath)
	Equals *string  `json:"equals,omitempty" yaml:"equals,omitempty"` // compared as string
	In     []string `json:"in,omitempty"   yaml:"in,omitempty"`
}

// HeaderMatch tests a response header. Exactly one of Present/Equals must be set.
type HeaderMatch struct {
	Name    string  `json:"name"             yaml:"name"`
	Present *bool   `json:"present,omitempty" yaml:"present,omitempty"`
	Equals  *string `json:"equals,omitempty"  yaml:"equals,omitempty"`
}

// Constraints carries operator hints about the target oracle.
type Constraints struct {
	RateLimitRPS float64 `json:"rate_limit_rps,omitempty" yaml:"rate_limit_rps,omitempty"`
	Lockout      bool    `json:"lockout,omitempty"        yaml:"lockout,omitempty"`
	Captcha      bool    `json:"captcha,omitempty"        yaml:"captcha,omitempty"`
}

// StatusMatch is a union accepting a single int OR a list of ints in JSON/YAML,
// normalising both to []int.
type StatusMatch struct {
	values []int
}

// Values returns the normalised list of status codes.
func (s *StatusMatch) Values() []int {
	if s == nil {
		return nil
	}
	return s.values
}

// UnmarshalJSON accepts either a scalar int (200) or a list of ints ([200,404]).
func (s *StatusMatch) UnmarshalJSON(data []byte) error {
	var single int
	if err := json.Unmarshal(data, &single); err == nil {
		s.values = []int{single}
		return nil
	}
	var list []int
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	s.values = list
	return nil
}

// UnmarshalYAML accepts either a scalar int or a sequence of ints.
func (s *StatusMatch) UnmarshalYAML(value *yaml.Node) error {
	var single int
	if err := value.Decode(&single); err == nil {
		s.values = []int{single}
		return nil
	}
	var list []int
	if err := value.Decode(&list); err != nil {
		return err
	}
	s.values = list
	return nil
}
