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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// errInconclusive is the sentinel error for the "error" verdict: the oracle ran
// but the response matched no rule. The message never embeds the response body
// (security-lead R7).
var errInconclusive = errors.New("oracle: no rule matched")

// matchInput carries everything a rule can test, captured once per response.
type matchInput struct {
	status int
	body   []byte
	header http.Header
}

// evaluate walks the rules in order; the FIRST rule whose When matches wins,
// returning its verdict+confidence. If no rule matches, the default verdict is
// returned with ConfidenceLow.
func (s *Spec) evaluate(in matchInput) (verdict string, conf enum.Confidence) {
	for i := range s.Oracle.Match.Rules {
		r := &s.Oracle.Match.Rules[i]
		if s.ruleMatches(i, in) {
			return r.Verdict, mapConfidence(r.Confidence)
		}
	}
	return s.Oracle.Match.Default, enum.ConfidenceLow
}

// ruleMatches reports whether every active condition in rule i holds for in.
func (s *Spec) ruleMatches(i int, in matchInput) bool {
	w := &s.Oracle.Match.Rules[i].When

	if w.Status != nil && !statusMatches(w.Status, in.status) {
		return false
	}
	if w.BodyContains != "" && !bytes.Contains(in.body, []byte(w.BodyContains)) {
		return false
	}
	if w.BodyRegex != "" {
		re := s.compiledRe[i]
		if re == nil || !re.Match(in.body) {
			return false
		}
	}
	if w.JSONField != nil && !jsonFieldMatches(w.JSONField, in.body) {
		return false
	}
	if w.Header != nil && !headerMatches(w.Header, in.header) {
		return false
	}
	return true
}

// applyVerdict maps a verdict + confidence + status onto an enum.Result.
//
//	exists → Exists=true,  Error=nil
//	absent → Exists=false, Error=nil
//	error  → Error wraps errInconclusive with a status-only message (R7), Exists=false
func applyVerdict(result *enum.Result, verdict string, conf enum.Confidence, status int) {
	result.Confidence = conf
	switch verdict {
	case "exists":
		result.Exists = true
		result.Error = nil
	case "absent":
		result.Exists = false
		result.Error = nil
	default: // "error"
		result.Exists = false
		result.Error = fmt.Errorf("%w (status=%d)", errInconclusive, status)
	}
}

// statusMatches reports whether status is in the StatusMatch's value set.
func statusMatches(sm *StatusMatch, status int) bool {
	for _, v := range sm.Values() {
		if v == status {
			return true
		}
	}
	return false
}

// headerMatches evaluates a HeaderMatch against the response headers using
// case-insensitive lookup. Presence uses http.Header.Values so a present
// header with an empty value still counts as present; Equals uses Get.
func headerMatches(hm *HeaderMatch, header http.Header) bool {
	if hm.Present != nil {
		present := len(header.Values(hm.Name)) > 0
		return present == *hm.Present
	}
	if hm.Equals != nil {
		return header.Get(hm.Name) == *hm.Equals
	}
	return false
}

// jsonFieldMatches walks the dot-path (+ numeric indices) into the JSON body and
// compares the stringified leaf. A non-JSON body or missing path yields false
// (never an error, security-lead R7/R11).
func jsonFieldMatches(jf *JSONFieldMatch, body []byte) bool {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return false
	}
	leaf, ok := walkJSONPath(root, jf.Path)
	if !ok {
		return false
	}
	got, ok := stringifyLeaf(leaf)
	if !ok {
		return false
	}
	if jf.Equals != nil {
		return got == *jf.Equals
	}
	for _, candidate := range jf.In {
		if got == candidate {
			return true
		}
	}
	return false
}

// walkJSONPath resolves a dot-separated path (object keys + numeric array
// indices) into the decoded JSON value.
func walkJSONPath(root any, path string) (any, bool) {
	cur := root
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// stringifyLeaf renders a scalar JSON leaf as a string for comparison.
// bool → "true"/"false"; number → integer-or-trimmed string; string → itself.
// Non-scalar leaves (objects/arrays/null) are not comparable → false.
func stringifyLeaf(leaf any) (string, bool) {
	switch v := leaf.(type) {
	case string:
		return v, true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	default:
		return "", false
	}
}

// mapConfidence converts a spec confidence string to an enum.Confidence,
// defaulting empty to low.
func mapConfidence(c string) enum.Confidence {
	switch c {
	case "high":
		return enum.ConfidenceHigh
	case "medium":
		return enum.ConfidenceMedium
	default:
		return enum.ConfidenceLow
	}
}
