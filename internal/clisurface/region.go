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

package clisurface

import (
	"fmt"
	"strings"
)

// Generated regions let a hand-written document carry generated blocks. The
// markers are HTML comments so they are invisible when the markdown renders.
const (
	regionBeginFormat = "<!-- BEGIN generated: %s -->"
	regionEndFormat   = "<!-- END generated: %s -->"
)

// BeginMarker is the opening marker of the named region.
func BeginMarker(name string) string { return fmt.Sprintf(regionBeginFormat, name) }

// EndMarker is the closing marker of the named region.
func EndMarker(name string) string { return fmt.Sprintf(regionEndFormat, name) }

// Splice replaces the body of the named region in doc with body. The markers
// themselves are preserved. body is normalized to exactly one trailing newline
// so repeated splices converge.
func Splice(doc, name, body string) (string, error) {
	begin, end, err := regionBounds(doc, name)
	if err != nil {
		return "", err
	}
	normalized := strings.TrimRight(strings.ReplaceAll(body, "\r\n", "\n"), "\n") + "\n"
	// Match the document's own line endings. Splicing LF into a CRLF checkout leaves a
	// file that is mixed, which is worse than either convention and shows up as noise
	// in every later diff.
	if dominantNewline(doc) == "\r\n" {
		normalized = strings.ReplaceAll(normalized, "\n", "\r\n")
	}
	return doc[:begin] + normalized + doc[end:], nil
}

// dominantNewline reports the line ending doc mostly uses.
func dominantNewline(doc string) string {
	if strings.Count(doc, "\r\n")*2 > strings.Count(doc, "\n") {
		return "\r\n"
	}
	return "\n"
}

// RegionBody returns the current body of the named region.
func RegionBody(doc, name string) (string, error) {
	begin, end, err := regionBounds(doc, name)
	if err != nil {
		return "", err
	}
	return doc[begin:end], nil
}

// regionBounds returns the offsets of the region body: begin is just after the
// newline that ends the opening marker line, end is the start of the closing
// marker line.
func regionBounds(doc, name string) (begin, end int, err error) {
	beginMarker, endMarker := BeginMarker(name), EndMarker(name)

	if n := strings.Count(doc, beginMarker); n != 1 {
		return 0, 0, fmt.Errorf("expected exactly one %q marker, found %d", beginMarker, n)
	}
	if n := strings.Count(doc, endMarker); n != 1 {
		return 0, 0, fmt.Errorf("expected exactly one %q marker, found %d", endMarker, n)
	}

	beginIdx := strings.Index(doc, beginMarker)
	endIdx := strings.Index(doc, endMarker)
	if endIdx < beginIdx {
		return 0, 0, fmt.Errorf("%q appears before %q", endMarker, beginMarker)
	}

	afterBegin := beginIdx + len(beginMarker)
	nl := strings.IndexByte(doc[afterBegin:], '\n')
	if nl < 0 {
		return 0, 0, fmt.Errorf("%q must be followed by a newline", beginMarker)
	}
	begin = afterBegin + nl + 1
	// Both markers on one line leaves begin past endIdx. Splicing that produced a
	// document with a duplicated closing marker rather than an error, so say so.
	if begin > endIdx {
		return 0, 0, fmt.Errorf("%q and %q must be on separate lines", beginMarker, endMarker)
	}
	return begin, endIdx, nil
}
