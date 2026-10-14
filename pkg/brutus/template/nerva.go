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

package template

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Target is one HTTP service and the technologies Nerva reported for it.
type Target struct {
	BaseURL      string
	Technologies []string
}

type nervaService struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
	Metadata struct {
		Technologies []string `json:"technologies"`
	} `json:"metadata"`
	Technologies []string `json:"technologies"`
	URL          string   `json:"url"`
}

// ParseNerva reads Nerva JSON or JSONL and returns HTTP(S) targets.
// Non-HTTP services are skipped. A document with no technologies is skipped:
// templates are selected by product, not by port.
func ParseNerva(r io.Reader) ([]Target, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Target
	lineNo := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lineNo++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var svc nervaService
		if err := json.Unmarshal([]byte(line), &svc); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		t, ok := targetFrom(svc)
		if ok {
			out = append(out, t)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func targetFrom(svc nervaService) (Target, bool) {
	techs := svc.Technologies
	if len(techs) == 0 {
		techs = svc.Metadata.Technologies
	}
	if len(techs) == 0 {
		return Target{}, false
	}
	if svc.URL != "" {
		return Target{BaseURL: strings.TrimRight(svc.URL, "/"), Technologies: techs}, true
	}
	proto := strings.ToLower(svc.Protocol)
	if proto != "http" && proto != "https" {
		return Target{}, false
	}
	scheme := proto
	if svc.TLS && scheme == "http" {
		scheme = "https"
	}
	host := svc.Host
	if host == "" {
		host = svc.IP
	}
	if host == "" || svc.Port == 0 {
		return Target{}, false
	}
	return Target{
		BaseURL:      fmt.Sprintf("%s://%s:%d", scheme, host, svc.Port),
		Technologies: techs,
	}, true
}
