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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// printSummary prints the results summary to stdout.
func printSummary(validCount, invalidCount, errorCount, total int, useColor bool) {
	if useColor {
		fmt.Printf("\n%s\n", heading(useColor, "Results Summary"))
		if validCount > 0 {
			fmt.Printf("  %sValid:%s     %d\n", ColorGreen, ColorReset, validCount)
		}
		if invalidCount > 0 {
			fmt.Printf("  %sInvalid:%s   %d\n", ColorDim, ColorReset, invalidCount)
		}
		if errorCount > 0 {
			fmt.Printf("  %sErrors:%s    %d\n", ColorRed, ColorReset, errorCount)
		}
		fmt.Printf("  %sTotal:%s     %d\n", ColorCyan, ColorReset, total)
	} else {
		fmt.Printf("Results: %d valid, %d invalid, %d errors (total: %d)\n",
			validCount, invalidCount, errorCount, total)
	}

	if errorCount > 5 {
		if useColor {
			fmt.Printf("\n%s%s Suppressed %d additional errors%s\n", ColorYellow, SymbolWarning, errorCount-5, ColorReset)
		} else {
			fmt.Printf("(Suppressed %d additional errors)\n", errorCount-5)
		}
	}
}

func outputHuman(results []brutus.Result, useColor, quiet bool) {
	validCount := 0
	invalidCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		switch {
		case r.Success:
			validCount++
			fmt.Printf("%s[+] VALID: %s %s:%s @ %s (%s)%s\n",
				colorIf(useColor, ColorGreen), r.Protocol, r.Username, r.Password, r.Target, r.Duration, colorIf(useColor, ColorReset))
			if r.LLMSuggested {
				fmt.Printf("    %s\n", highlight(useColor, "(LLM-suggested)"))
			}
		case r.Error != nil:
			errorCount++
			if !quiet && errorCount <= 5 {
				fmt.Printf("%s%s ERROR:%s %s:%s @ %s - %v\n",
					colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset), r.Username, r.Password, r.Target, r.Error)
			}
		default:
			invalidCount++
		}
	}

	// Print security findings from banners (e.g., sticky keys detection)
	// These appear regardless of auth success since they are pre-auth findings.
	for i := range results {
		r := &results[i]
		if r.Banner != "" && hasSecurityFinding(r.Banner) {
			fmt.Printf("\n%s\n", heading(useColor, "Security Findings"))
			fmt.Printf("  %s @ %s\n", r.Protocol, r.Target)
			for _, line := range splitLines(r.Banner) {
				fmt.Printf("  %s\n", line)
			}
			break // One findings block per target
		}
	}

	if !quiet || validCount > 0 {
		printSummary(validCount, invalidCount, errorCount, len(results), useColor)
	}
}

// outputValidOnly prints only successful credentials (for pipeline/large-scale scanning)
func outputValidOnly(results []brutus.Result, useColor bool) {
	for i := range results {
		r := &results[i]
		if r.Success {
			// Simple, parseable format: protocol username:password@target or protocol username:key@target
			cred := r.Username
			if r.Password != "" {
				cred += ":" + r.Password
			} else if len(r.Key) > 0 {
				cred += ":key"
			}
			if useColor {
				fmt.Printf("%s%s %s@%s%s\n", ColorGreen, r.Protocol, cred, r.Target, ColorReset)
			} else {
				fmt.Printf("%s %s@%s\n", r.Protocol, cred, r.Target)
			}
		}
	}
}

// outputJSONL streams successful results as JSONL (one JSON object per line)
// This matches the output format of naabu and nerva for easy piping
func outputJSONL(w io.Writer, results []brutus.Result) {
	type JSONResult struct {
		Protocol     string `json:"protocol"`
		Target       string `json:"target"`
		Username     string `json:"username"`
		Password     string `json:"password,omitempty"`
		Key          bool   `json:"key,omitempty"`
		Duration     string `json:"duration"`
		Banner       string `json:"banner,omitempty"`
		LLMSuggested bool   `json:"llm_suggested,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		if !r.Success {
			continue // Only output successful auths
		}
		jr := JSONResult{
			Protocol:     r.Protocol,
			Target:       r.Target,
			Username:     r.Username,
			Password:     r.Password,
			Key:          len(r.Key) > 0,
			Duration:     r.Duration.String(),
			Banner:       r.Banner,
			LLMSuggested: r.LLMSuggested,
		}
		if err := enc.Encode(jr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		}
	}

	// Also output security findings (e.g., sticky keys detection) regardless of auth success
	for i := range results {
		r := &results[i]
		if r.Banner != "" && hasSecurityFinding(r.Banner) {
			type FindingResult struct {
				Protocol string `json:"protocol"`
				Target   string `json:"target"`
				Finding  string `json:"finding"`
				Banner   string `json:"banner"`
			}
			fr := FindingResult{
				Protocol: r.Protocol,
				Target:   r.Target,
				Finding:  "security",
				Banner:   r.Banner,
			}
			if err := enc.Encode(fr); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			}
			break // One finding per target
		}
	}
}

// hasSecurityFinding checks if a banner contains security-relevant findings.
func hasSecurityFinding(banner string) bool {
	return strings.Contains(banner, "[CRITICAL]") ||
		strings.Contains(banner, "[HIGH]") ||
		strings.Contains(banner, "[INFO] Sticky keys")
}

// splitLines splits a string into non-empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// outputScanHuman writes scan results in human-readable format.
func outputScanHuman(results []brutus.Result, useColor bool) {
	for i := range results {
		r := &results[i]
		scanType := "Sticky Keys Scan"

		finding := extractFinding(r.Banner)
		color, symbol := ColorCyan, SymbolInfo
		switch finding {
		case "[CRITICAL]":
			color, symbol = ColorRed, SymbolError
		case "[HIGH]":
			color, symbol = ColorYellow, SymbolWarning
		}

		if useColor {
			fmt.Printf("%s%s %s: %s%s  %s\n", color, symbol, scanType, r.Target, ColorReset, r.Banner)
		} else {
			fmt.Printf("%s: %s  %s\n", scanType, r.Target, r.Banner)
		}
	}
}

// outputScanJSONL writes scan results as JSONL for pipeline consumption.
func outputScanJSONL(w io.Writer, results []brutus.Result) {
	type ScanResult struct {
		Protocol string `json:"protocol"`
		Target   string `json:"target"`
		ScanType string `json:"scan_type"`
		Finding  string `json:"finding"`
		Banner   string `json:"banner"`
		Success  bool   `json:"success"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		scanType := "sticky_keys"
		sr := ScanResult{
			Protocol: r.Protocol,
			Target:   r.Target,
			ScanType: scanType,
			Finding:  extractFinding(r.Banner),
			Banner:   r.Banner,
			Success:  r.Success,
		}
		if err := enc.Encode(sr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding scan JSON: %v\n", err)
		}
	}
}

// extractFinding extracts the severity tag from a banner string.
func extractFinding(banner string) string {
	for _, tag := range []string{"[CRITICAL]", "[HIGH]", "[INFO]"} {
		if strings.Contains(banner, tag) {
			return tag
		}
	}
	return ""
}
